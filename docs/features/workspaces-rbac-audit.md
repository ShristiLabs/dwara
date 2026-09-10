# Workspaces + RBAC + Audit (DW-067, Enterprise)

## Overview

dwara Enterprise supports tenant namespaces (workspaces), admin RBAC
roles, and immutable audit log shipping. This is an Enterprise
feature, compiled into the OSS build.

## Enabling

Build with the `enterprise` feature:

```sh
cargo build --features ent
```

## Workspaces

Workspaces partition the config space. Each workspace owns its own
routes, services, upstreams, consumers, and policies. Cross-workspace
access is denied by default.

The default workspace ("default") always exists and cannot be
deleted.

```rust
use dwara_core::workspace::{WorkspaceManager, Workspace};

let mgr = WorkspaceManager::new();

// Create a workspace (requires admin permission).
mgr.add_role(Role {
    name: "admin".to_string(),
    permissions: vec![Permission {
        action: Action::Admin,
        workspace: "*".to_string(),
    }],
})?;
mgr.assign_role("admin-cert", "admin", "req-0")?;

mgr.create_workspace(
    "admin-cert",
    Workspace {
        name: "tenant-a".to_string(),
        description: "Tenant A".to_string(),
        active: true,
    },
    "req-1",
)?;
```

## RBAC

Roles reuse the same vocabulary as the M1 admin mTLS identity model:
the client certificate is the principal; roles are assigned to
principals. A role grants a set of permissions (read, write, admin)
on a workspace (or all workspaces with "*").

The action hierarchy: Admin > Write > Read. Admin implies all;
Write implies Read.

```rust
use dwara_core::workspace::{Action, Permission, Role};

let reader = Role {
    name: "reader".to_string(),
    permissions: vec![Permission {
        action: Action::Read,
        workspace: "*".to_string(),
    }],
};

let writer = Role {
    name: "tenant-a-writer".to_string(),
    permissions: vec![Permission {
        action: Action::Write,
        workspace: "tenant-a".to_string(),
    }],
};
```

### Permission check

```rust
// Check if a principal has a permission.
let allowed = mgr.check_permission("writer-cert", Action::Write, "tenant-a");
assert!(allowed);

// Cross-workspace access denied.
let denied = mgr.check_permission("writer-cert", Action::Write, "tenant-b");
assert!(!denied);
```

## Audit log

Every admin API change records the acting principal, the action, the
before/after state, and a timestamp. The log is append-only/immutable
with monotonically assigned sequence numbers.

```rust
// Record a change.
mgr.record_change(
    "admin-cert",
    "config.patch",
    "tenant-a",
    Some(&before_json),
    Some(&after_json),
    "req-123",
);

// Query the audit log.
let log = mgr.audit_log();
for entry in &log {
    println!(
        "{} {} {} by {} (seq={})",
        entry.timestamp_ms,
        entry.action,
        entry.workspace,
        entry.principal,
        entry.seq,
    );
}

// Filter by workspace.
let tenant_a_log = mgr.audit_log_for_workspace("tenant-a");
```

### AuditEntry fields

| Field | Type | Description |
|---|---|---|
| `seq` | u64 | Monotonically assigned sequence number |
| `timestamp_ms` | u64 | Unix epoch milliseconds |
| `principal` | String | The acting principal (mTLS cert CN) |
| `action` | String | The action (e.g. "config.patch", "workspace.create") |
| `workspace` | String | The workspace affected (or "global") |
| `before` | Option<String> | Before state (JSON, None for creations) |
| `after` | Option<String> | After state (JSON, None for deletions) |
| `request_id` | String | Correlation handle |

## Persistence (SCALE-05, #184)

The workspace manager optionally persists to the state store. When a
`StateStore` is attached via `WorkspaceManager::with_store`, every
mutation (workspace create/delete, role add, role assignment, audit
append) is written to the `workspaces`, `rbac_roles`,
`rbac_principals`, and `workspace_audit` tables (migration 008). The
in-memory `RwLock<HashMap>` remains the hot read path; the store is
the durable backing. On startup the manager loads the full state from
the store (seeding the `default` workspace if the table is empty).

```rust
use dwara_core::state::store::StateStore;
use dwara_core::workspace::WorkspaceManager;
use std::sync::Arc;

let store = Arc::new(StateStore::open_in_memory()?);
let mgr = WorkspaceManager::with_store(Some(store));

// Mutations are persisted automatically.
mgr.add_role(Role { /* ... */ })?;
// Reopening the store recovers the state.
let mgr2 = WorkspaceManager::with_store(Some(store));
assert_eq!(mgr2.list_roles(), mgr.list_roles());
```

The audit log query (`query_audit`) goes directly to the durable
`workspace_audit` table when a store is attached, supporting
workspace and time filters with a bounded limit. Without a store the
manager runs in-memory only (the pre-#184 behavior).

### Admin API endpoints

When the workspace manager is attached to the `AdminContext` (ent
only), the admin API exposes:

| Method | Path | Description |
|---|---|---|
| GET | `/workspaces` | List all workspaces |
| POST | `/workspaces` | Create a workspace |
| GET | `/workspaces/:name` | Get one workspace |
| DELETE | `/workspaces/:name` | Delete a workspace |
| GET | `/roles` | List all RBAC roles |
| POST | `/roles` | Create a role |
| GET | `/principals` | List all principals |
| GET | `/principals/:identity` | Get one principal |
| POST | `/principals/:identity/roles` | Assign a role |
| GET | `/audit` | Query the audit log |

The `/audit` endpoint accepts `workspace`, `since_ms`, `until_ms`,
and `limit` query parameters.

## Design (section 5-Platform)

- **Workspaces:** tenant namespaces that partition the config space.
  Each workspace owns its own routes, services, upstreams, consumers,
  and policies. Cross-workspace access is denied by default.
- **RBAC:** role-based access control for the admin API. Roles reuse
  the same vocabulary as the M1 admin mTLS identity model (the client
  certificate is the principal; roles are assigned to principals). A
  role grants a set of permissions (read, write, admin) on a
  workspace (or all workspaces).
- **Audit log:** every admin API change records the acting principal,
  the action, the before/after state, and a timestamp. The log is
  append-only/immutable -- not just an event name.

## Feature gate

The `ent` cargo feature must be enabled. Without it, the
module is not compiled and the gateway runs in single-workspace mode
(the default OSS behavior).
