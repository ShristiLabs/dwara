# Workspaces + RBAC + Audit (DW-067, Enterprise)

## Overview

dwara Enterprise supports tenant namespaces (workspaces), admin RBAC
roles, and immutable audit log shipping. This is an Enterprise
feature, feature-gated behind the `enterprise` cargo feature.

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

The `enterprise` cargo feature must be enabled. Without it, the
module is not compiled and the gateway runs in single-workspace mode
(the default OSS behavior).
