# Workspaces, RBAC, and audit

Workspaces provide multi-tenant isolation: each workspace has its
own routes, services, and consumers, and access is controlled by
role-based access control (RBAC). All administrative actions are
recorded in an append-only audit log.

## When to use this

Use workspaces when:

- You run multiple teams or tenants on a single gateway deployment.
- You need to isolate tenant configs from each other.
- You need an audit trail of who changed what and when.

This is an enterprise feature -- build with the `ent` feature:

```sh
cargo build --features ent
```

## Workspaces

A workspace is a named isolation boundary. The default workspace
(`default`) always exists and cannot be deleted. Each workspace has:

- A name and description.
- An `active` flag (inactive workspaces are not served).
- Its own set of routes, services, upstreams, consumers, and
  policies.

```yaml
workspaces:
  - name: tenant-a
    description: Tenant A production
    active: true
  - name: tenant-b
    description: Tenant B staging
    active: true
```

Requests are routed to a workspace based on the host header or a
configured workspace selector. Traffic in one workspace cannot
access resources in another.

## RBAC

Access to workspaces is controlled by roles. A role defines which
actions a principal (identified by their mTLS client certificate
subject) can perform in which workspace.

### Roles

```yaml
roles:
  - name: tenant-a-admin
    description: Full access to tenant-a
    permissions:
      - action: "*"
        workspace: tenant-a
  - name: tenant-a-writer
    description: Write access to tenant-a
    permissions:
      - action: write
        workspace: tenant-a
      - action: read
        workspace: tenant-a
```

### Actions

| Action | Description |
|---|---|
| `read` | View workspace config, routes, consumers. |
| `write` | Create/modify routes, services, consumers. |
| `admin` | Delete workspace, manage roles, purge cache. |
| `*` | All actions (admin equivalent). |

### Assigning roles

Roles are assigned to principals (identified by their mTLS client
certificate CN or subject):

```yaml
role_assignments:
  - principal: "admin-cert"
    role: tenant-a-admin
  - principal: "writer-cert"
    role: tenant-a-writer
```

### Permission model

Permissions are evaluated as follows:

1. A principal's roles are looked up.
2. For each role, the permissions are checked against the requested
   action and workspace.
3. If any role grants the action on the workspace, access is allowed.
4. Otherwise, access is denied (fail-closed).

Cross-workspace access is denied by default: a writer for `tenant-a`
cannot write to `tenant-b` unless explicitly granted.

## Audit log

Every administrative action is recorded in an append-only audit log:

| Field | Description |
|---|---|
| `seq` | Monotonically increasing sequence number. |
| `timestamp` | When the action occurred. |
| `principal` | Who performed the action (mTLS cert subject). |
| `action` | What action was performed (create, update, delete, etc.). |
| `workspace` | Which workspace was affected. |
| `before` | The state before the change (for updates/deletes). |
| `after` | The state after the change (for creates/updates). |
| `request_id` | The request id of the admin API call. |

The audit log is queried via the admin API:

```sh
curl --cert admin.crt --key admin.key \
  https://127.0.0.1:2019/workspaces/tenant-a/audit
```

The log is append-only: entries cannot be modified or deleted. The
sequence number is monotonically increasing and gap-free within a
gateway lifetime.
