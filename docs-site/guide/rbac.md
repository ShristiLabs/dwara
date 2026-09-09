# RBAC

Role-based access control (RBAC) governs who may administer which
[workspace](./workspaces). A role defines which actions a principal
(identified by their mTLS client certificate subject) can perform in
which workspace.

Workspaces scope what a tenant owns; RBAC scopes what a principal
may do there. Every permitted administrative action is recorded in
the [audit log](./audit-log).

## When to use this

Use RBAC when you run multi-tenant [workspaces](./workspaces) and
need to control, per principal, who can view, modify, or administer
each tenant's configuration -- with an [audit trail](./audit-log) of
who was allowed to do what.

This is an enterprise feature (see [Enterprise](./enterprise)) --
build with the `ent` feature:

```sh
cargo build --features ent
```

## Configuration

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

| Field | Default | Description |
|---|---|---|
| `name` | (required) | Role name. |
| `description` | (none) | Human-readable description. |
| `permissions` | (required) | List of permission grants. |
| `permissions[].action` | (required) | The action granted (see below). |
| `permissions[].workspace` | (required) | The workspace the grant applies to. |

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

| Field | Default | Description |
|---|---|---|
| `principal` | (required) | The principal (mTLS client certificate CN or subject). |
| `role` | (required) | The role to assign. |

## How it works

Permissions are evaluated as follows:

1. A principal's roles are looked up.
2. For each role, the permissions are checked against the requested
   action and workspace.
3. If any role grants the action on the workspace, access is
   allowed.
4. Otherwise, access is denied (fail-closed).

Cross-workspace access is denied by default: a writer for
`tenant-a` cannot write to `tenant-b` unless explicitly granted.

Allowed and denied administrative actions alike are visible after
the fact through the [audit log](./audit-log); see
[Workspaces](./workspaces) for the isolation boundary itself.
