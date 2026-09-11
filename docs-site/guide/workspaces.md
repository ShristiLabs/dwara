# Workspaces

Workspaces provide multi-tenant isolation. Each workspace has its
own routes, services, and consumers, so multiple teams or tenants
can share a single gateway deployment without seeing or affecting
each other's configuration.

Workspaces are the isolation boundary that [RBAC](./rbac) grants
principals access to, and every administrative action taken against
a workspace is recorded in the [audit log](./audit-log).

## When to use this

Use workspaces when:

- You run multiple teams or tenants on a single gateway deployment.
- You need to isolate tenant configs from each other.
- You need an audit trail of who changed what and when.

This is an enterprise feature (see [Enterprise](./enterprise)) --
build with the `ent` feature:

```sh
cargo build --features ent
```

## Configuration

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

| Field | Default | Description |
|---|---|---|
| `name` | (required) | Workspace name. |
| `description` | (none) | Human-readable description. |
| `active` | (none) | Whether the workspace is active. Inactive workspaces are not served. |

## How it works

Requests are routed to a workspace based on the host header or a
configured workspace selector. Traffic in one workspace cannot
access resources in another.

Who may act inside a workspace is governed by [RBAC](./rbac), and
every administrative action is captured in the [audit log](./audit-log).

## Runnable demo

The [`demos/11-enterprise/`](https://github.com/shristilabs/dwara/tree/main/demos/11-enterprise) directory in the repository documents
workspace RBAC and verifies the admin API's mTLS surface, the OSS
admin boundary (test script: `test-06-workspace-rb.sh`). The
category README covers prerequisites and teardown.
