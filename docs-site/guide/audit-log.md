# Audit log

The audit log is an append-only record of administrative activity.
Every administrative action is recorded with who performed it, what
they did, and what changed -- nothing can be edited or deleted after
the fact.

It completes the multi-tenant story: [workspaces](./workspaces)
provide the isolation boundary, [RBAC](./rbac) decides who may act,
and the audit log records what they actually did.

## When to use this

Use the audit log when you need an audit trail of who changed what
and when -- for example, when multiple principals administer the
gateway through [RBAC](./rbac), or when tenant changes in
[workspaces](./workspaces) must be attributable after the fact.

This is an enterprise feature (see [Enterprise](./enterprise)) --
build with the `ent` feature:

```sh
cargo build --features ent
```

## Fields

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

## Querying

The audit log is queried via the [admin API](./admin-api):

```sh
curl --cert admin.crt --key admin.key \
  https://127.0.0.1:2019/workspaces/tenant-a/audit
```

## Guarantees

The log is append-only: entries cannot be modified or deleted. The
sequence number is monotonically increasing and gap-free within a
gateway lifetime.
