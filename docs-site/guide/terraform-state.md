# Terraform State Tool

`dwara-cli tf` is a CLI-based Terraform state tool that exports and imports
Terraform-compatible JSON state and generates HCL, performing
plan/apply round-trips directly over the admin API. This brings a
running gateway's config under Infrastructure-as-Code management
without requiring a Terraform binary or a gRPC plugin.

## When to use this

Use `dwara-cli tf` when you want to manage your gateway config with the
same Infrastructure-as-Code workflow as the rest of your
infrastructure. Export a running gateway's config as tfstate, track it
in version control, and apply changes through the plan/apply cycle.

## `dwara-cli tf export`

```sh
dwara-cli tf export --admin http://127.0.0.1:2019 \
  --out-state dwara.tfstate \
  --out-hcl dwara.tf
```

Fetches the current config from the admin API and writes a tfstate JSON
file and an HCL `.tf` file. This is the "state import" step: bring a
running gateway's config under management.

## `dwara-cli tf plan`

```sh
dwara-cli tf plan --admin http://127.0.0.1:2019 --state dwara.tfstate
```

Compares the local tfstate against the running gateway and prints the
diff (added, removed, and changed resources). Exit code 0 if no diff,
1 if a diff is present.

## `dwara-cli tf apply`

```sh
dwara-cli tf apply --admin http://127.0.0.1:2019 --state dwara.tfstate
```

Pushes the desired config to the gateway via `PATCH /config`. If
`--config` is given, that YAML is used as the desired config;
otherwise the desired YAML is derived from the tfstate.

## State model

The tfstate JSON follows Terraform's state file structure. Dwara config
entities map to Terraform resource types:

| Dwara entity | Resource type |
|---|---|
| Listener | `dwara_listener` |
| Route | `dwara_route` |
| Service | `dwara_service` |
| Upstream | `dwara_upstream` |
| Consumer | `dwara_consumer` |

## Admin API TLS

The tf tool targets the dev admin (plaintext loopback,
`DWARA_ADMIN_DEV=1`). The `--ca`, `--client-cert`, and `--client-key`
flags are reserved for mTLS to a production admin (a documented
follow-up).
