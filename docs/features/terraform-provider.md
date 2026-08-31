# Terraform-Compatible State Tool (DW-065)

## Overview

dwara ships a CLI-based Terraform state tool (`dwara tf`) that exports
and imports Terraform-compatible JSON state and generates HCL,
performing plan/apply round-trips directly over the admin API. This
brings a running gateway's config under Infrastructure-as-Code
management without requiring a Terraform binary or a gRPC plugin.

## Why a CLI tool, not a terraform-plugin-rs provider

The `terraform-plugin-rs` ecosystem is MPL-2.0, which is not in the
project's `deny.toml` license allow list, and the compliance control
must not be modified. So instead of a gRPC plugin, dwara implements a
CLI-based state tool that produces structurally Terraform-compatible
state and HCL. No new external dependencies are introduced (hyper,
serde_json, serde_yaml_ng, serde, clap, tokio are all already workspace
dependencies).

The state is structurally Terraform-compatible so a future real
Terraform provider (or `terraform import`) could consume it. The bridge
path to Pulumi (via the Terraform bridge) is also open: the HCL and
tfstate are the standard interchange formats those tools expect.

## State model

The tfstate JSON follows Terraform's state file structure:

```json
{
  "version": 4,
  "terraform_version": "1.5.0",
  "resources": [
    {
      "mode": "managed",
      "type": "dwara_route",
      "name": "api",
      "instances": [
        { "attributes": { "name": "api", "service": "api-service", ... } }
      ]
    }
  ]
}
```

Dwara config entities map to resources:

| Dwara entity | Terraform resource type |
|---|---|
| Listener | `dwara_listener` |
| Route | `dwara_route` |
| Service | `dwara_service` |
| Upstream | `dwara_upstream` (with endpoints as a nested attribute) |
| Consumer | `dwara_consumer` |

The attribute set captures the config faithfully enough that
export -> apply -> export round-trips preserve the entity set and their
key fields (name, path match, service, upstream, endpoints, methods,
host, protocol, load balancer).

## Commands

### `dwara tf export`

```
dwara tf export --admin <url> [--out-state <path>] [--out-hcl <path>] \
  [--ca <path>] [--client-cert <path>] [--client-key <path>]
```

Fetches the current config from the admin API (`GET /config`), parses
the YAML via `dwara_core::config::parse_gateway`, and writes:

1. A tfstate JSON file (default: `dwara.tfstate`).
2. An HCL `.tf` file with `resource "dwara_route" "<name>" { ... }`
   blocks (default: `dwara.tf`).

This is the "state import" step: bring a running gateway's config under
management.

### `dwara tf plan`

```
dwara tf plan --admin <url> --state <path> [--ca <path>]
```

Reads the local tfstate, fetches the current config from the gateway,
computes the diff (added, removed, and changed routes, upstreams,
services, consumers, listeners), and prints it human-readably. Exit
code 0 if no diff, 1 if a diff is present.

### `dwara tf apply`

```
dwara tf apply --admin <url> --state <path> [--config <yaml>] [--ca <path>]
```

Pushes the desired config to the gateway via `PATCH /config` (body =
YAML, full-document replacement). If `--config` is given, that YAML is
the desired config; otherwise the desired YAML is derived from the
tfstate. The admin API's response carries the new generation and
content hash.

## Plan/apply flow

```
                 +-----------+
                 |  tfstate  |  (desired state)
                 +-----------+
                      |
                      v
  dwara tf plan  ----->  GET /config  ----->  diff  ----->  print
                                                      |
                          (no diff: exit 0; diff: exit 1)
                                                      |
  dwara tf apply  ----->  PATCH /config  ----->  publish
                                                      |
                          (response: generation, content_hash)
```

## Admin API TLS

The tf tool targets the dev admin (plaintext loopback,
`DWARA_ADMIN_DEV=1`) as its primary round-trip target. mTLS to a
production admin is configured via the same `--ca` / `--client-cert` /
`--client-key` flags the admin client uses; TLS support is a documented
follow-up (the current implementation is plaintext-only to avoid scope
creep; the flags are accepted and reserved).

## Round-trip guarantee

The done-when is a plan/apply round-trip: export a running gateway's
config as tfstate, modify the state, run `plan` (asserts a diff is
shown), run `apply` (pushes the desired config), then `export` again
and assert the state matches the applied config. The pure-function
tests in `crates/dwara-cli/tests/tf.rs` verify this round-trip against
parsed `Gateway` values deterministically.

## Relationship to a future real Terraform provider

The tfstate and HCL produced by this tool are structurally
Terraform-compatible. A future real Terraform provider (built with
`terraform-plugin-rs` if the license situation changes, or a hand-rolled
gRPC plugin) could consume the same state file via `terraform import`.
The Pulumi bridge path is also open: the Terraform bridge consumes
Terraform providers, and the HCL/tfstate formats are the standard
interchange. This CLI tool is the pragmatic first step that works within
the project's license constraints today.
