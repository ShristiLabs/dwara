# CLI

`dwara-cli` is the operator command line for working with configs
without standing up a gateway.

## `run`

```sh
dwara-cli run [ARGS]...
```

Runs the gateway server. The CLI spawns the `dwara` binary (which must
be on `PATH`) with the given arguments passed through verbatim; the
environment (`DWARA_CONFIG`, etc.) passes through, and the binary's
exit status is propagated.

## `validate`

```sh
dwara-cli validate path/to/dwara.yaml
```

Runs the same parse → validate → compile pipeline the gateway runs at
startup and on reload, without starting a server. Prints **every**
issue found (never stops at the first). Exit 0 on success (prints the
route count), exit 1 on any issue.

## `fmt`

```sh
dwara-cli fmt path/to/dwara.yaml
```

Normalizes a config file in place: parses it, then re-serializes with
stable field order and defaulted-empty collections omitted. The output
is guaranteed to parse back to the same typed value. Prints nothing on
success; exit 1 on failure.

## `diff`

```sh
dwara-cli diff a.yaml b.yaml
```

Compiles both configs and prints route/upstream/consumer deltas:

```
+ route new-api
- route old-api
~ upstream backend
```

`+`/`-`/`~` mean added / removed / same-name-but-changed (compared by a
hash of the normalized serialization, so reordering keys in the source
file never shows up as a change). Exit 1 if either side is invalid.

## `lint`

```sh
dwara-cli lint path/to/dwara.yaml
```

Advisory checks beyond validation — config that compiles and routes
traffic but likely doesn't do what the author meant:

| Rule | Flags |
| --- | --- |
| `prefix-duplicate` | two prefix routes with an identical pattern (the later one can never win) |
| `regex-shadowed-by-exact` | an exact route that fully matches a regex route's pattern |
| `consumer-unused` | referenced by no authorization rule and bound to no JWT provider |
| `policy-unused` | attached to nothing (no consumer, route, service, listener, or global) |
| `upstream-unreferenced` | targeted by no service |

Exit codes: `0` clean, `2` warnings found, `1` the file didn't even
parse/validate (fix that first — linting an invalid config would just
be noise).

## `schema`

```sh
dwara-cli schema
```

Prints the [JSON Schema](https://json-schema.org/) (a standard for describing a JSON document's shape) of the gateway config to stdout (deterministic
for a given build). This is what generates the committed
`config-reference.json` — see
[Generating the config schema reference](./deployment#generating-the-config-schema-reference).

## `upgrade`

```sh
dwara-cli upgrade
dwara-cli upgrade --pid 12345
dwara-cli upgrade --pid-file /run/dwara.pid
```

Sends `SIGUSR2` (a Unix signal that triggers a zero-downtime upgrade) to a running gateway to trigger a zero-downtime binary
upgrade. The PID is read from `--pid`, else the PID file (`--pid-file`
or the `DWARA_PID_FILE` env var). The gateway must have been started
with `DWARA_PID_FILE` set (or the PID supplied explicitly). See
[Zero-downtime upgrade](./zero-downtime-upgrade) for the hand-off
sequence and the `DWARA_UPGRADE_*` env vars.
