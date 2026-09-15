# dwara-cli for config work

The CLI runs the same parse/validate/compile pipeline as the gateway unless
noted. Binary name: `dwara-cli` (repo builds; some docs shorthand it as
`dwara <sub>`).

## validate

```sh
dwara-cli validate dwara.yaml
```

Full-document check. Prints **all** issues, each naming its config path.
Exit non-zero on any error. Use before every reload and in CI.

## fmt

```sh
dwara-cli fmt dwara.yaml      # normalizes in place
```

Canonical key order/indentation. Run after structural edits so diffs stay
clean.

## lint (advisory)

```sh
dwara-cli lint dwara.yaml     # exit 0 clean | 2 warnings | 1 error
```

Rules: `prefix-duplicate`, `regex-shadowed-by-exact`,
`consumer-unused`, `policy-unused`, `upstream-unreferenced`,
`config/version`. Warnings do not block reload - but fix them; unused
entities and shadowed regexes are almost always mistakes. Note
`regex-shadowed-by-exact`: an exact route beats your regex regardless of
declaration order (fixed precedence exact > regex > prefix).

## diff

```sh
dwara-cli diff old.yaml new.yaml
```

Compiled route/upstream/consumer deltas as `+`/`-`/`~`. The right artifact
to paste into a change request: it shows what the gateway will actually do
differently, not text diffs.

## explain

```sh
dwara-cli explain --config dwara.yaml --method GET --path /v1/users/42 \
                  [--header 'X-API-Key: k'] [--header 'Host: api.example.com'] \
                  [--consumer mobile-app]
```

Renders the decision the gateway would make for that request: matched route
(and why), applied policies, auth outcome. The fastest way to debug match
surprises:

- exact beats regex beats prefix, always;
- non-path criteria (methods/headers/query/cookies/accept) are AND-ed
  **after** path resolution - a criteria miss is a 404, not fall-through to
  the next candidate;
- prefix is a byte prefix (`/v1` matches `/v1anything`); among prefixes the
  longest wins; among regexes the **first declared** wins.

## schema

```sh
dwara-cli schema > config-reference.json
```

The JSON Schema of the config, generated from the running code. The
authoritative answer to "does this key exist / what are this enum's values".
Feed it to editors for completion, or grep it.

## migrate

```sh
dwara-cli migrate dwara.yaml            # prints upgraded config to stdout
dwara-cli migrate dwara.yaml --in-place # writes back
```

Bumps the schema `version` to current and re-serializes; migration notes go
to stderr. Run it when upgrading the gateway binary across schema versions.

## Non-config companions

- `dwara-cli status [--admin URL]` - one-shot snapshot of a running gateway
  (`DWARA_ADMIN` env, default `http://127.0.0.1:2019`).
- `dwara-cli top [--interval ms]` - live load-balancer/breaker view.
- `dwara-cli run` - spawn the gateway binary with pass-through args/env.
- `dwara-cli upgrade` / `import` / `tf` / `plugin` / `replay` / `k8s` - see
  the dwara-operations, dwara-migration, and dwara-plugins skills.
- `dwara-cli completions bash|zsh|fish|powershell`.

## CI recipe

```sh
dwara-cli validate dwara.yaml && dwara-cli lint dwara.yaml
```

Treat lint exit 2 as a warning gate you can waive, exit 1 as fatal. Keep
`config-reference.json` regenerated (`dwara-cli schema`) in the same PR as
any config-surface change so downstream tooling never drifts.
