# Demo 01: user-subset migration to a new API version

The flagship recipe from the docs-site guide
[user-subset migration to a new API version](../../../docs-site/guide/use-cases/user-subset-migration.md),
Option A (entitlement-snapshot plugin) -- run live.

An API ships `/v1/user`; enhancements land as `/v2/user`. Only users
on the entitlement allow-list (owned by a separate microservice)
should be forwarded to `/v2/user`; everyone else keeps hitting
`/v1/user`. An SDK-style proxy-wasm plugin rewrites the target path
per request; the allow-list lands in the plugin's config through the
documented publishing loop.

## What runs

```
                entitlement microservice (owns the allow-list)
                        │  GET /entitlements        (18203)
                        ▼
                services/publish.sh  ── writes ──►  plugins-config/
                (the publisher loop)                 v2-migrator.yaml
                        │  atomic same-name replace of dwara.yaml
                        │  + SIGHUP to the gateway (deterministic)
                        ▼
                    reload ──► new config generation (unchanged module
                        │       checksum = kept plugin health)
                        ▼
 curl ──x-user-id──► dwara gateway :18201 ──► plugin decides per user
                        │   /v1/user ──(user in list)──► /v2/user
                        ▼
                mock user API (18202): /v1/user vs /v2/user,
                distinct JSON per version
```

- `plugin/` -- the `v2-migrator` proxy-wasm plugin (Rust
  proxy-wasm 0.2 SDK, wasm32-wasip1): `request_headers` phase, config
  `{from, to, allowed_users}`, rewrites `:path` for allowed users.
  The filter body matches the documented sample verbatim.
- `services/user-api.py` -- one mock API serving both versions (the
  rewrite happens after route resolution, so the same route/upstream
  sees the rewritten path; that is exactly the docs wiring).
- `services/entitlement.py` -- the entitlement microservice
  (`GET`/`POST /entitlements`, revision counter).
- `services/publish.sh` -- the publisher: pulls the allow-list,
  writes the generated `plugins-config/` include (the plugin's
  config), atomically replaces the main config file with its own
  identical bytes (the documented "touch the main config"), and sends
  the gateway SIGHUP. The signal is the deterministic trigger: macOS
  FSEvents rename events do not always carry the destination file
  name, so the watcher's name filter can miss the file rewrite; SIGHUP
  always re-reads, re-validates, and re-publishes (a forced reload).
  Either trigger alone is correct; together they are reliable
  everywhere.
- `dwara.yaml` -- the wiring: `/v1/*` + plugin, plugin-less `/public/*`
  control route, `includes:` pointing at the generated plugin config.

## What test.sh asserts

1. user on the list -> the `/v2/` endpoint answers (migrated)
2. user off the list -> `/v1/` answers
3. unknown / missing `x-user-id` -> `/v1/` (fail to the old version)
4. empty allow-list -> EVERYONE gets `/v1/` (the safe default)
5. hot-reload flips: publisher adds `user-77`, removes `user-42` --
   the NEXT request changes verdict, no restart (config generation
   moves; module checksum and health stay put)
6. the plugin-less `/public/` route is unaffected throughout
7. the gateway log shows `config_reloaded` generations

## Run

```sh
./test.sh          # from this directory (builds the plugin + finds
                   # or builds the gateway binary first)
```

Ports: gateway 18201, user API 18202, entitlement 18203.

## Notes

- The `:path` rewrite is REAL: the gateway applies a changed `:path`
  write to the forwarded request (after the route's own rewrite, with
  no route re-match -- the plugin's target is the final say for the
  upstream; see the "Header conventions" note in
  `crates/dwara-core/src/dataplane/plugin_dispatch.rs`). The mock user
  API keys on the request path alone, exactly like the documented
  sample; a plugin writing the value it read back unchanged (the
  not-migrated case) is a no-op.
- Publishing the SAME list twice is a no-op for the file-watch path
  (unchanged compiled content is skipped); the SIGHUP path
  re-publishes by design. Either way the verdict is stable.
- Config JSON that fails to parse makes the plugin's `on_configure`
  return false: the plugin is marked broken and its routes answer
  500 `plugin_unavailable` while other routes keep serving. Gate the
  publisher (validate before writing), as the docs advise.
