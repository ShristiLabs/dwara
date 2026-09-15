# Hot reload and secret references

## The publish pipeline

Every config change - file watch, SIGHUP, or `PATCH /config` - goes through
the same pipeline:

```
read -> Parse -> Validate -> Compile -> atomic Publish (new generation)
```

- Publishes swap an immutable snapshot; in-flight requests finish on their
  own generation.
- A failing candidate is reported in full (every issue at once) and the
  **previous generation keeps serving**. The process never exits on a bad
  reload.
- Each publish bumps a generation id: `config_generation` metric, the
  `x-dwara-config-generation` header on `GET /config`, and `/runtime_info`.
- Listener bind sets and TLS certificates also reload; the listener socket
  set itself is fixed at process start.

Three triggers:

| Trigger | When to use |
| --- | --- |
| File save (watch; atomic rename, debounced) | Default when config is file-managed. Unchanged content = no-op. |
| `kill -HUP <pid>` | Force republish; also works if the file watcher fails. |
| `PATCH /config` (admin API, full-document YAML) | Config is API-managed. Dry-run compiles first; 400 lists all issues. |

## Secret references

Two OSS forms (Vault/KMS forms are enterprise):

```yaml
password: ${MY_ENV_VAR}          # env var: [A-Za-z_][A-Za-z0-9_]*, resolved at config build
key_file_path: ${file:/etc/secrets/key}   # file: must exist, UTF-8, non-empty, <= 1 MiB;
                                          # exactly one trailing \n / \r\n is trimmed
```

Rules that matter:

- Resolution happens **when the config generation is built**. Changing the
  file's *contents* does not re-resolve - trigger a reload after changing
  the file. Env changes require a process restart.
- A malformed reference is a validation error, never a literal string.
  An unresolvable one (missing env var/file) fails the publish.
- Whole-value rule for AI provider auth: `auth.value: ${OPENAI_AUTH_HEADER}`
  where the env var contains `Bearer sk-...` - the reference must span the
  entire value, prefixes cannot live outside the reference.
- Inline secret *values* are redacted when config is echoed:
  `GET /config` shows `${redacted:sha256:<8hex>}` placeholders. Patching a
  placeholder back verbatim is a 400 - never round-trip redacted output;
  edit the source file instead.
- API-key credentials are not stored as configured plaintext in the state
  store: they are peppered hashes (`DWARA_CREDENTIAL_PEPPER`; rotate with
  `DWARA_CREDENTIAL_PEPPER_PREVIOUS` for zero-downtime pepper rotation).

## What hot-reloads vs what needs a restart

| Change | Takes effect |
| --- | --- |
| Routes, services, upstreams, consumers, policies, ai block, admin config, TLS certs | Next publish (file save / SIGHUP / PATCH) |
| `${file:...}` contents | After triggering a reload (resolution is per-generation) |
| `${ENV_VAR}` values | Process restart only |
| Listener addresses/ports (the bind set) | Process restart only |
| Env-var knobs (`DWARA_*` below) | Process restart only |

Common `DWARA_*` env vars: `DWARA_CONFIG` (config path),
`DWARA_STATE_DB` (SQLite state store - required for quota enforcement and
MCP sessions), `DWARA_LOG` (`dwara=info`), `DWARA_ADMIN` (CLI default admin
URL), `DWARA_ADMIN_DEV` (loopback plaintext admin - dev only),
`DWARA_CREDENTIAL_PEPPER`/`_PREVIOUS`, `DWARA_PID_FILE` +
`DWARA_UPGRADE_BINARY` (zero-downtime upgrades), `DWARA_OTLP_ENDPOINT` +
`DWARA_OTLP_METRICS_INTERVAL_SECS`, `DWARA_SHUTDOWN_TIMEOUT_SECS`.
Full list: the environment-variables reference on the docs site.
