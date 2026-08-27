# Environment variables reference

All operational knobs are environment variables; all topology and
policy is YAML config (see [Configuration](../guide/configuration)).

| Variable | Default | Purpose |
| --- | --- | --- |
| `DWARA_CONFIG` | `./dwara.yaml` | Path to the gateway config file (watched for changes). |
| `DWARA_BIND` | unset | Overrides all configured listeners with a single cleartext HTTP listener on this address. Dev/test escape hatch — the synthetic listener cannot receive listener-level policies or authorization. |
| `DWARA_STATE_DB` | unset | Path to a SQLite state store. Unset = no store. See the state store section in the repository README. |
| `DWARA_CREDENTIAL_PEPPER` | unset | Per-deployment secret that peppers stored credential hashes (`hmac-sha256:<hex>`). Unset = legacy-only mode (`sha256:` entries keep verifying). Never logged. |
| `DWARA_ADMIN_DEV` | unset | `1` = serve the admin API as plaintext on a loopback bind. Dev only — see [Admin API](../guide/admin-api#dev-fallback-never-in-production). |
| `DWARA_LOG` | `dwara=info` | Log filter, `RUST_LOG` syntax. |
| `DWARA_ACCESS_LOG_SAMPLE` | `1.0` | Fraction (0.0-1.0) of non-error access-log lines emitted; errors (5xx) always log. |
| `DWARA_OTLP_ENDPOINT` | unset | Base OTLP collector endpoint (`http://` only). Only live in an `otlp`-feature build; reserved-but-inert otherwise. |
| `DWARA_SHUTDOWN_TIMEOUT_SECS` | `10` | Graceful-drain budget on `SIGTERM`/`SIGINT`. |
| `DWARA_HTTP1_MAX_HEADERS` | `100` | HTTP/1 max header count. |
| `DWARA_HTTP1_MAX_BUF_KIB` | `64` | HTTP/1 read-buffer cap (KiB). |
| `DWARA_HTTP1_HEADER_TIMEOUT_MS` | `10000` | HTTP/1 slowloris header-arrival timeout. |
| `DWARA_H2_MAX_CONCURRENT_STREAMS` | `128` | HTTP/2 max concurrent streams per connection. |
| `DWARA_H2_STREAM_WINDOW_KIB` | `1024` | HTTP/2 per-stream receive window (KiB). |
| `DWARA_H2_CONNECTION_WINDOW_KIB` | `4096` | HTTP/2 connection-wide receive window (KiB). |
| `DWARA_H2_MAX_SEND_BUF_KIB` | `1024` | HTTP/2 outbound send buffer per connection (KiB). |
| `DWARA_REQUEST_BODY_TIMEOUT_MS` | `30000` (`0` disables) | Inactivity gap allowed between inbound request body frames. |

See [Operations](../guide/operations) and [Observability](../guide/observability)
for the behavior each of these controls.
