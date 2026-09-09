# Environment variables

The binary requires a config at startup (exit 1 with all validation issues
if invalid). Reload: file change (debounced) or SIGHUP. Shutdown:
SIGTERM/SIGINT with backlog flush + drain. Admin API POST is live-published.

| Variable | Default | Purpose |
|---|---|---|
| `DWARA_CONFIG` | `./dwara.yaml` | config file path (watched for changes) |
| `DWARA_BIND` | `127.0.0.1:8080` | override for a single cleartext listener |
| `DWARA_STATE_DB` | unset | enable SQLite state store |
| `DWARA_CREDENTIAL_PEPPER` | unset | per-deployment secret for credential hashes; unset = legacy mode |
| `DWARA_CREDENTIAL_PEPPER_PREVIOUS` | unset | prior pepper for seamless rotation |
| `DWARA_ADMIN_DEV` | unset | `1` = plaintext loopback admin (dev only) |
| `DWARA_LOG` | `dwara=info` | log filter |
| `DWARA_ACCESS_LOG_SAMPLE` | `1.0` | access-line sampling rate |
| `DWARA_OTLP_ENDPOINT` | unset | OTLP trace + metrics export; inert when unset |
| `DWARA_CONSOLE` | unset | `1` = tokio-console gRPC on 127.0.0.1:6669 |
| `DWARA_PID_FILE` | unset | PID file path (enables `dwara upgrade` via SIGUSR2) |
| `DWARA_UPGRADE_BINARY` | unset | binary path for zero-downtime upgrade |
| `DWARA_UPGRADE_READY_SOCKET` | unset | ready socket for upgrade hand-off |
| `DWARA_UPGRADE_READY_TIMEOUT_SECS` | unset | ready timeout for upgrade |
| `DWARA_INSTANCE_ID` | unset | stable instance identifier (fleet/CP-DP) |
| `DWARA_LICENSE_PUBLIC_KEY` | unset | public key for ent license verification |
| `DWARA_PROFILE` | unset | environment profile overlay (dev/staging/prod) |
| `DWARA_HTTP1_MAX_HEADERS` | see README | HTTP/1 hardening |
| `DWARA_HTTP1_MAX_BUF_KIB` | see README | HTTP/1 hardening |
| `DWARA_HTTP1_HEADER_TIMEOUT_MS` | see README | HTTP/1 hardening |
| `DWARA_H2_MAX_CONCURRENT_STREAMS` | see README | HTTP/2 hardening |
| `DWARA_H2_STREAM_WINDOW_KIB` | see README | HTTP/2 hardening |
| `DWARA_H2_CONNECTION_WINDOW_KIB` | see README | HTTP/2 hardening |
| `DWARA_H2_MAX_SEND_BUF_KIB` | see README | HTTP/2 hardening |
| `DWARA_REQUEST_BODY_TIMEOUT_MS` | see README | request body timeout |
| `DWARA_SHUTDOWN_TIMEOUT_SECS` | `10` | graceful drain bound |
