# Verify and troubleshoot a first run

## Verification checklist (in order)

1. **Process/log health.** The gateway logs structured JSON to stdout. A
   successful publish logs the config generation. No output on stdout besides
   logs = normal; the gateway does not daemonize.
2. **Data plane answers.**
   ```sh
   curl -i http://localhost:8080/healthz          # reserved path -> 200 "ok"
   curl --cacert ../certs/server.crt -i https://localhost:8443/
   ```
3. **Auth path (quickstart config).**
   ```sh
   curl -i http://localhost:8080/v1/anything -H 'X-API-Key: dwara-quickstart-api-key'
   ```
   Missing/unknown credential on an `auth_required: true` route -> `401`.
4. **Admin plane answers (needs client cert).**
   ```sh
   curl --cert ../certs/client.crt --key ../certs/client.key \
        --cacert ../certs/server.crt https://localhost:2019/health
   ```
   `/health` reports readiness, the config generation, and per-upstream
   endpoint health. `/runtime_info` reports version, uptime, generation.
5. **Metrics.** `curl http://localhost:8080/metrics` (Prometheus text) - or
   the same path on any listener; it is reserved and exempt from policies.

## First-run failure triage

| Symptom | Cause | Fix |
| --- | --- | --- |
| Gateway exits at startup, YAML errors listed | Strict config: unknown key, wrong type, missing required field | Every error names its path - fix all of them, not just the first; pre-flight with `dwara-cli validate dwara.yaml` |
| `curl: (60) SSL certificate problem` | Self-signed quickstart CA not trusted | Pass `--cacert ../certs/server.crt` (or `-k` for throwaway checks only) |
| Admin `connection reset` / TLS alert | Admin API is mTLS-only; no client cert presented | Use `--cert`/`--key` with the client cert from `certs/`; three-file TLS config (`cert_file`, `key_file`, `client_ca_file`) is mandatory in the `admin:` block |
| `401` on every request to `/v1/...` | Route is `auth_required: true` | Send the API key header (quickstart ships `X-API-Key: dwara-quickstart-api-key`) or set `auth_required: false` for the route |
| Logs warn on each request about quotas/state | `DWARA_STATE_DB` not set | Set it to a writable SQLite path (compose already does; manual runs often forget) |
| Analytics DB not created / permission denied | Bind-mounted data dir not writable by the gateway user (UID 65532 in the quickstart image) | `chown -R 65532:65532 data` on Linux |
| Port already in use | 8080/8443/2019 occupied | Change listener `port` in config and the compose port mapping together |
| `404` on a path you configured | Path resolves through fixed precedence `exact > regex > prefix`; a miss is a 404 with no fall-through | Check the route's `match.path.type` and non-path criteria (`methods`, `headers`, ... are AND-ed and applied after path resolution) |
| Reload didn't apply | New config failed validation | Failed reloads keep the previous generation serving; the errors are in the logs - fix and re-save |

## What "good" looks like

```sh
$ curl -i http://localhost:8080/healthz
HTTP/1.1 200 OK
...

$ curl -s http://localhost:8080/metrics | head -3
# HELP ... Prometheus text format
```

Access log lines carry a `request_id`; the gateway echoes it back as the
`X-Request-Id` response header - use it to correlate a client complaint
with log lines.
