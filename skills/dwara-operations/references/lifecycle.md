# Lifecycle: reload, drain, upgrade, systemd, triage

## Reload (covered in dwara-config, operator view)

- File save (atomic rename observed, debounced; unchanged content = no-op),
  `SIGHUP` (force republish - also the fallback if the watcher breaks), or
  `PATCH /config`. One pipeline: Parse -> Validate -> Compile -> atomic
  Publish as a new **generation**.
- In-flight requests finish on their own generation. A bad candidate is
  fully reported in logs and the previous generation keeps serving - the
  process never exits on reload failure.
- Listener certificates reload; the listener **bind set** is fixed at
  process start.
- Confirm what's live: `GET /runtime_info` or the
  `x-dwara-config-generation` header on `GET /config`; watch
  `config_generation` in `/metrics`.

## Shutdown

`SIGTERM` drains: stop accepting, finish in-flight (bounded by
`DWARA_SHUTDOWN_TIMEOUT_SECS`, default 10s), flush buffered analytics and
OTLP, exit 0.

## Zero-downtime binary upgrade (SO_REUSEPORT hand-off)

1. Start the gateway with `DWARA_PID_FILE=/var/run/dwara.pid`.
2. Place the new binary (or set `DWARA_UPGRADE_BINARY=/path/to/new`).
3. Trigger: `dwara-cli upgrade [--pid N | --pid-file F]` or
   `kill -USR2 <pid>`.
4. What happens: old process spawns the new binary with inherited env ->
   new process binds the same ports (SO_REUSEPORT) -> signals READY over a
   Unix socket (wait bounded by `DWARA_UPGRADE_READY_TIMEOUT_SECS`, 30s) ->
   old process drains exactly like SIGTERM and exits 0.
5. Failure mode is safe: if the child fails to build/initialize or times
   out, the old process keeps serving.

Rollback story = rerun the upgrade against the previous binary; a failed
upgrade never takes the gateway down. The listener bind set cannot change
across the hand-off (fixed at startup).

## systemd unit shape

```ini
[Service]
Type=exec
Environment=DWARA_CONFIG=/etc/dwara/dwara.yaml
Environment=DWARA_STATE_DB=/var/lib/dwara/state.db
Environment=DWARA_PID_FILE=/var/run/dwara.pid
ExecStart=/usr/local/bin/dwara
ExecReload=/bin/kill -HUP $MAINPID      # config reload
Restart=on-failure
```

Use `Type=exec` (readiness = exec success), `Restart=on-failure`; combine
with SIGUSR2 upgrades for binary rollouts.

## Triage playbook (from the docs-site troubleshooting guides)

**503 upstream_unavailable / empty bodies**
`GET /health` -> per-endpoint states; passive `health` may have ejected
endpoints (`endpoint_health`, ejection events in webhooks/logs); breaker
open (`breaker_state=1`)? Recently-deployed endpoints still in
`slow_start_ms` ramp? Connection caps saturated
(`connection_cap`/`max_pending`)?

**429 family - disambiguate by `code`**
`rate_limited` (policy windows - check which of consumer/route/service/
listener/global attached; headers name the limiting rule's limits) vs quota
(`daily/monthly_requests` - check `GET /quotas/usage`; is `DWARA_STATE_DB`
set?) vs `ai_budget_exceeded` (tokens/min or cost/day - pricing present for
every reachable alias?).

**Reload didn't apply**
Logs list validation issues; previous generation still serving (verify
`config_generation` didn't move). Common causes: unknown key (strict
schema), unresolvable `${...}` reference, past-`sunset` deprecation date.

**High latency**
Access-log `duration_ms` vs upstream timing: queueing
(`dwara_admission_queue_depth`, shed events), pool exhaustion
(`connection_cap`), upstream slowness (hedging helps), TLS handshake cost
(`dwara_tls_handshake_failures_total`).

**TLS handshake failures**
`dwara_tls_handshake_failures_total`; client CA mismatch, expired cert,
SNI without a matching pair (fallback pair missing), PQ offer from an old
client (experimental hybrid).

**AI request failures**
Response is an OpenAI-shaped error envelope with `request_id` + `code` -
map the code to the pipeline phase (`invalid_json` parse, `model_denied_by_policy`
governance, `guardrail_blocked`, `model_not_found` alias, `provider_unreachable`
transport, `provider_malformed_response` translation, `ai_budget_exceeded`
budget). Streaming failures surface as `provider_stream_aborted` chunks.

## Load testing before you claim a fix

`dwara-loadgen` (ships with the gateway): `--url`, `--protocol h1|h2|h3`,
`--workload throughput|pool-reuse|streaming`, `--connections`,
`--duration`, `--rate`, `--json`, `--insecure`, plus `--echo` for an
in-process upstream with no backend needed. Reproduce, fix, re-measure.
