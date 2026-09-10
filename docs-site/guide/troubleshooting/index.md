# Troubleshooting playbooks

This section covers common operational issues and how to diagnose them.
Each playbook walks through the symptoms, likely causes, and the steps
to resolve the issue.

## Playbooks

- [503 Service Unavailable](./503-upstream-health) — upstream health,
  circuit breaker, and connection issues.
- [429 Too Many Requests](./429-rate-limit-quota-budget) — rate
  limiting, quotas, and AI token budgets.
- [Config reload failure](./config-reload-failure) — validation errors
  and hot-reload issues.
- [High latency](./high-latency) — upstream latency, connection pool
  exhaustion, and queueing.
- [AI request failures](./ai-request-failures) — provider errors,
  translation errors, and AI-specific issues.
- [mTLS handshake failures](./mtls-handshake-failures) — certificate
  issues, trust chain, and client cert validation.

## General debugging approach

1. **Check the admin API** — `GET /health` and `GET /stats` on the
   admin listener show the gateway's view of upstream health and
   active connections.
2. **Check the access log** — every request is logged with the
   request id, route, upstream, status, and duration. Filter by the
   failing request's correlation id.
3. **Use `dwara explain`** — the `dwara explain <method> <path>`
   command traces a request through the full decision path, showing
   which route matched, which policies applied, and which upstream
   would be selected. See [dwara explain](../replay-debugging).
4. **Check metrics** — the gateway exports Prometheus-compatible
   metrics on the admin listener. Look for spikes in error rates,
   latency histograms, and breaker state.
5. **Check the config** — `dwara validate` checks the config for
   validation errors without applying it. `dwara diff` shows what
   changed between the current and desired config.

## See also

- [Operations](../operations)
- [Replay time-travel debugging](../replay-debugging)
- [CLI](../cli)
