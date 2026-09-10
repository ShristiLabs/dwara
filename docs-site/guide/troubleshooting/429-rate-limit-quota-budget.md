# 429 Too Many Requests

A 429 response means the request was rejected by a rate limiter,
quota, or AI token budget. The error envelope includes the
`code` field to distinguish which.

## Symptoms

- Client receives `429 Too Many Requests` with
  `{"error":{"code":"...","message":"...","request_id":"..."}}`.
- The `Retry-After` header indicates when to retry.
- Metrics show rate limiter or budget counters increasing.

## Likely causes

### Rate limiting

The consumer has exceeded its rate limit. The error code is
`rate_limited`.

**Diagnose:**

```sh
# Check rate limiter metrics
curl -k https://127.0.0.1:2019/metrics | grep dwara_rate_limited
```

**Fix:** Increase the rate limit in the consumer's policy or wait
for the window to reset. Rate limits are configured per-policy:

```yaml
policies:
  - name: standard
    rate_limit:
      requests_per_second: 100
      burst: 50
```

### Quota exceeded

The consumer has exceeded its daily or monthly request quota. The
error code is `quota_exceeded`.

**Diagnose:**

```sh
# Check quota usage from the admin API
curl -k https://127.0.0.1:2019/analytics/usage?consumer=my-consumer
```

**Fix:** Increase the quota in the consumer's policy or wait for
the quota window to reset (daily at midnight, monthly on the 1st):

```yaml
policies:
  - name: standard
    quotas:
      daily_requests: 100000
      monthly_requests: 1000000
```

### AI token budget exhausted

The consumer has exhausted its AI token or cost budget. The error
code is `ai_budget_exceeded`.

**Diagnose:**

```sh
# Check AI budget metrics
curl -k https://127.0.0.1:2019/metrics | grep dwara_ai_budget
```

**Fix:** Increase the token budget in the consumer's policy or wait
for the budget window to reset:

```yaml
policies:
  - name: ai-standard
    token_budget:
      tokens_per_min: 100000
      tokens_per_day: 1000000
      cost_per_day_micros: 5000000  # $5/day
```

### Admission queue full

The gateway's concurrency cap has been reached and the admission
queue is full. The error code is `queue_full`.

**Diagnose:**

```sh
# Check admission queue metrics
curl -k https://127.0.0.1:2019/metrics | grep dwara_admission
```

**Fix:** Increase the concurrency cap or queue size in the listener
config, or scale out the gateway:

```yaml
listeners:
  - name: main
    concurrency:
      max_connections: 10000
      queue:
        max_queued: 1000
        timeout_ms: 5000
```

## See also

- [Rate limiting](../rate-limiting)
- [Quotas and metering](../quotas)
- [AI token budgets](../ai-token-budgets)
- [Admission queues](../admission-queue)
