#!/bin/bash
# test-04-redis-limiters.sh — Redis-backed rate limiters (enterprise feature).
#
# The distributed Redis-backed rate limiter (DW-031) is an enterprise
# feature: the GCRA bucket state lives in Redis and is updated
# atomically via a Lua script, so a fleet of N instances shares one
# rate limit. See crates/dwara-core/src/extensions/redis_rate_limiter.rs.
#
# The config block (gateway.redis_rate_limiter) is present in this
# demo's dwara.yaml but is INERT in the OSS build: the gateway logs a
# notice and uses the local in-memory GCRA limiter instead (one limit
# per process). The same GCRA algorithm runs; only the backing store
# differs.
#
# The OSS edition supports local rate limiting via the `rate_limit` and
# `rate_limits` policy fields. This test verifies the gateway proxies
# traffic (rate limiting is a policy on top of the proxy path).
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-04-redis-limiters ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# Verify the gateway proxies to the echo upstream.
status=$(http_status http://localhost:8080/v1/echo/test)
assert_status 200 "$status" "gateway proxies to echo (local limiter path)"

# Verify multiple requests succeed (no rate limiting is configured on
# these routes, so all requests should pass).
for i in 1 2 3 4 5; do
  status=$(http_status http://localhost:8080/v1/echo/test)
  assert_status 200 "$status" "request $i returns 200"
done

# Verify the static upstream is also reachable.
status=$(http_status http://localhost:8080/)
assert_status 200 "$status" "gateway proxies to static"

print_summary
