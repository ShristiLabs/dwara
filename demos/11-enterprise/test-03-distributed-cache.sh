#!/bin/bash
# test-03-distributed-cache.sh — Distributed cache (enterprise feature).
#
# The distributed cache (DW-068) is an enterprise feature: a
# Redis-backed CacheStore implementation with coordinated invalidation
# via Redis Pub/Sub. When one gateway instance purges a cache entry,
# the purge propagates to all other instances in the fleet. See
# crates/dwara-core/src/extensions/redis_cache.rs.
#
# The OSS edition ships a local in-memory (moka) cache behind the same
# CacheStore trait. There is no config-level block for the distributed
# cache -- the CacheStore implementation is selected at startup based
# on the compiled features and license. The route-level `cache` block
# (DW-037) works in both editions; only the backing store differs.
#
# This test verifies that the OSS gateway proxies traffic correctly
# (the cache is a transparent optimization behind the proxy path).
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-03-distributed-cache ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# Verify the gateway proxies to the echo upstream.
status=$(http_status http://localhost:8080/v1/echo/test)
assert_status 200 "$status" "gateway proxies to echo (cache is transparent)"

# Verify the static upstream is reachable.
status=$(http_status http://localhost:8080/)
assert_status 200 "$status" "gateway proxies to static"

# Verify repeated requests are consistent (the proxy path is stable).
body1=$(http_body http://localhost:8080/v1/echo/test)
body2=$(http_body http://localhost:8080/v1/echo/test)
assert_contains "$body1" "echo" "first echo response contains echo data"
assert_contains "$body2" "echo" "second echo response contains echo data"

print_summary
