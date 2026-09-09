#!/bin/bash
# test-14-ent-controller-persistence.sh — ent controller persistence
# (enterprise feature, documented).
#
# The enterprise controller — the management-plane component that
# distributes config to a fleet of gateway data planes — stores its
# durable state in PostgreSQL: config snapshots (immutable, versioned,
# with author/publish time/full YAML), license state and entitlement
# counters, fleet membership (registered edges, heartbeats, versions,
# health), and federated analytics rollups. The store is accessed only
# by the controller; data planes receive config and report heartbeats
# over the cluster-sync protocol and never touch the database.
#
# The backend was chosen by ADR: SQLite was rejected (the controller is
# a multi-writer service; SQLite's single-writer model would serialize
# config publishes, heartbeat updates, and analytics ingestion), an
# object store was rejected (the query patterns are relational), and
# PostgreSQL was chosen for multi-writer concurrency, operational
# tooling, and relational fit. See
# docs-site/guide/ent-controller-persistence.md.
#
# There is NO OSS-validate config surface for the persistence backend:
# it is a licensed runtime concern, not part of the gateway config
# schema (the controller binary's launch surface is CLI flags / env
# vars, documented in ./fixtures/ent-controller-launch.env). This demo
# deliberately ships NO postgres container. This test therefore follows
# the documented style:
#   1) The OSS gateway runs its single-node SQLite state store and
#      proxies traffic normally (the data plane never touches the
#      controller's PostgreSQL).
#   2) The shipped reference snippet documents the controller's real
#      launch surface (env/flags) and the four persistence categories.
#   3) The demo's docker-compose.yml ships no postgres service (the
#      documented decision: no DB container in the OSS demo).
set -euo pipefail
source ../_shared/helpers.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== test-14-ent-controller-persistence ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# 1) The OSS gateway runs its own local SQLite state store (mounted at
#    ./data/state.db) and proxies normally. Data planes never touch the
#    controller's PostgreSQL store, so single-node behavior is the
#    correct OSS-equivalent demonstration.
status=$(http_status http://localhost:8080/healthz)
assert_status 200 "$status" "gateway runs local SQLite state store (no controller DB)"

status=$(http_status http://localhost:8080/v1/echo/test)
assert_status 200 "$status" "gateway proxies to echo"

status=$(http_status http://localhost:8080/)
assert_status 200 "$status" "gateway proxies to static"

# The state DB exists on the mounted volume (the OSS persistence the
# data plane actually does: SQLite at DWARA_STATE_DB).
if [ -f "$SCRIPT_DIR/data/state.db" ]; then
  echo -e "${GREEN}PASS${NC}: OSS SQLite state DB present on the mounted volume (data/state.db)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: OSS SQLite state DB missing (data/state.db)"
  FAIL=$((FAIL + 1))
fi

# 2) The shipped reference snippet documents the controller's real
#    launch surface (env vars from crates/dwara-cli/src/bin/
#    dwara_controller.rs) and the PostgreSQL persistence categories.
REF="$SCRIPT_DIR/fixtures/ent-controller-launch.env"
if [ -f "$REF" ]; then
  echo -e "${GREEN}PASS${NC}: controller reference snippet shipped (fixtures/ent-controller-launch.env)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: controller reference snippet missing (fixtures/ent-controller-launch.env)"
  FAIL=$((FAIL + 1))
fi
ref_body=$(cat "$REF" 2>/dev/null || true)
assert_contains "$ref_body" "DWARA_CP_BIND" "reference documents the controller gRPC bind flag"
assert_contains "$ref_body" "DWARA_CP_CONFIG_SOURCE" "reference documents the config-source watch flag"
assert_contains "$ref_body" "PostgreSQL" "reference documents the PostgreSQL persistence backend"
assert_contains "$ref_body" "Config snapshots" "reference documents the config-snapshots state category"
assert_contains "$ref_body" "License state" "reference documents the license-state category"
assert_contains "$ref_body" "Fleet membership" "reference documents the fleet-membership category"
assert_contains "$ref_body" "Federated analytics" "reference documents the federated-analytics category"

# 3) Guard: this demo ships no postgres container (documented decision
#    — the ent controller + PostgreSQL require the ent build; see
#    quickstart/enterprise/ for the full topology).
compose_body=$(cat "$SCRIPT_DIR/docker-compose.yml")
assert_not_contains "$compose_body" "postgres" "docker-compose.yml ships no postgres service"
assert_not_contains "$compose_body" "pgsql" "docker-compose.yml ships no postgres-derived image"

echo ""
echo "NOTE: the ent controller's durable state (config snapshots,"
echo "license state, fleet membership, federated analytics rollups)"
echo "lives in PostgreSQL behind the ent build + a license. There is no"
echo "OSS-validate YAML surface for the DSN (the controller launches"
echo "via flags/env, documented in fixtures/ent-controller-launch.env), so"
echo "this demo documents the store instead of running it. See"
echo "docs-site/guide/ent-controller-persistence.md and"
echo "quickstart/enterprise/."

print_summary
