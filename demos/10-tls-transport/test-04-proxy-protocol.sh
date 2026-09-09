#!/bin/bash
# test-04-proxy-protocol.sh — PROXY protocol (documented, opt-in).
#
# dwara supports PROXY protocol v1/v2 (DW-030): when a listener sets
# `proxy_protocol: true`, the gateway reads a PROXY header as the
# FIRST bytes of every connection (before the TLS handshake) and uses
# the conveyed peer address for authz IP ACLs, rate-limit keying, and
# X-Forwarded-For / X-Real-IP. It is OPT-IN (default false) — a
# plaintext listener that does not expect a PROXY line never
# interprets the first request bytes as one.
#
# Sending a PROXY header from curl is not directly possible (curl has
# no PROXY-protocol option); it requires a Layer-4 load balancer (e.g.
# HAProxy, NGINX stream, AWS NLB) in front. This demo does not run an
# L4 LB, so the live PROXY-protocol path is not exercised here.
#
# What we CAN verify is that the plaintext HTTP listener (which has
# proxy_protocol at its default of false) still serves normal HTTP
# traffic correctly — i.e. the gateway is up and routing.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-04-proxy-protocol ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# Plaintext HTTP listener (proxy_protocol off) serves normally -> 200.
status=$(http_status http://localhost:8080/healthz)
assert_status 200 "$status" "HTTP listener (no PROXY protocol) returns 200"

echo "NOTE: PROXY protocol v1/v2 is opt-in (proxy_protocol: true) and"
echo "      requires an L4 load balancer in front to send the header."
echo "      Not exercised live here; see dwara.yaml edge-http listener"
echo "      and the README for how to enable it."

print_summary
