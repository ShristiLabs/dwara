#!/bin/bash
# test-06-grpc-proxying.sh — native gRPC through the gateway.
#
# The grpc-route matches gRPC RPC paths (/dwdemo.DemoService/Method)
# like any path prefix; the grpc-upstream is dialed with
# protocol: http2, which is TLS with ALPN h2 (the gateway does not
# speak h2c prior-knowledge toward upstreams — that is why the demo
# gRPC server also listens with TLS; see grpc-certs/ and the compose
# file). Trailers pass through, so a successful RPC surfaces as a
# normal gRPC response in the client.
#
# Clients enter on the shared listeners:
#   - edge-http  :8080  plaintext, grpcurl -plaintext (h2c prior
#                          knowledge from the client; the gateway's own
#                          hop to the upstream is TLS+h2 regardless)
#   - edge-https :8443  TLS, grpcurl -cacert (h2 via ALPN)
#
# Server reflection is ALSO routed through the gateway
# (grpc-reflection-route), so grpcurl needs no local proto files —
# the schema is discovered through the proxy hop exactly as it would
# be against the upstream directly.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-06-grpc-proxying ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# --- Direct-to-upstream sanity: the gRPC server's TLS listener is up
# (published on host port 19012) and speaks TLS+h2. -insecure skips
# verification of the self-signed demo cert (the gateway verifies it
# properly via trusted_ca_file). Uses the upstream's reflection.
out=$(docker run --rm --network host fullstorydev/grpcurl \
  -insecure -d '{"name":"upstream"}' \
  localhost:19012 dwdemo.DemoService/SayHello 2>&1 || true)
assert_contains "$out" 'hello, upstream!' "gRPC upstream TLS listener serves SayHello directly (:19012)"

# --- Server reflection through the gateway (grpcurl 'list' with no
# local proto files — the schema round-trips the proxy hop).
out=$(docker run --rm --network host fullstorydev/grpcurl \
  -plaintext localhost:8080 list 2>&1 || true)
assert_contains "$out" 'dwdemo.DemoService' "reflection (list) works through the gateway"

# --- Plaintext entry: grpcurl -plaintext through the gateway (client
# uses h2c prior knowledge on :8080; the gateway relays over its own
# TLS+h2 connection to grpc:8443).
out=$(docker run --rm --network host fullstorydev/grpcurl \
  -plaintext -d '{"name":"demo"}' \
  localhost:8080 dwdemo.DemoService/SayHello 2>&1 || true)
assert_contains "$out" 'hello, demo!' "SayHello via gateway :8080 (plaintext h2c entry)"

# --- TLS entry: grpcurl verifies the gateway's cert with the shared CA
# and negotiates h2 via ALPN on :8443.
out=$(docker run --rm --network host \
  -v "$PWD/../_shared/certs:/certs:ro" \
  fullstorydev/grpcurl \
  -cacert /certs/server.crt -d '{"name":"tls"}' \
  localhost:8443 dwdemo.DemoService/SayHello 2>&1 || true)
assert_contains "$out" 'hello, tls!' "SayHello via gateway :8443 (TLS + h2 ALPN entry)"

# --- A second RPC (unary) through the gateway.
out=$(docker run --rm --network host fullstorydev/grpcurl \
  -plaintext -d '{"text":"grpc proxying"}' \
  localhost:8080 dwdemo.DemoService/ToUpper 2>&1 || true)
assert_contains "$out" 'GRPC PROXYING' "ToUpper via gateway :8080"

# --- Server-streaming RPC (Count): trailers pass through the proxy
# hop and the stream completes; grpcurl prints every message (3..1).
out=$(docker run --rm --network host fullstorydev/grpcurl \
  -plaintext -d '{"to":3}' \
  localhost:8080 dwdemo.DemoService/Count 2>&1 || true)
assert_contains "$out" '"value": 3' "Count stream first message via gateway"
assert_contains "$out" '"value": 1' "Count stream last message via gateway (trailers intact)"

print_summary
