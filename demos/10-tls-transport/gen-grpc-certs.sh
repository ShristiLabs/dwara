#!/bin/bash
# gen-grpc-certs.sh — self-signed cert for the gRPC TLS upstream.
#
# The gateway's `protocol: http2` upstream transport dials TLS with
# ALPN h2 and verifies the server certificate against the endpoint
# hostname (the docker service name `grpc`). The shared quickstart
# cert is only valid for localhost, so the gRPC upstream gets its own
# self-signed pair with SAN DNS:grpc (+ localhost / 127.0.0.1 so the
# same pair works for direct grpcurl checks against the published
# port). The gateway trusts it via `trusted_ca_file` (a self-signed
# leaf anchors itself in the root store).
#
# Run from the demo directory:  ./gen-grpc-certs.sh
# Regenerates grpc-certs/server.crt + grpc-certs/server.key.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$DIR/grpc-certs"
mkdir -p "$OUT"

# basicConstraints MUST be CA:FALSE: this macOS openssl defaults
# self-signed (-x509) certs to CA:TRUE, and rustls's webpki verifier
# rejects a CA-flagged certificate presented as the end entity
# (CaUsedAsEndEntity). A self-signed non-CA leaf still anchors itself
# fine in the gateway's trusted_ca_file root store.
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout "$OUT/server.key" \
  -out "$OUT/server.crt" \
  -subj "/CN=grpc" \
  -addext "subjectAltName=DNS:grpc,DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  >/dev/null 2>&1

echo "wrote $OUT/server.crt and $OUT/server.key"
openssl x509 -in "$OUT/server.crt" -noout -subject -ext subjectAltName
