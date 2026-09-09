#!/bin/bash
# test-03-protocol-translation.sh — protocol translation block (DW-100).
#
# The /translate/ route carries a `translation` block with
# kind: rest_to_graphql and a query_template (the contract that would
# turn a REST JSON body into a GraphQL query for the upstream).
#
# FINDING (folded into this category's README): REST->gRPC translation
# is NOT a `translation` kind — it is the grpc_web.transcoding engine
# of test-02 (the same descriptors + google.api.http annotations). The
# `translation` block's four kinds (rest_to_graphql, graphql_to_rest,
# rest_to_soap, soap_to_rest) are library components
# (dataplane/translation*.rs) that are not dispatched from the proxy
# path today.
#
# This test proves the config shape validates (the gateway booted with
# the block) and records the observed passthrough behavior: the echo
# upstream receives the ORIGINAL REST JSON, not a GraphQL query.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-03: protocol translation (rest_to_graphql) ==="

wait_for http://localhost:8080/healthz 30 || exit 1

echo "--- POST /translate/hello {\"name\":\"world\"} ---"
status=$(http_status "http://localhost:8080/translate/hello" -X POST -H "Content-Type: application/json" \
  -d '{"name":"world"}')
body=$(http_body "http://localhost:8080/translate/hello" -X POST -H "Content-Type: application/json" \
  -d '{"name":"world"}')
echo "  status=$status"
echo "  body=$(echo "$body" | head -c 300)"

assert_status 200 "$status" "route with the translation block serves traffic (block accepted)"

# The echo upstream reflects what the gateway actually forwarded. If the
# rest_to_graphql translator ran, the forwarded body would be a GraphQL
# query built from the template; passthrough means the raw REST JSON.
assert_contains "$body" 'world' "upstream received the original REST JSON body (echo reflects the value)"
assert_not_contains "$body" 'query {' \
  "no GraphQL query was synthesized (rest_to_graphql not dispatched — documented limitation)"
assert_not_contains "$body" 'greeting' \
  "query_template fields do not appear in the forwarded body"

echo ""
echo "NOTE: REST->gRPC translation is the grpc_web.transcoding machinery"
echo "      (test-02); the translation block's kinds are library-only today."
echo "      See README.md (Documented limitations)."

print_summary
