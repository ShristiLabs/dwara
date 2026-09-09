#!/bin/bash
# test-12-kubernetes-gateway-api.sh — Gateway API manifests +
# conformance report (documented limitation: reconciliation needs a
# cluster).
#
# Dwara implements a Kubernetes Gateway API controller (DW-064) that
# reconciles Gateway API v1 resources (GatewayClass, Gateway,
# HTTPRoute) and standard Ingress resources into its config model:
# the controller watches the Kubernetes API server, translates the
# watched resources into a Dwara config YAML, and writes it to a file
# the gateway hot-reloads.
#
# LIMITATION: this demo category runs on docker compose, not on a
# Kubernetes cluster — the controller's watch/reconcile loop has no
# API server to talk to here, so applying these manifests live is out
# of scope (see README.md for the against-a-cluster procedure). What
# CAN be verified without a cluster:
#
#   1) The demo manifests exist and carry the translator's expected
#      shape (Gateway listeners {name, port, protocol}; HTTPRoute
#      parentRefs + rules with PathPrefix matches + backendRefs).
#   2) `dwara-cli k8s conformance-report` — the deterministic,
#      cluster-free half of the conformance story: it generates the
#      upstream Gateway API conformance report YAML from the
#      features the translator actually supports
#      (crates/dwara-core/src/k8s_gateway/).
#   3) The translator itself is pinned by cluster-free self-tests:
#      cargo test -p dwara-core --test k8s_conformance
#      cargo test -p dwara-core --test k8s_controller
set -euo pipefail
source ../_shared/helpers.sh

REPO_ROOT="$(cd "$(dirname $0)/../.." && pwd)"
DWARA_CLI="$REPO_ROOT/target/debug/dwara-cli"
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
GATEWAY_MANIFEST="$DEMO_DIR/fixtures/gateway.yaml"
ROUTE_MANIFEST="$DEMO_DIR/fixtures/httproute.yaml"

echo "=== test-12-kubernetes-gateway-api ==="

echo "SKIP (documented limitation): Gateway API reconciliation needs a"
echo "      Kubernetes cluster (controller + API server watch loop);"
echo "      this category runs on docker compose. The manifests below"
echo "      are shipped for a cluster run (see README.md), and the"
echo "      cluster-free halves are verified live: manifest shape +"
echo "      'dwara-cli k8s conformance-report'."

# 1) The Gateway manifest: GatewayClass + Gateway with a listener.
if [ -f "$GATEWAY_MANIFEST" ]; then
  echo -e "${GREEN}PASS${NC}: Gateway manifest present ($GATEWAY_MANIFEST)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: Gateway manifest missing ($GATEWAY_MANIFEST)"
  FAIL=$((FAIL + 1))
fi
gw_manifest=$(cat "$GATEWAY_MANIFEST" 2>/dev/null || true)
assert_contains "$gw_manifest" "kind: GatewayClass" "manifest defines a GatewayClass"
assert_contains "$gw_manifest" "shristilabs.com/dwara" \
  "GatewayClass controllerName is shristilabs.com/dwara (DWARA_K8S_CONTROLLER_NAME default)"
assert_contains "$gw_manifest" "kind: Gateway" "manifest defines a Gateway"
assert_contains "$gw_manifest" "gatewayClassName: dwara" "Gateway references the dwara GatewayClass"
assert_contains "$gw_manifest" "protocol: HTTP" "Gateway listener declares protocol HTTP"
assert_contains "$gw_manifest" "port: 8080" "Gateway listener declares port 8080"

# 2) The HTTPRoute manifest: parentRef + PathPrefix rules +
#    Service backendRefs.
if [ -f "$ROUTE_MANIFEST" ]; then
  echo -e "${GREEN}PASS${NC}: HTTPRoute manifest present ($ROUTE_MANIFEST)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: HTTPRoute manifest missing ($ROUTE_MANIFEST)"
  FAIL=$((FAIL + 1))
fi
route_manifest=$(cat "$ROUTE_MANIFEST" 2>/dev/null || true)
assert_contains "$route_manifest" "kind: HTTPRoute" "manifest defines an HTTPRoute"
assert_contains "$route_manifest" "name: demo-gateway" "HTTPRoute parentRef targets demo-gateway"
assert_contains "$route_manifest" "PathPrefix" "HTTPRoute uses PathPrefix path matches"
assert_contains "$route_manifest" "value: /api" "HTTPRoute routes the /api prefix"
assert_contains "$route_manifest" "backendRefs" "HTTPRoute rules carry backendRefs"

# 3) The cluster-free CLI half: generate the conformance report.
if [ -x "$DWARA_CLI" ]; then
  echo "--- dwara-cli k8s conformance-report ---"
  report="$DEMO_DIR/data/conformance-report.yaml"
  rm -f "$report"
  "$DWARA_CLI" k8s conformance-report --output "$report"
  if [ -f "$report" ]; then
    echo -e "${GREEN}PASS${NC}: conformance report emitted ($report)"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC}: conformance report missing ($report)"
    FAIL=$((FAIL + 1))
  fi
  report_text=$(cat "$report" 2>/dev/null || true)
  assert_contains "$report_text" "GatewayClass" "conformance report covers GatewayClass"
  assert_contains "$report_text" "HTTPRoute" "conformance report covers HTTPRoute"
  assert_contains "$report_text" "PathPrefix" "conformance report covers PathPrefix matches"
else
  echo "SKIP: host dwara-cli not found at $DWARA_CLI"
  echo "      (build with: cargo build -p dwara-cli) — the"
  echo "      conformance-report generation is skipped; the manifest"
  echo "      assertions above still ran."
fi

echo ""
echo "NOTE: to run the full controller against a cluster, deploy"
echo "deploy/k8s/{namespace,rbac,gatewayclass,configmap,deployment}.yaml"
echo "(two containers per pod: dwara-k8s-controller writing the"
echo "generated config to a shared volume, and the dwara gateway"
echo "hot-reloading it), then kubectl apply -f fixtures/gateway.yaml and"
echo "fixtures/httproute.yaml. The upstream conformance suite:"
echo "go test ./conformance -ginkgo.focus=Core -gateway-class=dwara \\"
echo "  -controller-name=shristilabs.com/dwara"

print_summary
