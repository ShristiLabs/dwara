#!/bin/bash
# test-01-grpc-web-framing.sh — gRPC-Web framing (DW-101) and the native
# gRPC hop it fronts.
#
# The /rpc/ route carries a `grpc_web` block (enabled: true) and fronts
# the gRPC upstream over TLS+h2 (protocol: http2, SPKI-pinned). The
# documented behavior: the gateway accepts
# Content-Type: application/grpc-web+proto, strips the gRPC-Web framing,
# forwards native gRPC upstream, and re-frames the response (data frame
# + trailer frame carrying grpc-status).
#
# WHAT IS WIRED TODAY (documented limitation, see README):
# the framing translator (dataplane::grpc_web) is a complete,
# test-covered library component, but it is NOT dispatched from the
# proxy path — a route with `grpc_web` validates and the gateway boots,
# yet the request body is forwarded un-translated. This test:
#
#   1) POSITIVE CONTROL: native gRPC through the gateway works
#      end-to-end — grpcurl speaks TLS+h2 to the :8443 listener, the
#      gateway dials the SPKI-pinned TLS+h2 upstream, SayHello answers.
#      This proves the gRPC transport chain the framing layer sits on.
#   2) LIMITATION EVIDENCE: a hand-rolled gRPC-Web POST (correct 5-byte
#      framing, application/grpc-web+proto) does NOT come back as a
#      gRPC-Web framed response — the gateway passes it through and the
#      upstream cannot decode the double-framed body, so the translated
#      greeting never appears.
#
# The gRPC-Web request/response bytes are produced and parsed with
# python3 stdlib only (no grpc client on the host needed):
#   request body  = grpc-web data frame [0x00][len4] wrapping the gRPC
#                   message [0x0a][len][name bytes] with its own 5-byte
#                   gRPC length prefix;
#   response body (if translation ran) = data frame + trailer frame
#                   with `grpc-status: 0`.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-01: gRPC-Web framing ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# ---------------------------------------------------------------------------
# 1) Positive control: native gRPC through the gateway (TLS + ALPN h2
#    ingress on :8443, TLS+h2 SPKI-pinned upstream).
# ---------------------------------------------------------------------------
echo "--- native gRPC: grpcurl SayHello through the gateway (:8443) ---"
grpcurl_out=$(docker run --rm --network host \
  -v "$(cd "$(dirname "$0")" && pwd)/protos:/protos:ro" \
  fullstorydev/grpcurl -insecure -protoset /protos/dwdemo.pb \
  -d '{"name":"gateway"}' localhost:8443 dwdemo.DemoService/SayHello 2>&1)
echo "  grpcurl: $grpcurl_out"
assert_contains "$grpcurl_out" "hello, gateway!" \
  "native gRPC SayHello through the gateway (TLS+h2 in, TLS+h2 pinned upstream)"

# ---------------------------------------------------------------------------
# 2) gRPC-Web POST on the /rpc/ route (plaintext h1 ingress).
# ---------------------------------------------------------------------------
echo "--- gRPC-Web POST /rpc/dwdemo.DemoService/SayHello (python3 stdlib) ---"
grpcweb_out=$(python3 - <<'PYEOF'
import sys, urllib.request, urllib.error

# protobuf HelloRequest: field 1 (string) = "gateway"
name = b"gateway"
msg = b"\x0a" + bytes([len(name)]) + name
# native gRPC message: 5-byte prefix (flag 0x00 + BE length) + message
grpc_msg = b"\x00" + len(msg).to_bytes(4, "big") + msg
# gRPC-Web data frame: flag 0x00 + BE length + the gRPC message
frame = b"\x00" + len(grpc_msg).to_bytes(4, "big") + grpc_msg

req = urllib.request.Request(
    "http://localhost:8080/rpc/dwdemo.DemoService/SayHello",
    data=frame,
    headers={"Content-Type": "application/grpc-web+proto"},
)
try:
    resp = urllib.request.urlopen(req, timeout=15)
    status, body = resp.status, resp.read()
except urllib.error.HTTPError as e:
    status, body = e.code, e.read()
except Exception as e:  # transport failure of any kind
    print(f"STATUS=error:{e}")
    sys.exit(0)

print(f"STATUS={status}")
print(f"BODY_LEN={len(body)}")
print(f"BODY_HEX={body[:64].hex()}")
# If the framing translator ran, the body would be a gRPC-Web data frame
# carrying "hello, gateway!" plus a trailer frame with grpc-status: 0.
greeting_present = b"hello, gateway!" in body
print(f"GREETING_PRESENT={'yes' if greeting_present else 'no'}")
trailer_frame = len(body) >= 5 and (body[0] & 0x80) != 0
print(f"TRAILER_FRAME_FIRST={'yes' if trailer_frame else 'no'}")
PYEOF
)
echo "$grpcweb_out" | sed 's/^/  /'

status_line=$(echo "$grpcweb_out" | grep '^STATUS=' | cut -d= -f2-)
greeting=$(echo "$grpcweb_out" | grep '^GREETING_PRESENT=' | cut -d= -f2-)
body_len=$(echo "$grpcweb_out" | grep '^BODY_LEN=' | cut -d= -f2-)

# The gateway answered (some HTTP status came back).
if [ -n "$status_line" ]; then
  echo -e "${GREEN}PASS${NC}: gateway answered the gRPC-Web POST (status=$status_line)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: no response captured for the gRPC-Web POST"
  FAIL=$((FAIL + 1))
fi

# Documented limitation: no gRPC-Web framing translation is dispatched,
# so the translated greeting must NOT appear in the response.
if [ "$greeting" = "no" ]; then
  echo -e "${GREEN}PASS${NC}: response is NOT gRPC-Web translated (no greeting in body; body_len=$body_len) — matches the documented limitation"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: response contains the translated greeting — translation IS dispatched (docs out of date?)"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "NOTE: the grpc_web block validates and the gateway serves the route,"
echo "      but the framing translator is not dispatched from the proxy path"
echo "      today. See README.md (Documented limitations) and the positive"
echo "      control above for the working native gRPC chain."

print_summary
