#!/usr/bin/env bash
# dwara-doctor.sh - one-shot health snapshot of a running Dwara gateway
# over its admin API (mTLS). Read-only: GET endpoints only.
#
# Usage:
#   ./dwara-doctor.sh --admin https://127.0.0.1:2019 \
#                     --cert client.crt --key client.key --cacert server.crt
#
# Minimal deps: curl, awk. Exit 0 = all checks pass, 1 = any FAIL.
set -uo pipefail

ADMIN="http://127.0.0.1:2019"
CERT_ARGS=()
fail=0

while (( $# )); do
  case "$1" in
    --admin)  ADMIN="$2"; shift 2 ;;
    --cert)   CERT_ARGS+=(--cert "$2");  shift 2 ;;
    --key)    CERT_ARGS+=(--key "$2");   shift 2 ;;
    --cacert) CERT_ARGS+=(--cacert "$2"); shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

api() { curl -fsS "${CERT_ARGS[@]}" "$ADMIN$1"; }
api_hdr() { curl -fsS -D - -o /dev/null "${CERT_ARGS[@]}" "$ADMIN$1"; }

# 1. Reachability + readiness
if body="$(api /health)"; then
  echo "PASS  /health reachable"
  grep -q '"ready"[[:space:]]*:[[:space:]]*true' <<<"$body" \
    && echo "PASS  gateway ready" \
    || { echo "WARN  'ready' not true in /health: ${body:0:160}"; }
else
  echo "FAIL  /health unreachable (admin mTLS certs? admin block enabled?)"
  exit 1
fi

# 2. Runtime info: version, generation, uptime
if info="$(api /runtime_info)"; then
  echo "PASS  /runtime_info: $(tr -d '\n' <<<"$info" | cut -c1-200)"
else
  echo "FAIL  /runtime_info"; fail=1
fi

# 3. Config generation header (config plane responsive)
if gen="$(api_hdr /config | tr -d '\r' | awk 'tolower($1)=="x-dwara-config-generation:"{print $2}')"; then
  [[ -n "$gen" ]] && echo "PASS  config generation: $gen" \
                 || { echo "WARN  generation header absent"; }
else
  echo "FAIL  GET /config"; fail=1
fi

# 4. Stats: breakers open? active requests? config_generation moving?
if stats="$(api /stats)"; then
  echo "PASS  /stats"
  open_breakers="$(grep -o '"state"[[:space:]]*:[[:space:]]*1' <<<"$stats" | wc -l | tr -d ' ')"
  if (( open_breakers > 0 )); then
    echo "WARN  $open_breakers breaker(s) OPEN (state=1) in /stats"
  else
    echo "PASS  no open breakers reported"
  fi
else
  # /stats shape can vary by version; treat as warning, not failure
  echo "WARN  /stats not parseable (version-dependent shape)"
fi

# 5. Prometheus spot-check (works even without admin: reserved path)
echo "---"
echo "Next: curl ${ADMIN%:*}:<data-port>/metrics | grep -E 'config_generation|breaker_state|active_requests'"

(( fail )) && { echo "DOCTOR: FAILURES PRESENT"; exit 1; }
echo "DOCTOR: all checks passed"
