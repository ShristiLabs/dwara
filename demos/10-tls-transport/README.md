# Category 10: TLS & Transport

Demonstrates the dwara gateway's TLS and transport-layer capabilities:
TLS termination, multi-SNI certificate selection, SNI passthrough
(documented), HTTP/2 over TLS, and PROXY protocol (documented).

## What this demo covers

| Feature | Status | Test |
|---|---|---|
| TLS termination | Tested | `test-01-tls-terminate.sh` |
| Multi-SNI cert selection | Tested | `test-02-multi-sni.sh` |
| SNI passthrough | Documented (limitation) | `test-03-sni-passthrough.sh` |
| PROXY protocol | Documented (opt-in) | `test-04-proxy-protocol.sh` |
| HTTP/2 (h2 via ALPN) | Tested | `test-05-http2.sh` |
| HTTP/3 (QUIC) | Documented (special build) | - |
| Post-quantum TLS (X25519+ML-KEM) | Documented (special build) | - |
| ACME / Let's Encrypt | Documented (special build) | - |
| FIPS mode | Documented (special build) | - |

## Architecture

```
                    +-------------------+
  client ---> :8080 | edge-http         | plaintext HTTP
            \
             \---> :8443 | edge-https        | TLS terminate (multi-SNI + mTLS)
            \
             \---> :8444 | edge-passthrough  | TLS SNI passthrough (inert*)
            \
             \---> :2019 | admin             | mTLS-only admin API

  * passthrough is configured but inert: the echo upstream is HTTP only,
    so a live TLS handshake through :8444 cannot complete. See below.
```

Upstreams (HTTP only, on the shared docker network):

- `echo`   (dwara-demo/echo)   on :8080 — reflects the request as JSON
- `static` (dwara-demo/static) on :80   — serves demo HTML + JSON files

## Prerequisites

- Docker + Docker Compose
- The prebuilt images:
  - `dwara:demo`            (the gateway; built from `Dockerfile.scratch`)
  - `dwara-demo/echo`       (echo upstream)
  - `dwara-demo/static`     (static upstream)
- The shared certs at `../_shared/certs/`:
  - `server.crt` / `server.key` — self-signed, CN=localhost,
    SAN `DNS:localhost,IP:127.0.0.1`
  - `client-ca.crt` — CA for client certificates (mTLS)
  - `client.crt` / `client.key` — a client cert for the admin API

If `dwara:demo` is not tagged, `docker compose up` builds it from the
repo root via the `build:` fallback in `docker-compose.yml`.

## How to run

```sh
docker compose up -d
# wait a couple seconds for listeners to bind, then:
./test-01-tls-terminate.sh
./test-02-multi-sni.sh
./test-03-sni-passthrough.sh
./test-04-proxy-protocol.sh
./test-05-http2.sh
```

Stop with `docker compose down`.

## Expected results

- `test-01-tls-terminate.sh` — `curl --cacert ... https://localhost:8443/healthz`
  returns `200` with body `ok`.
- `test-02-multi-sni.sh` — `curl --resolve api.example.com:8443:127.0.0.1 ...`
  returns `200` (SNI=api.example.com selects the matching cert entry).
- `test-03-sni-passthrough.sh` — skips the live test and documents the
  HTTPS-upstream requirement.
- `test-04-proxy-protocol.sh` — verifies the plaintext HTTP listener
  works; documents that PROXY protocol needs an L4 LB in front.
- `test-05-http2.sh` — `curl --http2 ... https://localhost:8443/healthz`
  returns `200` and ALPN negotiates HTTP/2 (`http_version=2`).

## Notes on the HTTPS tests

All HTTPS curls use `--cacert ../_shared/certs/server.crt` because the
server certificate is self-signed. The cert is valid for `localhost` and
`127.0.0.1` only.

The multi-SNI test (`test-02-multi-sni.sh`) sends SNI=`api.example.com`,
which is **not** in the cert's SAN. curl's hostname verification would
therefore fail, so that test adds `-k` to skip hostname verification —
the goal is to verify SNI-based *cert selection*, not hostname matching.
With a real cert that carried `api.example.com` in its SAN, `--cacert`
alone would suffice.

## SNI passthrough (documented limitation)

The `edge-passthrough` listener (`:8444`) is configured with
`tls.mode: passthrough` and an `sni_routes` entry mapping
`api.example.com` to `echo-upstream`. In passthrough mode the gateway
peeks the TLS ClientHello SNI and splices the raw TLS stream
byte-for-byte to the matched upstream — it does **not** terminate TLS,
so the upstream must speak TLS itself.

The `dwara-demo/echo` upstream is HTTP only (plaintext on :8080), so a
live client TLS handshake through `:8444` cannot complete. The listener
is included to demonstrate the `sni_routes` config shape; the live test
is skipped. To exercise passthrough end to end, point an `sni_route` at
an HTTPS upstream (e.g. an nginx container with TLS enabled).

## Features that require special builds (documented, not tested here)

These capabilities need cargo feature flags / special builds and are
out of scope for this demo's runnable tests:

- **HTTP/3 (QUIC ingress, DW-088)** — `protocol: h3` listeners require
  the `h3` cargo feature on `dwara-bin` (`cargo build -p dwara-bin
  --features h3`). The default demo build does not include it.
- **Post-quantum TLS (DW-105)** — `tls.pq: true` prefers the
  X25519+ML-KEM hybrid key-exchange group, but only when the `pq` cargo
  feature is ON; otherwise it is accepted but inert. Experimental
  (rustls PQ API not yet stable).
- **ACME / Let's Encrypt (SEC-02)** — `tls.acme` automates cert
  issuance/renewal from an ACME directory. Terminate mode only; needs
  a reachable ACME CA and a public domain.
- **FIPS mode** — a FIPS-validated build of the crypto provider
  (aws-lc-rs). Incompatible with post-quantum kx (ML-KEM is not on the
  FIPS-validated list).

See the repo-root `config-reference.json` and the OSS quickstart
(`quickstart/oss/dwara.yaml`) for the full schema and feature flags.

## Admin API (mTLS)

The admin API binds `:2019` with TLS and requires a client certificate
chained to `client-ca.crt`. Query it with the client cert:

```sh
curl -s --cacert ../_shared/certs/server.crt \
  --cert ../_shared/certs/client.crt \
  --key  ../_shared/certs/client.key \
  https://localhost:2019/health
```
