# dwara OSS quickstart

One command, TLS proxying a demo upstream (DW-026 done-when). This is
the default edition: a single self-contained gateway binary.

For the enterprise edition's CP/DP split topology (controller + edge
fleet, one config file driving every data plane), see
[../enterprise/](../enterprise/README.md).

## Run

From this directory (`quickstart/oss/`):

```sh
../gen-certs.sh          # self-signed localhost certificate into ../certs
docker compose up        # builds the gateway image (../../Dockerfile.scratch)
curl --cacert ../certs/server.crt https://localhost:8443/
```

Linux hosts need `../certs/` readable by the container user: if
`gen-certs.sh` was not run with sudo, also run
`sudo chown -R 65532:65532 ../certs`
(macOS/Docker Desktop needs nothing extra).

The curl prints the demo page from the nginx upstream, having negotiated
TLS with the gateway, which routed `/` to the upstream and proxied the
response back. Any HTTP client trusting `certs/server.crt` works the same.

## What is running

- `dwara` — the gateway image built from `../../Dockerfile.scratch`: a
  static musl binary on `FROM scratch` (no shell, no libc, no CA bundle;
  upstream TLS roots are compiled in via webpki-roots). It terminates
  TLS on :8443 with `../certs/server.{crt,key}` per `dwara.yaml`.
- `upstream` — `nginx:alpine` serving the static page in `../upstream`.

The cert material and demo upstream are shared with the enterprise
quickstart (both live at the `quickstart/` root), so running both
editions needs one `gen-certs.sh` and one set of certs.

Switch to `../../Dockerfile.distroless` in `docker-compose.yml` for the
variant with a baked-in nonroot UID. Binary size and image knobs are
documented in `../../packaging/README.md`.

## Teardown

```sh
docker compose down
```
