# Getting started

Dwara is a reverse-proxy API gateway configured from a single YAML file.
This page gets a gateway running locally in under a minute; see
[Installation](./installation) for binaries/Docker/build-from-source, and
[Deployment](./deployment) for a full TLS demo.

## Requirements

- A Dwara binary (see [Installation](./installation)), or Rust 1.94+ if
  building from source.

## 1. Start something to proxy to

Any HTTP server will do. For a quick demo:

```sh
python3 -m http.server 9000
```

## 2. Point Dwara at a config

The repository ships a sample config that forwards everything under `/v1`
to `127.0.0.1:9000`. If you're running from a source checkout:

```sh
DWARA_CONFIG=crates/dwara-bin/dwara.yaml cargo run -p dwara-bin
```

If you're running a released binary, point `DWARA_CONFIG` (or the default
`./dwara.yaml`) at a config like:

```yaml
listeners:
  - name: http
    bind: "0.0.0.0:8080"

services:
  - name: demo
    upstream:
      endpoints:
        - url: "http://127.0.0.1:9000"

routes:
  - path_prefix: "/v1"
    service: demo
    listeners: [http]
```

## 3. Send a request

```sh
curl http://127.0.0.1:8080/v1/
```

The request is streamed to the backend unbuffered, and the response
streams back the same way — Dwara does not buffer request or response
bodies by default. A path with no matching route returns `404`; a dead
backend returns `502` (or `504` on connect timeout). Stop the gateway
with `Ctrl-C` — it drains in-flight requests before exiting (see
[Operations](./operations)).

## What just happened

- Dwara parsed and validated `dwara.yaml` at startup. An invalid config
  makes the process exit with code 1, printing **every** validation issue
  at once (not just the first).
- It bound the `http` listener and started routing traffic per the
  `routes` list.
- The proxy is streaming: nothing about the request or response is
  buffered in memory beyond what the OS socket buffers require.

## Next steps

- [Configuration](./configuration) — the shape of the YAML config and the
  concepts (Listener/Route/Service/Upstream/...) it's built from.
- [Deployment](./deployment) — TLS termination, Docker images, systemd.
- [Architecture overview](../architecture/overview) — how a request flows
  through the gateway, and how hot reload works.
