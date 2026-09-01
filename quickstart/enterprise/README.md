# dwara enterprise quickstart

The enterprise edition's flagship topology -- the control plane /
data plane split (DW-066) -- on one docker network: a
`dwara-controller` broadcasting config generations to a fleet of two
`dwara-edge` data planes, each driving a gateway that proxies the demo
nginx upstream. One config file reconfigures the whole fleet.

This demo runs fully without a license: the CP/DP split is compiled in
by the `ent` build (`../Dockerfile.ent`) and does not require a
license claim. Only the Redis-backed features (distributed rate
limiting, config convergence) need license claims -- see
[Enterprise licensing](../../docs-site/guide/licensing.md) in the
docs site.

## Topology

```
                    ./dwara.yaml  (the single source of truth)
                          |
                    dwara-controller          compiles + broadcasts
                    gRPC :50051               generations
                    /       \
              edge-1         edge-2           receive, write local
                |               |             config, ack
           ./edge-1/       ./edge-2/          config caches (outage
                |               |             survival, see below)
           gateway-1       gateway-2          watch the file,
           :9443           :9444              hot-reload
                \               /
                 nginx upstream (../upstream)
```

Each data plane is two containers sharing one bind-mounted directory:
the edge writes the config it receives from the controller, and the
gateway's file watcher hot-reloads on every write. The edge and
gateway never talk to each other directly -- the config file IS the
interface, which is why an edge keeps working through anything short
of losing its cache.

## Run

From this directory (`quickstart/enterprise/`):

```sh
../gen-certs.sh                    # shared with the OSS quickstart
./vendor-licensing.sh              # vendor the private licensing-core
mkdir -p edge-1 edge-2
cp dwara.yaml edge-1/dwara.yaml    # seed both gateways' config
cp dwara.yaml edge-2/dwara.yaml
docker compose up                  # builds ../Dockerfile.ent
curl --cacert ../certs/server.crt https://localhost:9443/
curl --cacert ../certs/server.crt https://localhost:9444/
```

Both curls print the demo page: two independent data planes, one
config, TLS terminated at each gateway.

The seed copy matters: a gateway exits at startup without a valid
config, so `edge-N/dwara.yaml` must exist before `gateway-N` boots.
The seed also doubles as the outage cache (below).

The vendor step matters: the `ent` build links `licensing-core` from
the private ShristiLabs/licensing git repo. Local cargo builds
authenticate via your git credential helper; a Docker build has no
credentials, so `vendor-licensing.sh` clones the pinned revision on
the host into `./vendor/` and the Docker build resolves the dependency
from there. It requires read access to the repo (any ShristiLabs
member, or an entitled customer with a token in their git credential
helper) -- which is the honest boundary of an open-core product: the
enterprise edition's build needs enterprise entitlement.

Linux hosts need the edge dirs writable by the container user, like
the OSS quickstart's certs: `sudo chown -R 65532:65532 edge-1 edge-2`
(macOS/Docker Desktop needs nothing extra).

## Watch the fleet converge

Edit `dwara.yaml` -- the controller's source of truth -- and observe
every data plane pick up the change. A crisp, observable edit is
narrowing the catch-all route to `/api/.*`:

```sh
sed -i '' 's|value: /.\*|value: /api/.*|' dwara.yaml   # macOS
# sed -i 's|value: /.\*|value: /api/.*|' dwara.yaml    # Linux
sleep 5   # controller polls (2s default), compiles, broadcasts;
          # edges write; gateways hot-reload
curl -s --cacert ../certs/server.crt https://localhost:9443/ | head -1
# -> {"error":{...}} 404: BOTH gateways now route only /api/*
curl -s --cacert ../certs/server.crt https://localhost:9444/ | head -1
# -> the same 404 envelope on the second data plane
```

One file edited once; the whole fleet converged. Revert the edit and
both gateways serve the demo page again. `docker compose logs -f
controller edge-1 edge-2` shows the full loop: `cp_generation_published`
-> `edge_config_received` -> `edge_config_applied`.

Invalid edits are safe by construction: the controller compiles before
broadcasting (`cp_config_compile_failed` is logged and nothing is
pushed), and a gateway that fails to compile a received config keeps
serving its current generation -- the atomic-not-publish rollback from
the embedded mode, unchanged.

## Survive a controller outage

```sh
docker compose stop controller
curl --cacert ../certs/server.crt https://localhost:9443/   # still serving
docker compose start controller
```

Edges cache the last received generation and reconnect with bounded
backoff; the gateways never notice. The controller's next config
change reaches them after it returns.

## What is running

- `controller` -- `dwara-controller` from the ent image: watches
  `./dwara.yaml` (read-only mount), compiles changes through the same
  snapshot pipeline as an embedded gateway, publishes generations,
  broadcasts to edges over gRPC. Single controller here, so `--leader`
  is explicit; gRPC stays on the compose network.
- `edge-1` / `edge-2` -- `dwara-edge`: connect to the controller,
  receive generations, write them to `./edge-N/dwara.yaml`, ack. On
  controller outage they serve from cache and reconnect.
- `gateway-1` / `gateway-2` -- the plain `dwara` gateway binary from
  the same ent image, each watching the config file its edge
  maintains and hot-reloading on change. TLS-terminate on :8443
  (host ports 9443 and 9444, distinct from the OSS quickstart's 8443
  so both demos can run at once) with `../certs`.
- `upstream` -- `nginx:alpine` serving the static page in
  `../upstream`, shared with the OSS quickstart.

One image (`../Dockerfile.ent`, FROM scratch, ent feature) carries all
three binaries; each service picks one via `command:`. Binary size and
image knobs are documented in `../../packaging/README.md`.

## Teardown

```sh
docker compose down
```

The `edge-1/` and `edge-2/` dirs are gitignored runtime state; they can
be deleted, but re-seed them before the next `up`.
