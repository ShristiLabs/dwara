# dwara quickstarts

Runnable demos of the two dwara editions, one per directory:

| Directory | Edition | Topology |
|---|---|---|
| [oss/](./oss/README.md) | OSS (default build, Apache-2.0) | One gateway container TLS-terminating in front of the demo nginx upstream |
| [enterprise/](./enterprise/README.md) | Enterprise (`ent` build + license gate) | CP/DP split: a controller broadcasting config generations to a fleet of two edge/gateway data planes |

Both run on one docker network per edition and share the assets at this
directory's root:

- `gen-certs.sh` — writes the self-signed localhost TLS pair into
  `certs/` (gitignored). Run it once; both quickstarts mount `certs/`.
- `upstream/` — the static demo page the nginx container serves.

Host ports do not collide: the OSS quickstart publishes 8443, the
enterprise quickstart 9443/9444, so both can run at the same time.

The enterprise quickstart needs one extra preparation step
(`enterprise/vendor-licensing.sh`, which requires read access to the
private ShristiLabs/licensing repo) because the `ent` build links the
licensing-core dependency; see
[enterprise/README.md](./enterprise/README.md) for the full walkthrough.
