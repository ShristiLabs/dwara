# Service mesh mode (DW-107)

> Implements issue DW-107 (Enterprise, scaffolded behind the `mesh`
> cargo feature). Sources: `crates/dwara-core/src/mesh/mod.rs` (the
> domain module docs carry the full contract and dependency
> direction), `crates/dwara-core/src/mesh/sidecar.rs`
> (`SidecarController`, `SidecarConfig`, `SidecarMode`,
> `SidecarRedirectMode`), `crates/dwara-core/src/mesh/spiffe.rs`
> (`SpiffeClient`, `SpiffeConfig`, `SpiffeIdentity`, `SpiffeSvid`,
> `SpiffeTrustBundle`, `SvidRefreshResult`), the config schema in
> `crates/dwara-core/src/config/mesh.rs` (`MeshConfig`,
> `MeshSidecarConfig`, `MeshSpiffeConfig`, `MeshMode`), validation in
> `snapshot/mod.rs`. Tests: `crates/dwara-core/tests/mesh.rs` (sidecar
> and SPIFFE config parsing, `SpiffeIdentity` parse/validate/round-
> trip, snapshot validation: valid config, missing trust domain,
> missing socket, zero refresh interval, same/zero ports, unknown
> redirect mode, disabled-block skips checks, feature-gate and ent-gate
> warnings, the scaffold contract: `SidecarController` exposes
> listeners, `install_redirects` is a no-op, `fetch_svid` is stubbed,
> SVID expiry clamping). Operator docs:
> [configuration guide](../../docs-site/guide/configuration.md) and
> [enterprise guide](../../docs-site/guide/enterprise.md).

The service mesh mode runs dwara as a sidecar in each pod: an init
container configures iptables (or TPROXY) redirects so all inbound
traffic to the local application and all outbound traffic from the
local application to remote services flows through the sidecar. The
sidecar terminates mTLS on inbound connections (verifying the peer's
SPIFFE SVID, applying policies, then forwarding to the local app over
loopback) and wraps outbound connections in mTLS (applying policies,
then dialing the remote sidecar with the local workload's SVID).
Identity is provided by SPIFFE/SPIRE: each workload fetches X.509
SVIDs from the SPIRE Workload API over a Unix domain socket; the
SVID's URI SAN carries the SPIFFE ID
(`spiffe://<trust-domain>/<path>`), the authentication identity for
policy decisions.

## What is scaffolded today

The scaffold compiles and the config schema is always present so
configs round-trip without the feature. What is stubbed (documented
no-ops pending production hardening):

- **`SidecarController`**: records the configured listeners
  (`inbound_listener`, `outbound_listener`) but does NOT install
  iptables rules or open sockets (`install_redirects` logs
  `mesh_sidecar_redirect_stubbed` and returns). The init-container
  bootstrap would land here when production-ready.
- **`SpiffeClient`**: records the configured socket path and refresh
  interval but does NOT open the Unix socket or fetch real SVIDs
  (`fetch_svid`/`fetch_trust_bundle` return
  `SpiffeError::WorkloadApiStubbed`). The `spiffe` crate would be
  added as an optional dependency when production-ready.

The controller is the compile-time seam: it validates the config shape
and documents the runtime contract so production wiring lands here
without touching config, validation, or metrics.

## Inbound/outbound listener architecture

Two listeners, two directions, documented in `SidecarMode`:

- **Inbound** (`SidecarMode::Inbound`): intercepts traffic destined for
  the local application. The sidecar terminates the peer's mTLS,
  verifies the peer's SPIFFE SVID against the trust bundle, applies
  policies, then forwards plaintext to the local app over loopback.
- **Outbound** (`SidecarMode::Outbound`): intercepts traffic the local
  application sends to a remote service. The sidecar applies policies,
  wraps the request in mTLS using the local workload's SVID, then
  dials the remote service's sidecar.

`SidecarController::inbound_listener` and `outbound_listener` return
the `(mode, port, redirect_mode)` triple the runtime would bind. The
mTLS wiring lives in `security::tls`, which would consume the SVID
material produced here. The seam is kept as a hand-off so the
dependency direction stays downward -- mesh is a peer of security,
both above config.

## Redirect modes

Two redirect modes, documented in `SidecarRedirectMode`:

- **`iptables`** (the default): the init container installs iptables
  REDIRECT rules sending traffic to the listener ports. The sidecar
  recovers the original destination via `SO_ORIGINAL_DST` (the
  Istio/Linkerd convention).
- **`tproxy`**: TPROXY mode uses iptables TPROXY + `IP_TRANSPARENT` so
  the sidecar receives the original destination address (no port
  rewrite), knowing the intended upstream without `SO_ORIGINAL_DST`.

## SPIFFE identity

`SpiffeIdentity` is the trust domain plus the path forming the
workload identity (`spiffe://<trust-domain>/<path>`). `parse`
extracts them from a URI (rejecting wrong schemes and empty trust
domains); `new` normalizes the path to start with `/`. `SpiffeSvid`
carries the X.509 certificate chain (DER, leaf first), the private
key, and the expiry. `SpiffeTrustBundle` holds the X.509 CA
certificates (the SPIRE signing CAs) used as the peer-verification
root store. SVID refresh: the client refreshes at half the remaining
lifetime by default; `svid_refresh_interval` is the upper bound. A
refresh failure does not drop identity immediately -- the client keeps
serving the previous SVID until it expires
(`SvidRefreshResult::Error` records the failure for the
`dwara_spiffe_svid_refresh_total{result}` metric).

## Configuration

The top-level `gateway.mesh` block (`MeshConfig`):

```yaml
mesh:
  enabled: true
  mode: sidecar
  sidecar:
    inbound_port: 15006       # default 15006 (Istio convention)
    outbound_port: 15001      # default 15001 (Istio convention)
    redirect_mode: iptables   # or tproxy; default iptables
  spiffe:
    trust_domain: example.org
    workload_api_socket: /tmp/spire-agent/public/api.sock
    svid_refresh_interval_secs: 300   # default 300; must be > 0
```

`enabled` defaults to false: the mesh is inert even when the `mesh`
feature is compiled in, so operators can stage the config ahead of
activating the surface. `mode` is `sidecar` (v1 ships only sidecar).
The `sidecar` block is required when `mode` is `sidecar`; the `spiffe`
block is required when the mesh is enabled (mTLS identity is
mandatory).

Validation rules (in `snapshot/mod.rs`, gated on `enabled`):
`inbound_port`/`outbound_port` must each be > 0 and distinct;
`redirect_mode` must be `iptables` or `tproxy`; `trust_domain` and
`workload_api_socket` must be non-empty; `svid_refresh_interval_secs`
must be > 0. A disabled block skips all field-level checks.

## Feature gate and ent gate

The `mesh` cargo feature is flag-only (no new deps). When OFF, the
`mesh` block is accepted but inert: validation warns, and no sidecar
listeners or SPIFFE client are wired. When ON, the scaffold compiles;
the iptables/Workload API wiring lands when production-ready.

Ent-only: validation warns when mesh is configured without the `ent`
feature (mirrors the FIPS/credential-pool ent-gate pattern). An OSS
build with `mesh` alone compiles the scaffold, but the enterprise gate
is the licensing seam.

The [dataplane and proxy](./dataplane-proxy.md) page covers the request
path the sidecar intercepts; [TLS](./tls.md) covers `security::tls`.
