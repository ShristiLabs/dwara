# SPIFFE/SPIRE workload identity integration (SEC-16, #247)

> Implements issue SEC-16 (#247). Sources:
> `crates/dwara-core/src/mesh/spiffe.rs` (the SPIFFE domain model,
> `SpiffeIdentity`, `SpiffeSvid`, `SpiffeTrustBundle`, `SpiffeClient`,
> `WorkloadApiTransport`, `GrpcWorkloadApi`, `FakeWorkloadApi`,
> `SpiffeError`, `SvidRefreshResult`), `crates/dwara-core/src/security/tls.rs`
> (`build_spiffe_mtls_config`, `extract_spiffe_id_from_peer_cert`,
> `SpiffeMtlsConfig`, `SpiffeMtlsRole`). Operator docs:
> [docs-site SPIFFE guide](../../docs-site/guide/spiffe-spire.md).

## Overview

SPIFFE (Secure Production Identity Framework for Everyone) provides
zero-configuration mTLS identity for service-mesh deployments. The
SPIRE Workload API issues X.509 SVIDs (SPIFFE Verifiable Identity
Documents) and trust bundles to workloads; the gateway uses the SVID
as its mTLS client certificate (for upstream connections) or server
certificate (for inbound connections), and verifies peer SVIDs against
the trust bundle. The peer's SPIFFE ID (extracted from the URI SAN of
its verified certificate) becomes the auth identity for policy
decisions.

## Architecture

```
mesh::spiffe                    security::tls
+-----------------------+       +---------------------------+
| SpiffeIdentity        |       | build_spiffe_mtls_config  |
| SpiffeSvid            | -----> |   (Client/Server config)  |
| SpiffeTrustBundle     |       | extract_spiffe_id_from_   |
| SpiffeClient          |       |   peer_cert (URI SAN)     |
| WorkloadApiTransport  |       +---------------------------+
| GrpcWorkloadApi       |              |
|   (Unix socket,       |              v
|    tonic + prost)     |       authn / policy / consumer
+-----------------------+       identity
```

The dependency direction is preserved: `mesh` produces SVID material,
`security` consumes it. `mesh` does not import `security`; the TLS
integration lives in `security::tls`.

## Workload API transport

`GrpcWorkloadApi` connects to the SPIRE agent over a Unix domain socket
and fetches X.509 SVIDs and trust bundles via the SPIRE Workload API
gRPC protocol. The implementation uses hand-written prost wire messages
(`PbX509Svid`, `PbX509Bundle`, `PbX509SvidResponse`, etc.) matching the
SPIRE proto, with a custom prost codec (the same pattern as
`cp_dp/transport.rs`). No `protoc` or build-script dependency is
introduced.

- `fetch_x509_svid`: calls `FetchX509SVID`, parses the response into
  domain `SpiffeSvid`s (with DER chain splitting and SPIFFE ID
  validation).
- `fetch_x509_bundle`: calls `FetchX509Bundle`, returns the trust
  bundle.

The transport is gated behind the `ent` cargo feature (tonic + prost
are ent-gated). The `WorkloadApiTransport` trait keeps the transport
testable; `FakeWorkloadApi` provides deterministic test fixtures.

## TLS integration

`build_spiffe_mtls_config` builds a rustls `ClientConfig` (client
role) or `ServerConfig` (server role) from an SVID and trust bundle:

- The SVID's cert chain and private key are loaded as the presented
  certificate.
- The trust bundle is loaded as the peer-verification root store.
- Server role: uses `WebPkiClientVerifier` (client auth required).
- Client role: uses `with_client_auth_cert` + `with_root_certificates`.

Returns `SpiffeMtlsConfig::Client(ClientConfig)` or
`SpiffeMtlsConfig::Server(ServerConfig)`.

## SPIFFE ID extraction

`extract_spiffe_id_from_peer_cert` performs a DER walk to the
SubjectAltName extension (OID 2.5.29.17), finds the URI SAN entry
(tag 0x86 = context-specific [6]), and parses `spiffe://...` URIs into
`SpiffeIdentity`. Returns `None` for certificates without a valid
SPIFFE URI SAN. The walk is the same DER-substrate approach used by
`spki_of_leaf` (no X.509 parser dependency); the certificate is
already verified by rustls before this function is called.

## Configuration

The SPIRE Workload API socket path is configured per mesh deployment
(see the operator guide for details). The gateway reads the SVID and
trust bundle at startup and refreshes them on a schedule; the refresh
logic lives in `SpiffeClient` (the `SvidRefreshResult` tracks success
or failure).

## Limitations

- The SPIFFE-ID-aware certificate verifier (which would extract the
  peer's URI SAN SPIFFE ID during the TLS handshake and hand it to
  the auth layer as the identity) is a separate enhancement. Today
  `build_spiffe_mtls_config` uses rustls's default verifier (chain
  validation against the root store); `extract_spiffe_id_from_peer_cert`
  is called separately on the verified peer certificate.
- JWT-SVIDs are not yet supported; only X.509 SVIDs.
- The server-side custom verifier (which would validate peer SVIDs
  against the trust bundle AND extract the SPIFFE ID in one step) is
  future work.
