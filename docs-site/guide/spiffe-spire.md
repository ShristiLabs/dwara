# SPIFFE/SPIRE workload identity

Dwara can integrate with a [SPIRE](https://spiffe.io/) deployment to
obtain zero-configuration mTLS identity for service-mesh traffic. The
gateway fetches X.509 SVIDs (SPIFFE Verifiable Identity Documents) and
trust bundles from the SPIRE Workload API, uses the SVID as its mTLS
certificate for upstream connections, and verifies peer SVIDs against
the trust bundle. The peer's SPIFFE ID (extracted from the URI SAN of
its verified certificate) becomes the identity for policy decisions.

## When to use this

Use SPIFFE/SPIRE when:

- You run a service mesh and want zero-configuration mTLS identity
  (no per-service certificate management).
- You want SPIFFE IDs as first-class consumer identities for policy
  decisions (route, authn, authz).
- You want the gateway to present its SVID as the client certificate
  when connecting to upstreams that require mTLS.

## Prerequisites

- A running SPIRE deployment with the SPIRE agent accessible via a
  Unix domain socket.
- The gateway's workload registered in SPIRE (the agent attests the
  gateway process).
- Enterprise edition (the gRPC Workload API transport is ent-gated).

## Configuration

The SPIRE Workload API socket path is configured in the mesh section
of the gateway config:

```yaml
mesh:
  spire:
    socket_path: /tmp/spire/agent.sock
    trust_domain: example.org
    refresh_interval_ms: 300000   # 5 minutes
```

The gateway connects to the SPIRE agent over the Unix socket, fetches
its X.509 SVID and the trust bundle, and uses them for:

- **Outbound mTLS** (upstream connections): presents the SVID as the
  client certificate, verifies the upstream's SVID against the trust
  bundle.
- **Inbound mTLS** (listener connections): presents the SVID as the
  server certificate, verifies the peer's SVID against the trust
  bundle (client auth required).

## SPIFFE ID extraction

The gateway extracts the peer's SPIFFE ID from the URI SAN of its
verified certificate. The SPIFFE ID (`spiffe://<trust-domain>/<path>`)
becomes the identity for policy decisions:

- Consumer identification: the SPIFFE ID can be used as the consumer
  identity in authn/authz policy.
- Route matching: routes can match on the peer's SPIFFE ID.

## SVID refresh

The gateway refreshes its SVID and trust bundle on a schedule
(configured by `refresh_interval_ms`). If the refresh fails, the
gateway continues using the cached SVID until it expires; a refresh
failure after expiry causes the gateway to fail closed (no mTLS
connections until a fresh SVID is obtained).

## Limitations

- Only X.509 SVIDs are supported (JWT-SVIDs are not yet supported).
- The SPIFFE-ID-aware certificate verifier (which extracts the peer's
  SPIFFE ID during the TLS handshake) is a separate enhancement; today
  the extraction happens after the TLS handshake completes.
- The server-side custom verifier (which validates peer SVIDs and
  extracts the SPIFFE ID in one step) is future work.

## See also

- [Post-quantum TLS](./post-quantum-tls.md) -- hybrid key exchange for
  quantum-resistant TLS.
- [HTTP/3 upstream](./h3-quic-upstream.md) -- QUIC-based upstream
  transport.
