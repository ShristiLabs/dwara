# Service mesh

Dwara can run as a [service mesh](https://en.wikipedia.org/wiki/Service_mesh)
sidecar, co-located with each service instance, providing identity, mTLS, and
policy for east-west traffic between services in the same way it provides
them for north-south traffic at the edge. In sidecar mode the gateway is the
network for the services it fronts: every call between meshed services flows
through a pair of gateways (outbound from the caller, inbound at the
callee), each enforcing policy and presenting a verifiable identity.

## When to use this

Use sidecar mode when east-west traffic between your services needs the same
authn, authz, mTLS, and observability the gateway gives north-south traffic,
and you want it without a separate control plane or a different proxy. The
same binary, config grammar, and policy chain that run at the edge run
beside each service -- one tool to learn, one config to author. For a
single-service deployment or a cluster where east-west trust is handled
elsewhere, the edge gateway alone is enough; the mesh block is for the
multi-service case.

## Configuration

Add a `mesh` block under `gateway`. It is optional and off by default.

```yaml
gateway:
  mesh:
    mode: sidecar
    identity:
      spiffe:
        trust_domain: example.com
        workload_id: ns/api/svc/api-server
        cert:
          spiffe_bundle_endpoint: https://spire.example.com:8443
          rotation_interval: 1h
    mtls:
      required: true
      client_verification: spiffe
      trusted_ca_file: /etc/dwara/spiffe-bundle.pem
    policy:
      enforce: true
      rules: /etc/dwara/mesh-policy.yaml
```

## SPIFFE identity

Each sidecar presents a [SPIFFE](https://spiffe.io/) (a framework for
cryptographic workload identity, independent of network location) identity
to its peers: a SPIFFE Verifiable Identity Document (SVID) issued by a
trust domain, naming the workload it represents. The `workload_id` is the
SPIFFE ID this sidecar presents; the `trust_domain` is the SPIFFE trust
domain it belongs to.

SVIDs are fetched from a SPIFFE Bundle Endpoint (typically a
[SPIRE](https://github.com/spiffe/spire) server) named by
`spiffe_bundle_endpoint`, and rotated on `rotation_interval`. The gateway
never holds a long-lived key -- it rotates the SVID before it expires, so a
compromised sidecar's identity is short-lived and revocable. The trust bundle
(`trusted_ca_file`) is the SPIFFE bundle the gateway uses to verify peer
SVIDs; it is refreshed from the same endpoint.

## mTLS

With `mtls.required: true`, every outbound connection the sidecar opens and
every inbound connection it accepts must complete mTLS using the SVID. A peer
that does not present a valid SVID from the configured trust domain is
rejected at the TLS handshake -- the request never reaches the service.

`client_verification: spiffe` tells the gateway to verify the peer's SVID
against the SPIFFE bundle and to extract the peer's SPIFFE ID for policy
evaluation. This is stronger than cert-chain verification alone: the gateway
checks not just that the cert is valid, but that it names the workload it
claims to be, under the trust domain.

## Policy

The `policy` block carries the east-west authorization rules, separate from
the route-level [authorization](./authorization) that governs north-south
clients. `rules` points at a policy file that maps source SPIFFE IDs to
destination routes and verdicts -- "workload `ns/checkout/svc/checkout` may
call `ns/payment/svc/payment` on `POST /charge`, and nothing else." With
`enforce: true`, a call that does not match an allow rule is denied with
`403` at the sidecar; with `enforce: false`, the decision is logged but the
call proceeds -- useful for shadow-rolling out mesh policy.

## Sidecar vs edge

The mesh block does not replace the edge gateway; it extends the same gateway
binary into the east-west path. A typical deployment runs one edge gateway
per cluster entry point (north-south) and one sidecar per service instance
(east-west), all reading from the same config pipeline. The edge gateway's
config carries the public-facing routes; each sidecar's config carries the
routes for its co-located service plus the `mesh` block. Both share the
[config convergence](./config-convergence) pipeline, so a policy change
rolls to edge and sidecars in one publish.

## Observability

Mesh decisions surface in [`/metrics`](./observability) as
`dwara_mesh_mtls_total{sidecar,outcome}` with outcomes `handshake_ok`,
`handshake_failed`, and `svid_rotated`, and `dwara_mesh_policy_total{src,dst,verdict}`
for east-west authorization. The SPIFFE IDs of caller and callee are added
to the access log, so east-west traffic is attributable to workloads, not
just IP addresses -- the foundation of zero-trust service-to-service calls.
