# Authorization chain in detail

## The five levels and evaluation

```
consumer  >  route  >  service  >  listener  >  global (`authorization:` root)
```

1. Collect every level's rules. If **any** level denies this caller -
   `403`, done. (Deny-anywhere-wins.)
2. Otherwise take the **most specific level that has any rules** and apply
   only that level's allow logic. Less-specific levels are not consulted.
3. An empty/absent block at the governing level = transparent (allowed).

`dry_run: true` (per attachment) logs would-deny decisions -
`dwara::policy` warn events + `dwara_policy_dry_run_total{phase="authz"}`
- without blocking. Dry-run can only ever *observe*; it never makes
something allowed that the non-dry chain would deny.

## One block, complete rule set

```yaml
authorization:
  allowed_consumers: [mobile-app, partner-mtls]
  denied_consumers: [banned-bot]
  allowed_groups: [internal]
  denied_groups: [external]
  required_scopes: [read]        # JWT-authenticated callers only
  required_claims:               # exact stringified match; absent claim fails
    tenant: acme
  ip_acl:
    allow: [10.0.0.0/8, 127.0.0.1]
    deny: [10.6.0.0/16]          # deny checked FIRST, then allow, then default
    default: allow               # fallback for unmatched IPs
  geoip:                         # requires gateway-level `geoip.path` (.mmdb)
    denied_countries: [XX]
    allowed_countries: [US, DE]  # empty = anything not denied
    denied_asns: [64500]
  dry_run: false
```

Any subset of these keys is valid at any of the five levels; the same shape
applies inside `consumers[]` (consumer level), `routes[]`, `services[]`,
`listeners[]`, and the root `authorization`.

Semantics inside one block:

- IP gate first: `deny` match -> 403; else `allow` match -> pass the gate;
  else `default` decides.
- Then consumer identity rules; `denied_*` is checked before `allowed_*`.
- `0.0.0.0/0` / `::/0` are rejected in **allow** lists (validation error) -
  use `default: allow` instead; `/0` is fine in deny lists.
- IP is the **effective client IP** (trusted-proxies/XFF resolved).
- GeoIP predicates use MaxMind country/ASN from `geoip.path`.

## Scoping strategies that work

| Goal | Correct placement |
| --- | --- |
| Allow-list a specific API to two partners | route-level `allowed_consumers` |
| Block a tenant everywhere | global `denied_consumers` (deny-anywhere) |
| Office/VPN-only admin routes | route-level `ip_acl` (allow + `default: deny`) |
| Country blocks for compliance | global `geoip.denied_countries` |
| Soft-launch a policy | same block + `dry_run: true`, watch the counter, flip off |

## Response contract

- Deny: `403` with a generic body - deliberately no detail about *which*
  rule fired (no policy oracle for attackers). Correlate via `request_id`
  in logs.
- Authn failure: `401` + `WWW-Authenticate` from the authenticator that was
  tried (e.g. `Dwara-HMAC-SHA256 realm="dwara"`, `Bearer`).
- Dry-run never changes a response - only log lines and counters.

## Not-yet-wired surfaces (verify with `dwara-cli schema`)

Cedar policies (`authz.cedar`), OPA sidecar decisions (`authz.opa`), and
CEL `condition` fields are implemented as libraries but their config
blocks are not in the generated schema yet - routes cannot reference them
today. When they land they run **after** the built-in chain and can only
further restrict. Until then: the built-in rule set above + policy
`dry_run` + the anomaly signals (policies[].anomaly) are the wired tools.
