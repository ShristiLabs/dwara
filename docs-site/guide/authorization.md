# Authorization rules

Authorization decides whether an authenticated caller may use the
route it resolved: allow/deny lists over consumers and groups, JWT
scopes and claims, IP ACLs, and GeoIP gates -- all built in, no
external engine required. (Authentication -- proving who the caller
is -- is covered in [Security](./security); for delegating decisions
to Cedar or OPA instead, see
[Cedar and OPA authorization](./cedar-opa-authz).)

Authorization runs on every request that resolved a route; unrouted
404s never reach the rules.

## Attaching rules

An `authorization` block can appear at five levels, from most to
least specific: **consumer**, **route**, **service**, **listener**,
and **global** (the top-level `authorization` key). Consumer-level
rules apply once authentication has identified the consumer;
listener-level rules apply to every routed request the listener
accepts.

```yaml
authorization:                     # global: applies to every route
  denied_groups: [suspended]

listeners:
  - name: edge
    address: 0.0.0.0
    port: 8443
    authorization:                 # every routed request on this listener
      ip_acl:
        allow: [203.0.113.0/24, 198.51.100.7]
        default: deny              # closed mode: only listed IPs pass

consumers:
  - name: acme-prod
    credentials:
      - type: api_key
        key: ${ACME_PROD_KEY}
    groups: [partners]
    authorization:                 # applies to this consumer's requests
      ip_acl:
        deny: [10.9.0.0/16]        # the office NAT we retired

routes:
  - name: orders-api
    service: orders
    match:
      path: { type: prefix, value: /orders }
    action: { type: proxy }
    authorization:
      allowed_consumers: [acme-prod, acme-ci]
      denied_consumers: [acme-staging]
      required_scopes: [orders:read]
```

### Fields

| Field | Default | Description |
| --- | --- | --- |
| `allowed_consumers` | `[]` (any authenticated) | Consumers allowed to call the route. |
| `denied_consumers` | `[]` | Consumers explicitly rejected, even when otherwise allowed. |
| `allowed_groups` | `[]` (no constraint) | Consumer groups (from `consumers[].groups`) allowed through. |
| `denied_groups` | `[]` | Groups explicitly rejected, even when otherwise allowed. |
| `required_scopes` | `[]` | JWT scopes (from the token's `scope` claim) every request must carry. |
| `required_claims` | `{}` | Claims (name -> exact stringified value) every token must carry; a listed claim absent from the token fails. |
| `ip_acl` | none | Allow/deny gate on the effective client IP (see below). |
| `geoip` | none | Country/ASN gate on the effective client IP (see [GeoIP rules](./admin-api#geoip-rules)). |
| `dry_run` | `false` | Monitor mode: evaluate, log, and count this block's would-be denials without enforcing (see below). |

## Evaluation

**Within one block:** the IP gate runs first -- the `deny` list, then
the `allow` list, then the fallback -- and after it the consumer and
group rules, where `denied_*` is checked before `allowed_*` at the
same level.

**Across levels:** two frozen rules resolve the chain:

1. **A deny at any level wins.** A consumer-level deny beats a
   route-level allow and vice versa; denials are absolute.
2. Otherwise the **most specific level with rules governs**: that
   level's own allow/deny verdict is the answer, and less-specific
   levels are not consulted. A level with no (or an empty)
   `authorization` block is transparent.

## IP ACLs

`ip_acl` entries are IP addresses (`10.1.2.3`) or CIDRs
(`10.0.0.0/8`); anything else fails config validation. Evaluation
order: `deny` first (a match rejects with 403 regardless of the allow
list), then `allow`, then `default` for IPs matched by neither:

- `default: allow` (the default) -- the lists are exceptions; a
  deny list blocks specific ranges, everything else passes.
- `default: deny` -- closed mode; only allow-listed IPs pass.

Validation rejects an all-addresses entry (`0.0.0.0/0`, `::/0`) in
the `allow` list -- it filters nothing and is always a mistake; the
intended shape is an empty allow list with `default: allow`. A `/0`
in the `deny` list is meaningful (deny-all) and accepted.

ACLs (and GeoIP gates) evaluate the **effective client IP** -- the
`X-Forwarded-For`-resolved address behind the gateway's
`trusted_proxies`, the same address the built-in authz uses at every
level.

## JWT scopes and claims

On routes authenticated with JWT, `required_scopes` lists scopes from
the token's `scope` claim that every request must carry, and
`required_claims` pins exact values:

```yaml
    authorization:
      required_scopes: [orders:read, orders:write]
      required_claims:
        acme/tenant: "acme-prod"
```

A listed claim absent from the token fails the request; values are
compared as exact strings.

## Monitor mode (dry run)

Any attachment may set `dry_run: true`: its rules still evaluate, and
every would-be denial is logged (a `dwara::policy` warn event) and
counted (the `dwara_policy_dry_run_total{phase="authz"}` Prometheus
counter), but the request proceeds as if allowed. The flag is per
attachment and mutes only that block's own denials: the resolver
walks past a dry deny and stops only at a live one, so a live deny at
any other level still enforces. Monitor mode never makes enforcement
more permissive.

Requiring authentication on a route is an authentication-phase
check, not an authorization rule, and is never muted by `dry_run`.

## Responses

- A request that fails authentication where the route requires it
  answers `401` with the authenticator's challenge.
- A denied request (authenticated or IP-gated) answers `403` with
  the standard [error envelope](./observability#error-envelope).
  The body is generic on purpose: which list matched or which claim
  was absent is server-side information, logged, not told to the
  client.
