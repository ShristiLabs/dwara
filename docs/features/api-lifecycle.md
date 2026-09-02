# API lifecycle management (DW-110)

> Implements issue DW-110 (three sub-concerns, hand-rolled over
> existing substrates, no new dependencies). Sources:
> `crates/dwara-core/src/lifecycle/mod.rs` (the domain module docs
> carry the full contract and dependency direction),
> `crates/dwara-core/src/lifecycle/portal.rs` (`DevPortal`,
> `DevPortalConfig`, `DevPortalSpec`, `DevPortalSpecSource`,
> `LoadedSpec`, the HTML renderer),
> `crates/dwara-core/src/lifecycle/profiles.rs` (`EnvProfile`,
> `ProfileOverlay`, `AppliedProfile`, `apply_profile`, `merge_yaml`),
> `crates/dwara-core/src/lifecycle/journey.rs` (`Journey`,
> `JourneyStep`, `JourneyStepResult`, `JourneyRecorder`,
> `JourneyConfig`, `journey_dimension`), the config schema in
> `crates/dwara-core/src/config/mod.rs` (`LifecycleConfig`,
> `LifecyclePortalConfig`, `LifecycleProfilesConfig`,
> `LifecycleJourneyConfig`). Tests: the lifecycle integration suite
> (portal build/render with file and URL specs, profile selection via
> `DWARA_PROFILE`, the merge semantics, journey recording and
> ring-buffer eviction, the feature-gate inert-without-feature
> behavior). Operator docs:
> [API versioning guide](../../docs-site/guide/api-versioning.md) and
> [configuration guide](../../docs-site/guide/configuration.md).

Three concerns that span the lifetime of an API surface the gateway
fronts, all hand-rolled over existing substrates (no new
dependencies): the developer portal, environment profiles, and the
journey recorder. The module is feature-gated behind the
`api_lifecycle` cargo feature; without it, the module is not compiled
and the top-level `lifecycle` config block is accepted but inert
(validation warns, mirroring the `a2a`/`graphql` pattern).

`lifecycle` depends on `config`, `observability`, and `analytics` (the
raw table the journey recorder stores into). It never imports
`dataplane` -- the dataplane calls into the journey recorder and the
portal renderer, never the reverse.

## Developer portal

A read-only static HTML page auto-generated from the configured
OpenAPI spec sources. The portal aggregates the existing OpenAPI specs
(file paths or upstream `/openapi.json` endpoints) into a single
listing of the APIs, their versions, and links to the specs. It is
served at a configured reserved path (before route resolution, like
`/healthz`). The portal is read-only (no CRUD): it renders the specs
the operator already configured.

`DevPortal::build` loads file specs at build time (read + parse as
JSON, extract `info.title` and `info.version`); URL specs are deferred
to render time (the upstream may be down at publish time but up at
render time). A file that cannot be read or parsed is recorded as an
error entry -- the portal still renders, listing the spec as
unavailable. The portal is best-effort, never a hard failure.
`render_html` fetches URL specs at render time (a minimal blocking
HTTP/1.1 client via `TcpStream`; https URL specs are listed with a
note). The HTML is hand-rolled with HTML-escaping.

```yaml
lifecycle:
  portal:
    enabled: true
    path: /portal            # default /portal; reserved HTTP path
    specs:
      - file: /etc/dwara/openapi/orders.json
        name: Orders API     # optional; derived from info.title
      - url: http://orders-svc/openapi.json
```

Each spec source is either a `file` path or a `url`; validation
rejects a spec with neither or both. `enabled` defaults to false.

## Environment profiles

Dev/staging/prod config overlays. A `ProfileOverlay` carries a base
config (as a YAML string) plus per-profile config patches (each patch
is a partial `Gateway` serialized as YAML). `apply_profile` merges the
selected profile's patch onto the base config. The profile is selected
via the `DWARA_PROFILE` env var (one of `dev`, `staging`, `prod`;
case-insensitive). When unset, no overlay is applied (the base config
is used as-is).

The merge is a shallow JSON merge: the base and patch are each parsed
into JSON values, the patch's top-level keys overwrite the base's, and
the result is serialized back to YAML. Collection fields (listeners,
routes, upstreams) in the patch REPLACE the base's collections (not
append) -- a profile is a full topology overlay, not a delta. This is
deliberate: a profile is a complete environment definition, so the
operator sees the full topology in each patch without mentally
subtracting the base. `EnvProfile::from_env_var` parses the env var
(case-insensitive); an unrecognized value is a no-op, not an error.
When the selected profile has no patch, the base is returned
unchanged.

```yaml
lifecycle:
  profiles:
    base_config: |
      listeners: [...]
      routes: [...]
      upstreams: [...]
    profile_overrides:
      dev: |
        routes:
          - name: api
            action: { type: proxy, upstream: dev-api }
      prod: |
        routes:
          - name: api
            action: { type: proxy, upstream: prod-api }
            rate_limit: { rps: 10000 }
```

## Journey recorder

Records the request flow through the gateway as a JSON document for
debugging. A `Journey` is the ordered sequence of phases a request
passed through (route match, authn, authz, transforms, upstream pick,
response), each captured as a `JourneyStep` (phase, duration, result,
detail). The recorder is a bounded in-memory ring buffer (capped at
`JOURNEY_BUFFER_CAP` = 4096) for live debugging plus a JSON serializer
that stores the journey via the existing analytics raw table's custom
dimensions column -- no schema migration, no new table, no new writer
channel. `journey_dimension` builds the `(key, value)` pair to push
onto `AccessRecord::custom` as a `_journey` key (the leading
underscore avoids collisions with operator-declared dimensions).

The journey's durable retention is the raw table's retention (the
`analytics.retention` config, default 24h). The `retention_hours`
config field is an advisory cap for the in-memory buffer.
`JourneyRecorder::record` never blocks: the buffer is a short mutex
over a capped `VecDeque`; when full, the oldest entry is evicted.
`snapshot` returns journeys newest-first, dropping stale entries.

```yaml
lifecycle:
  journey:
    enabled: true
    retention_hours: 24    # default 24; must be > 0; in-memory buffer cap
```

## Integration with API versioning

The portal aggregates the OpenAPI specs the operator already
configured (the same specs the DW-048 versioning system routes on).
The journey recorder traces the request through the versioned route
match, so a debugging session can see which API version a request hit
and how long each phase took. The profiles overlay can swap the entire
route topology per environment. The three sub-concerns compose: the
portal shows what APIs exist, the profiles select which topology is
active, and the journey recorder traces how a request flows through
it. The [versioning](./versioning.md) and [analytics](./analytics.md)
pages cover the DW-048 system and the raw table.
