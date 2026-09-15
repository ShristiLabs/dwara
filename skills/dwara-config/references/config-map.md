# Config map: every top-level key

Verified against the generated schema (`dwara-cli schema`). One-line purpose
plus where to read more. The runnable tour of nearly all of these is
`quickstart/oss/dwara.yaml` in the repo.

## Entities

| Key | Purpose |
| --- | --- |
| `version` | Config schema version; `dwara-cli migrate` bumps it. |
| `listeners[]` | Entry points: `name`, `address`, `port`, `protocol` (`http`, `https`, plus `h3`/`tcp`/`udp` surfaces — all compiled into every build), `tls` (terminate: `cert_file`/`key_file`/`client_ca_file`, multi-SNI `certificates[]`; passthrough mode), `proxy_protocol`, `alt_svc` (string, e.g. `h3=":8444"; ma=86400`), per-listener `authorization` + `policies`. |
| `routes[]` | `name`, `service`, `match` (`path` exact/prefix/regex, `methods`, `host`, `headers`, `query`, `cookies`, `accept`), `action` (`proxy` + `rewrite`, `redirect`, `respond`, `mock`, `ai`), plus route-level: `auth_required`, `authorization`, `transforms`, `security_headers`, `cors`, `compression`, `cache`, `limits`, `waf`, `request_validation`, `masking`, `deprecation`, `slo`, `mirror`, `fault_injection`, `websocket`, `priority`, `maintenance`, `policies`, `plugins`. |
| `services[]` | `name` + one of: `upstream` (+ `base_path`, `version`, `policies`), or `split` (`targets[]` weighted + optional `canary_analysis`), plus optional `sticky` (`cookie`, `ttl_s`). |
| `upstreams[]` | Endpoint pools: `load_balancer` (`round_robin`, `least_requests`, `random`, `ip_hash`, `maglev`, `peak_ewma`), `protocol` (`http1`, `http2` = h2 over TLS, `https`, `h2c`, `h3`), `endpoints[]` (`address`, `port`, `weight`), `health` (passive/outlier), `active_health`, `retries` (+ `hedge`), `timeouts`, `breaker`, `connection_cap`, `max_pending`, `slow_start_ms`, `dns_discovery`, `peak_ewma`, `hash_on`, `oauth2_client_credentials`, upstream `mtls`, `cert_pinning`, `trusted_ca_file`/`use_system_roots` (upstream TLS trust), `pq`. |
| `consumers[]` | `name`, `type` (`user`, `agent`), `groups[]`, `credentials[]` (`api_key`, `jwt`, `hmac`, `mtls`), `quotas` (`daily_requests`, `monthly_requests`, `dry_run`), `priority`, `token_budget`, `ai_logging`, `tool_allowlist`, `policies`. |
| `policies[]` | Named reusable bundles: `rate_limit` (single window) or `rate_limits[]` (stacked, selector-based), `timeouts`, `token_budget`, `anomaly`, `adaptive`, `dry_run`. |
| `global_policies` | Policy names applied to every request incl. unrouted 404s (except reserved `/healthz`, `/readyz`, `/metrics`). |

## Gateway-level blocks

| Key | Purpose |
| --- | --- |
| `authorization` | Global authorization (least specific link of the chain): `ip_acl`, and the same rule set as route-level. |
| `default_security_headers` | Defaults stamped on responses; routes can override. |
| `waf` | Global CRS-style rule set (severity/phase/targets/transformations/`paranoia_level`/`anomaly_threshold`/`exclude_rule_ids`/`exclude_tags`). Route-level `waf` is the heuristic sqli/xss/path_traversal filter. |
| `jwt_providers[]` | JWKS token verification: `jwks_url`, `issuer`, `audience`, `consumer`, `algorithms`, `leeway_secs`, `refresh_secs`, `retired_key_grace_secs`. |
| `oidc_providers[]` | RFC 7662 token introspection: `issuer`, `client_id`, `client_secret`, `consumer`, `scopes`, `fail_open`, `introspection_cache_ttl_s`. |
| `hmac_auth` | HMAC request-signing verification: `max_clock_skew_secs`. |
| `mtls_consumer_mapping` | Authoritative client-cert -> consumer mapping (`enabled`, `subject_cn_mapping`, fingerprint-based `consumers[]`). |
| `mtls_forward_headers` | Forward cert metadata to upstreams (`enabled`, `prefix`). |
| `admin` | mTLS admin API: `bind` (default `127.0.0.1:2019`), `tls` (all three files mandatory), optional `rbac`, `api_tokens`, `audit`. |
| `analytics` | Embedded analytics SQLite: `path`, `flush_ms`, `dimensions[]` (header/claim-sourced), `retention` (per-granularity ms), `live_sketches`, `insights` (forecast/anomaly), `exports` (directory/formats/window), `replay_capture`. |
| `analytics_stream` | NDJSON firehose of access records (`sink.type: webhook` today; Kafka is documented as planned). |
| `geoip` | `path` to a MaxMind `.mmdb` for country/ASN authorization predicates. |
| `webhooks[]` | Event delivery: breaker/endpoint-ejection/config-publish events (`url`, `events`, `headers`, retry/backoff). |
| `admission_queue` | Bounded priority-aware queue for over-cap requests (requires `max_concurrent_requests`). |
| `ai` | The AI gateway block - see the dwara-ai-gateway skill (`providers`, `models`, `pricing`, `routing_policies`, `governance`, `guardrails`, `logging`, `semantic_cache`, `experiments`, `mcp`, `a2a`). |
| `plugins` / `plugin_registry` | proxy-wasm + native plugin loading and registry - see the dwara-plugins skill. |
| `filter_chain` | Order/dry-run of the built-in filter chain - see the dwara-plugins skill. |
| `mesh` | Service-mesh/SPIFFE configuration (enterprise feature; runtime scaffolded). |
| `lifecycle` | Developer-portal / API lifecycle surfaces (scaffolded: accepted but inert today). |
| `trusted_proxies` | IPs/CIDRs whose `X-Forwarded-For` is honored. |
| `max_concurrent_requests` | Gateway-wide concurrency cap. |
| `load_shed_dry_run` | Log-and-admit instead of shedding over cap. |
| `ssrf_filter` | SSRF protections for gateway-initiated requests. |
| `redis_rate_limiter` / `redis_quotas` / `redis_cache` / `config_convergence` | Enterprise (build `--features ent` + license): shared Redis state. |
| `license` | Enterprise license wiring. |

## Not yet in the schema (verify before promising)

As of this skill's version, these documented-or-planned surfaces have **no
config block** in the generated schema: Cedar/OPA authorization, CEL
expression wiring (`condition` fields), API aggregation, OpenAPI response
validation. Built-in authorization rules and the heuristic WAF are the wired
paths today. Re-check with `dwara-cli schema` - this list shrinks over time.

## Attachment chain (why placement matters)

```
consumer  >  route  >  service  >  listener  >  global_policies
```

- Policies AND together across levels.
- Authorization: a deny at any level wins; otherwise the most specific
  level with rules governs.
- Rate limits: all attached windows must admit (stacked).
- Timeouts: most specific wins.
