# Test map

Run a single suite: `cargo test -p <crate> --test <name>`.

## dwara-core (`crates/dwara-core/tests/`)

Unit tests live in `tests/unit/` (one file per source module behind a single
`main.rs` binary). White-box residuals in `src/` carry justification comments.

| Area | Suites |
|---|---|
| Config schema / validation | `config_schema`, `config_schema_extended`, `snapshot_pipeline`, `config_convergence` |
| Routing | `router_golden` (golden files), `proxy_coverage` |
| Proxy behavior | `proxy`, `proxy_coverage` |
| TLS | `tls_validation`, `trusted_ca`, `fips`, `pq` |
| Upstreams / LB | `upstream_client`, `balancing`, `peak_ewma_lb`, `hedging`, `mirror_fault`, `dns_discovery`, `dns_dial_path` |
| Health | `passive_health`, `active_health` |
| Resilience | `retries_timeouts`, `breaker_caps`, `load_shedding`, `rate_limit`, `admission_queue`, `quotas`, `redis_quotas`, `chaos_resilience`, `canary`, `canary_analysis` |
| Edge policies | `cors_compression_limits` |
| Transforms | `transforms`, `masking`, `tests/unit/transforms.rs` |
| Caching + coalescing | `caching`, `tests/unit/response_cache.rs` |
| Maintenance + dry-run | `maintenance_dry_run` |
| Analytics | `analytics`, `streaming_analytics`, `tests/unit/analytics_store.rs`, `exports`, `tests/unit/exports.rs` |
| GeoIP | `tests/unit/geoip.rs`, `authz` geoip e2e |
| Auth | `authn`, `authz`, `hmac_signing`, `oauth2_mtls`, `oidc` |
| Key rotation | `authn` rotation cases, `store` |
| Observability / SLO | `observability`, `business_metrics`, `tests/unit/observability.rs` |
| Protocol hardening | `method_allowlist`, `tests/unit/proxy_proto.rs`, `tests/unit/upstream.rs` |
| Webhooks | `webhooks`, `tests/unit/webhooks.rs` |
| WAF-lite + anomaly | `waf`, `anomaly_scoring` |
| Plugins (native + wasm) | `plugins`, `wasm_host` |
| CEL + Cedar | `tests/unit/cel.rs`, `tests/unit/cel_everywhere.rs`, `tests/unit/cedar.rs` |
| OpenAPI validation | `tests/unit/openapi_validation.rs` |
| Aggregation | `tests/unit/aggregation.rs` |
| gRPC-Web / GraphQL | `grpc_web`, `graphql`, `grpc_websocket` |
| L4 / H3 / split / replay | `stream`, `replay`, `tests/unit/split.rs` |
| Synthetic monitoring | `tests/unit/synthetic.rs` |
| MCP | `tests/unit/mcp.rs` |
| Mesh | `mesh` |
| K8s Gateway API | `k8s_controller`, `k8s_conformance` |
| CP/DP split (ent) | `cp_dp_transport`, `tests/unit/cp_dp.rs`, `tests/unit/cluster_sync.rs` |
| Licensing + Workspaces (ent) | `licensing`, `tests/unit/workspace.rs` |
| AI gateway | `ai_adapters`, `ai_gateway`, `ai_endpoints`, `ai_routing`, `ai_routing_policy`, `ai_streaming`, `ai_budget`, `ai_cost`, `ai_governance`, `ai_agent_governance`, `ai_prompt_logging`, `ai_guardrails`, `ai_semantic_cache`, `ai_experiments`, `ai_mcp`, `ai_otel_metrics`, `ai_token_estimator`, `a2a` |
| State | `store` |
| Secrets | `secrets_handling`, `tests/unit/secrets.rs` |
| Mock mode | `mock_mode` |
| Concurrency | `swap_stress`, `loom` (feature-gated) |

## dwara-bin (`crates/dwara-bin/tests/`)

`reload_edges`, `reload_shutdown`, `healthz_readyz`, `protocol_hardening`,
`admin_reload_coherence`, `otlp_export`, `otlp_inert`, `hello_listener`,
`tls_listener`, `tls_edges`, `l4_splice_drain`, `secrets_redaction`,
`zero_downtime_upgrade`

## dwara-admin (`crates/dwara-admin/tests/`)

`admin_api`

## dwara-cli (`crates/dwara-cli/tests/`)

`cli`, `loadgen_e2e`, `loadgen_unit`, `openapi_import`, `openapi_import_unit`,
`nginx_import`, `nginx_import_unit`, `kong_import`, `kong_import_unit`,
`envoy_import`, `envoy_import_unit`, `plugin_scaffold_unit`
