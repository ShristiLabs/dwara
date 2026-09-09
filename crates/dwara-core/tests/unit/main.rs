//! Unit tests relocated from src (see AGENTS.md). One binary to keep
//! link time bounded on CI runners.
mod active;
mod adaptive;
mod admission_queue;
mod aggregation;
mod analytics;
mod analytics_store;
mod authn;
mod authz;
mod balance;
mod breaker;
mod cache;
mod cedar;
mod cel;
mod cel_everywhere;
#[cfg(feature = "ent")]
mod cluster_sync;
mod config_source;
#[cfg(feature = "ent")]
mod cp_dp;
mod credentials;
mod exports;
mod extensions_error;
mod geoip;
mod hardening;
mod health;
mod k8s_gateway;
mod mcp;
mod migrations;
mod oauth2_mtls;
mod observability;
mod openapi_validation;
mod proxy_proto;
mod rate_limiter;
#[cfg(feature = "ent")]
mod redis_cache;
mod response_cache;
mod retries;
mod secrets;
mod snapshot;
mod split;
mod store_public;
mod stream;
mod synthetic;
mod tls;
mod transforms;
mod upstream;
#[cfg(feature = "ent")]
mod vault_secrets;
mod versioning;
mod waf;
mod wasm_abi;
mod webhooks;
mod websocket;
#[cfg(feature = "ent")]
mod workspace;
