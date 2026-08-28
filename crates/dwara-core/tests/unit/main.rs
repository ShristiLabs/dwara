//! Unit tests relocated from src (see AGENTS.md). One binary to keep
//! link time bounded on CI runners.
mod active;
mod analytics;
mod authn;
mod authz;
mod balance;
mod breaker;
mod cache;
mod config_source;
mod credentials;
mod extensions_error;
mod hardening;
mod health;
mod migrations;
mod observability;
mod rate_limiter;
mod response_cache;
mod retries;
mod secrets;
mod snapshot;
mod store_public;
mod tls;
mod transforms;
mod upstream;
mod versioning;
mod webhooks;
