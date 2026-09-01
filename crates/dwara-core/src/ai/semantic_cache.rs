//! AI semantic caching (DW-083): embedding-similarity cache for AI
//! prompts. A paraphrased prompt within the similarity threshold
//! returns the cached response (no provider call, no token spend).
//!
//! Uses an external embedding service (OpenAI-compatible /v1/embeddings
//! API) to vectorize prompts and `hnsw_rs` (pure Rust HNSW) for
//! approximate nearest neighbor search.
//!
//! Feature-gated behind the `semantic_cache` cargo feature. Without it,
//! the module compiles to an inert placeholder that always returns
//! None (the config is accepted but the cache is a no-op).
//!
//! # Lifecycle
//!
//! The engine is constructed once at startup and stored on the
//! dataplane behind an `ArcSwapOption`. It PERSISTS across reloads:
//! the HNSW index and cached entries survive config refreshes, and a
//! reload updates the config in place via `update_config` (so a
//! threshold or TTL change applies to the next lookup with no cache
//! reset). When the cache reaches `max_entries`, it is reset wholesale
//! (a new HNSW index replaces the old, all entries evicted) — a simple
//! bounded-memory policy.
//!
//! # Request path
//!
//! The LOOKUP runs in `serve_ai` AFTER guardrails (the prompt may have
//! been redacted) and BEFORE model routing + the provider call. A hit
//! returns the cached response JSON with no provider call. The lookup
//! is async (it makes an HTTP call to the embedding service) —
//! acceptable because it runs in the already-async `serve_ai`. The
//! STORE is fire-and-forget (a spawned task): the embedding call and
//! the HNSW insert happen AFTER the response is sent, so they never
//! block the response path. Non-streaming only (streaming responses
//! cannot be cached — the zero-buffer design precludes full content
//! reassembly).

// -------------------------------------------------------------------------
// Feature-gated implementation (the `semantic_cache` cargo feature).
// -------------------------------------------------------------------------

#[cfg(feature = "semantic_cache")]
mod enabled {
    use crate::config::ai::{AiConfig, SemanticCacheConfig};
    use bytes::Bytes;
    use hnsw_rs::hnsw::Hnsw;
    use hnsw_rs::prelude::DistCosine;
    use http_body_util::{BodyExt as _, Full};
    use hyper::{Method, Request};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// One cached response entry.
    struct CachedEntry {
        /// The serialized OpenAI-shaped response JSON (ready to
        /// return to the client verbatim).
        response_json: serde_json::Value,
        /// The model alias the entry was cached for (the cache is
        /// per-model: a lookup for a different alias is a miss even
        /// at high similarity).
        model: String,
        /// When the entry was stored (epoch millis). Entries older
        /// than `ttl_secs` are stale and not returned.
        stored_at_ms: u64,
    }

    /// The semantic cache engine (DW-083). Constructed once at
    /// startup and stored on the dataplane (persists across reloads
    /// — the HNSW index and cached entries survive config refreshes).
    /// Config is updated in place via [`update_config`].
    pub struct SemanticCacheEngine {
        /// The current config (updated on refresh via RwLock).
        config: RwLock<SemanticCacheConfig>,
        /// The HNSW ANN index (replaced wholesale when the cache is
        /// full). `DistCosine` returns cosine DISTANCE
        /// (1 - cosine_similarity).
        hnsw: arc_swap::ArcSwap<Hnsw<'static, f32, DistCosine>>,
        /// Cached responses keyed by HNSW external id.
        entries: RwLock<HashMap<usize, CachedEntry>>,
        /// Next HNSW external id (monotonic across resets — a stale
        /// id from a previous index never collides with a live one).
        next_id: AtomicUsize,
        /// HTTP client for embedding service calls (constructed once;
        /// connection-pooled).
        client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    }

    impl std::fmt::Debug for SemanticCacheEngine {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SemanticCacheEngine")
                .field("enabled", &self.config.read().unwrap().enabled)
                .field("entry_count", &self.entries.read().unwrap().len())
                .finish()
        }
    }

    impl SemanticCacheEngine {
        /// Build the engine from a config. Creates a fresh HNSW
        /// index sized for `max_entries`.
        pub fn new(config: SemanticCacheConfig) -> Self {
            let max_entries = config.max_entries.max(1);
            let hnsw = Arc::new(Hnsw::new(
                16,          // max_nb_connection (M)
                max_entries, // max_elements (hint)
                8,           // max_layer
                200,         // ef_construction
                DistCosine,  // cosine distance
            ));
            let client = Client::builder(TokioExecutor::new()).build_http();
            SemanticCacheEngine {
                config: RwLock::new(config),
                hnsw: arc_swap::ArcSwap::new(hnsw),
                entries: RwLock::new(HashMap::new()),
                next_id: AtomicUsize::new(0),
                client,
            }
        }

        /// Extract the semantic-cache config from the `ai:` block.
        /// Returns None when the block or the `semantic_cache` field
        /// is absent. Does NOT check `enabled` — a disabled engine
        /// still compiles (so a reload can flip it on); the runtime
        /// checks `enabled` on every lookup/store.
        pub fn config_of(cfg: Option<&AiConfig>) -> Option<SemanticCacheConfig> {
            cfg.and_then(|c| c.semantic_cache.clone())
        }

        /// Compile from the `ai:` config block. Returns None when
        /// the `semantic_cache` field is absent. The returned engine
        /// is live only when `enabled` is true (checked at runtime).
        pub fn compile(cfg: Option<&AiConfig>) -> Option<Self> {
            Self::config_of(cfg).map(Self::new)
        }

        /// Update the config in place (reload path). The HNSW index
        /// and cached entries PERSIST — only the config (threshold,
        /// TTL, timeout, etc.) changes. A `max_entries` change does
        /// NOT rebuild the index immediately; the next reset (when
        /// the cache fills) sizes the new index to the new value.
        pub fn update_config(&self, config: SemanticCacheConfig) {
            *self.config.write().unwrap() = config;
        }

        /// Whether the cache is enabled (the runtime gate for every
        /// lookup/store).
        pub fn is_enabled(&self) -> bool {
            self.config.read().unwrap().enabled
        }

        /// Number of cached entries (introspection / tests).
        pub fn entry_count(&self) -> usize {
            self.entries.read().unwrap().len()
        }

        /// Look up a cached response for `prompt_text` + `model`.
        /// Returns the cached response JSON when a nearest neighbor
        /// is within the cosine-similarity threshold, within TTL, and
        /// for the same model alias. None otherwise (or when
        /// disabled, or on any embedding/search error — the cache
        /// fails open: a miss never blocks the request).
        pub async fn lookup(&self, prompt_text: &str, model: &str) -> Option<serde_json::Value> {
            if !self.is_enabled() {
                return None;
            }
            let embedding = match self.embed(prompt_text).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        code = "semantic_cache_embed_failed",
                        "semantic cache lookup embedding failed (failing open as a miss): {e}"
                    );
                    return None;
                }
            };
            let cfg = self.config.read().unwrap().clone();
            let hnsw = self.hnsw.load_full();
            let neighbors = hnsw.search(&embedding, 1, 200);
            let neighbor = neighbors.first()?;
            // DistCosine returns cosine DISTANCE (1 - similarity).
            let similarity = 1.0 - neighbor.distance as f64;
            if similarity < cfg.threshold {
                return None;
            }
            let entries = self.entries.read().unwrap();
            let entry = entries.get(&neighbor.d_id)?;
            // TTL check.
            let now = now_ms();
            if now.saturating_sub(entry.stored_at_ms) > cfg.ttl_secs * 1000 {
                return None;
            }
            // Model match (the cache is per-model).
            if entry.model != model {
                return None;
            }
            tracing::info!(
                code = "semantic_cache_hit",
                model = %model,
                similarity = %similarity,
                "semantic cache hit; returning cached response with no provider call"
            );
            Some(entry.response_json.clone())
        }

        /// Store a response in the cache (fire-and-forget from the
        /// request path). When the cache is full (`entry_count >=
        /// max_entries`), it is reset wholesale before the insert.
        /// Errors (embedding service down, etc.) are logged and
        /// swallowed — a store failure never surfaces to the client
        /// (the call is already in a spawned task).
        pub async fn store(
            &self,
            prompt_text: &str,
            response_json: &serde_json::Value,
            model: &str,
        ) {
            if !self.is_enabled() {
                return;
            }
            let cfg = self.config.read().unwrap().clone();
            // Reset when full (bounded memory).
            if self.entry_count() >= cfg.max_entries {
                self.reset();
            }
            let embedding = match self.embed(prompt_text).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        code = "semantic_cache_embed_failed",
                        "semantic cache store embedding failed (entry not cached): {e}"
                    );
                    return;
                }
            };
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let hnsw = self.hnsw.load_full();
            hnsw.insert((&embedding, id));
            let mut entries = self.entries.write().unwrap();
            entries.insert(
                id,
                CachedEntry {
                    response_json: response_json.clone(),
                    model: model.to_string(),
                    stored_at_ms: now_ms(),
                },
            );
            tracing::info!(
                code = "semantic_cache_store",
                model = %model,
                entries = entries.len(),
                "semantic cache stored a response"
            );
        }

        /// Reset the cache: a fresh HNSW index replaces the old, and
        /// all entries are evicted. Called when `max_entries` is
        /// reached (bounded memory) — a simple wholesale reset.
        pub fn reset(&self) {
            let cfg = self.config.read().unwrap();
            let max_entries = cfg.max_entries.max(1);
            let hnsw = Arc::new(Hnsw::new(16, max_entries, 8, 200, DistCosine));
            self.hnsw.store(hnsw);
            self.entries.write().unwrap().clear();
            tracing::info!(
                code = "semantic_cache_reset",
                "semantic cache reset (max_entries reached); all entries evicted"
            );
        }

        /// Call the embedding service: POST
        /// `{"model": ..., "input": text}` to `embedding_url`, parse
        /// `{"data": [{"embedding": [...]}]}`. Returns the embedding
        /// vector on success.
        async fn embed(&self, text: &str) -> Result<Vec<f32>, String> {
            let cfg = self.config.read().unwrap().clone();
            let body = serde_json::json!({
                "model": cfg.embedding_model,
                "input": text,
            });
            let body_bytes = serde_json::to_vec(&body)
                .map_err(|e| format!("encode embedding request body: {e}"))?;
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri(&cfg.embedding_url)
                .header("content-type", "application/json")
                .header("accept", "application/json");
            // Optional API key (resolved at compile time; the value
            // lives only on the wire).
            if let Some(key) = &cfg.embedding_api_key {
                let resolved = crate::config::credentials::resolve_configured_secret(key)
                    .map_err(|e| format!("resolve embedding api key: {e}"))?;
                builder = builder.header("authorization", format!("Bearer {resolved}"));
            }
            let req = builder
                .body(Full::new(Bytes::from(body_bytes)))
                .map_err(|e| format!("build embedding request: {e}"))?;
            let timeout = Duration::from_millis(cfg.embedding_timeout_ms);
            let resp = tokio::time::timeout(timeout, self.client.request(req))
                .await
                .map_err(|_| {
                    format!(
                        "embedding service timed out after {} ms",
                        cfg.embedding_timeout_ms
                    )
                })?
                .map_err(|e| format!("embedding service request failed: {e}"))?;
            let status = resp.status();
            let bytes = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| format!("read embedding response body: {e}"))?
                .to_bytes();
            if !status.is_success() {
                return Err(format!(
                    "embedding service returned {status}: {}",
                    String::from_utf8_lossy(&bytes)
                ));
            }
            let v: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|e| format!("parse embedding response JSON: {e}"))?;
            let embedding = v
                .get("data")
                .and_then(|d| d.get(0))
                .and_then(|d| d.get("embedding"))
                .and_then(|e| e.as_array())
                .ok_or_else(|| "embedding response missing data[0].embedding".to_string())?;
            let vec: Vec<f32> = embedding
                .iter()
                .map(|x| {
                    x.as_f64()
                        .map(|f| f as f32)
                        .ok_or_else(|| "embedding vector contains a non-number".to_string())
                })
                .collect::<Result<Vec<f32>, _>>()?;
            Ok(vec)
        }
    }

    /// Current Unix milliseconds.
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

#[cfg(feature = "semantic_cache")]
pub use enabled::SemanticCacheEngine;

// -------------------------------------------------------------------------
// Inert stub (no `semantic_cache` feature): the config is accepted
// but the cache is a no-op. compile() always returns None.
// -------------------------------------------------------------------------

#[cfg(not(feature = "semantic_cache"))]
mod disabled {
    use crate::config::ai::{AiConfig, SemanticCacheConfig};

    /// Inert placeholder (no `semantic_cache` feature). The config
    /// is accepted but the cache is a no-op.
    pub struct SemanticCacheEngine;

    impl SemanticCacheEngine {
        /// Always None (the feature is off).
        pub fn compile(_cfg: Option<&AiConfig>) -> Option<Self> {
            None
        }
        /// Always None (the feature is off). Mirrors the enabled
        /// module's signature so the dataplane refresh path compiles
        /// without the feature.
        pub fn config_of(_cfg: Option<&AiConfig>) -> Option<SemanticCacheConfig> {
            None
        }
        /// Unreachable without the feature (compile always returns
        /// None). Present so the dataplane refresh path compiles.
        pub fn new(_config: SemanticCacheConfig) -> Self {
            SemanticCacheEngine
        }
        /// Always false (the feature is off).
        pub fn is_enabled(&self) -> bool {
            false
        }
        /// No-op (the feature is off).
        pub fn update_config(&self, _config: SemanticCacheConfig) {}
        /// Always None (the feature is off). Async so the call site
        /// compiles unchanged with or without the feature.
        pub async fn lookup(&self, _prompt_text: &str, _model: &str) -> Option<serde_json::Value> {
            None
        }
        /// No-op (the feature is off). Async so the call site
        /// compiles unchanged with or without the feature.
        pub async fn store(
            &self,
            _prompt_text: &str,
            _response_json: &serde_json::Value,
            _model: &str,
        ) {
        }
    }
}

#[cfg(not(feature = "semantic_cache"))]
pub use disabled::SemanticCacheEngine;
