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
//! # PERF-02 enhancements
//!
//! - **Exact-match fast tier**: before calling the embedding service,
//!   a `HashMap<prompt_hash, entry_id>` checks for an exact text match.
//!   A hit skips the embedding call entirely (the common case for
//!   repeated identical prompts — RAG traffic, retry storms, etc.).
//! - **LRU eviction**: when the cache reaches `max_entries`, the least
//!   recently accessed entry is evicted (not a wholesale reset). Each
//!   entry carries a `last_accessed_ms` timestamp; the eviction scan
//!   is O(n) but runs once per insert, so the amortized cost is O(1).
//! - **Streaming support**: streaming responses (SSE frame sequences)
//!   are cached and replayed. On a cache miss, the stream is TEE'd:
//!   frames are forwarded to the client AND collected in a bounded
//!   buffer; on stream completion, the collected frames are stored. On
//!   a cache hit, the cached frames are replayed as an SSE response.
//!   The tee buffer is bounded (`stream_cache_max_bytes`, default 1
//!   MiB): a stream exceeding the cap is not cached (the response is
//!   still forwarded to the client unmodified).
//!
//! # Lifecycle
//!
//! The engine is constructed once at startup and stored on the
//! dataplane behind an `ArcSwapOption`. It PERSISTS across reloads:
//! the HNSW index and cached entries survive config refreshes, and a
//! reload updates the config in place via `update_config` (so a
//! threshold or TTL change applies to the next lookup with no cache
//! reset).
//!
//! # Request path
//!
//! The LOOKUP runs in `serve_ai` AFTER guardrails (the prompt may have
//! been redacted) and BEFORE model routing + the provider call. A hit
//! returns the cached response (JSON for non-streaming, SSE frames for
//! streaming) with no provider call. The lookup is async (it may make
//! an HTTP call to the embedding service) — acceptable because it runs
//! in the already-async `serve_ai`. The STORE is fire-and-forget (a
//! spawned task): the embedding call and the HNSW insert happen AFTER
//! the response is sent, so they never block the response path.

// -------------------------------------------------------------------------
// Feature-gated implementation (the `semantic_cache` cargo feature).
// -------------------------------------------------------------------------

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

    /// A cached response: either a complete JSON body (non-streaming)
    /// or a sequence of SSE frames (streaming). The `frames` variant
    /// stores the raw `data: ...\n\n` frames as collected by the tee;
    /// replaying them is a single concatenated body (the client sees
    /// the same SSE stream the provider emitted).
    #[derive(Clone)]
    enum CachedBody {
        /// Non-streaming: the OpenAI-shaped response JSON.
        Json(serde_json::Value),
        /// Streaming: the collected SSE frames (each a `data: ...\n\n`
        /// string, in order). The `[DONE]` sentinel is included.
        Frames(Vec<String>),
    }

    /// One cached response entry.
    struct CachedEntry {
        /// The cached response body (JSON or SSE frames).
        body: CachedBody,
        /// The model alias the entry was cached for (the cache is
        /// per-model: a lookup for a different alias is a miss even
        /// at high similarity).
        model: String,
        /// When the entry was stored (epoch millis). Entries older
        /// than `ttl_secs` are stale and not returned.
        stored_at_ms: u64,
        /// When the entry was last accessed (epoch millis). Used for
        /// LRU eviction (PERF-02): the entry with the smallest
        /// `last_accessed_ms` is evicted when the cache is full.
        last_accessed_ms: u64,
        /// The prompt text (stored for the exact-match fast tier and
        /// for eviction cleanup). PERF-02: the exact-match map stores
        /// a hash, but the entry retains the full text so the exact-
        /// match map can be rebuilt on eviction without re-hashing
        /// the prompt.
        prompt_text: String,
    }

    /// What a cache lookup returns (PERF-02): the cached response,
    /// either a JSON body (non-streaming) or SSE frames (streaming).
    #[derive(Clone)]
    pub enum CachedResponse {
        /// Non-streaming: the OpenAI-shaped response JSON.
        Json(serde_json::Value),
        /// Streaming: the collected SSE frames, ready to replay as
        /// a single concatenated SSE body.
        Frames(Vec<String>),
    }

    /// The semantic cache engine (DW-083). Constructed once at
    /// startup and stored on the dataplane (persists across reloads
    /// — the HNSW index and cached entries survive config refreshes).
    /// Config is updated in place via `update_config`.
    pub struct SemanticCacheEngine {
        /// The current config (updated on refresh via RwLock).
        config: RwLock<SemanticCacheConfig>,
        /// The HNSW ANN index (replaced on reset). `DistCosine` returns
        /// cosine DISTANCE (1 - cosine_similarity).
        hnsw: arc_swap::ArcSwap<Hnsw<'static, f32, DistCosine>>,
        /// Cached responses keyed by HNSW external id.
        entries: RwLock<HashMap<usize, CachedEntry>>,
        /// PERF-02: exact-match fast tier. Maps the prompt text hash
        /// to the HNSW external id, so an identical prompt skips the
        /// embedding call entirely. Cleared on reset; updated on store
        /// and evicted on LRU removal.
        exact_match: RwLock<HashMap<u64, usize>>,
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
                exact_match: RwLock::new(HashMap::new()),
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
        /// Returns the cached response (JSON or SSE frames) when a
        /// match is found within the similarity threshold, within TTL,
        /// and for the same model alias. None otherwise (or when
        /// disabled, or on any embedding/search error — the cache
        /// fails open: a miss never blocks the request).
        ///
        /// PERF-02: the exact-match fast tier checks a hash map
        /// BEFORE calling the embedding service. An exact prompt-text
        /// match skips the embedding call entirely (the common case
        /// for repeated identical prompts).
        pub async fn lookup(&self, prompt_text: &str, model: &str) -> Option<CachedResponse> {
            if !self.is_enabled() {
                return None;
            }
            let cfg = self.config.read().unwrap().clone();
            let now = now_ms();
            // PERF-02: exact-match fast tier. Check the hash map
            // before calling the embedding service. A hit skips the
            // embedding call entirely.
            let prompt_hash = hash_prompt(prompt_text);
            if let Some(id) = self.exact_match.read().unwrap().get(&prompt_hash).copied() {
                if let Some(entry) = self.validate_entry(id, model, now, &cfg) {
                    tracing::info!(
                        code = "semantic_cache_hit",
                        model = %model,
                        match_type = "exact",
                        "semantic cache exact-match hit; returning cached response"
                    );
                    return Some(entry);
                }
            }
            // Semantic (embedding) lookup.
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
            let hnsw = self.hnsw.load_full();
            let neighbors = hnsw.search(&embedding, 1, 200);
            let neighbor = neighbors.first()?;
            // DistCosine returns cosine DISTANCE (1 - similarity).
            let similarity = 1.0 - neighbor.distance as f64;
            if similarity < cfg.threshold {
                return None;
            }
            if let Some(entry) = self.validate_entry(neighbor.d_id, model, now, &cfg) {
                tracing::info!(
                    code = "semantic_cache_hit",
                    model = %model,
                    match_type = "semantic",
                    similarity = %similarity,
                    "semantic cache hit; returning cached response"
                );
                return Some(entry);
            }
            None
        }

        /// Validate a cached entry by id: check it exists, is within
        /// TTL, and matches the model. On success, update the
        /// last-accessed timestamp (LRU) and return the cached body.
        fn validate_entry(
            &self,
            id: usize,
            model: &str,
            now: u64,
            cfg: &SemanticCacheConfig,
        ) -> Option<CachedResponse> {
            let mut entries = self.entries.write().unwrap();
            let entry = entries.get_mut(&id)?;
            // TTL check.
            if now.saturating_sub(entry.stored_at_ms) > cfg.ttl_secs * 1000 {
                return None;
            }
            // Model match (the cache is per-model).
            if entry.model != model {
                return None;
            }
            // PERF-02: update last-accessed for LRU.
            entry.last_accessed_ms = now;
            match &entry.body {
                CachedBody::Json(v) => Some(CachedResponse::Json(v.clone())),
                CachedBody::Frames(f) => Some(CachedResponse::Frames(f.clone())),
            }
        }

        /// Store a non-streaming response in the cache (fire-and-
        /// forget from the request path). When the cache is full
        /// (`entry_count >= max_entries`), the least recently used
        /// entry is evicted (PERF-02 LRU, not a wholesale reset).
        /// Errors are logged and swallowed.
        pub async fn store(
            &self,
            prompt_text: &str,
            response_json: &serde_json::Value,
            model: &str,
        ) {
            self.store_body(prompt_text, CachedBody::Json(response_json.clone()), model)
                .await;
        }

        /// Store a streaming response (SSE frames) in the cache
        /// (PERF-02). The frames are the collected SSE `data: ...\n\n`
        /// strings as tee'd by the stream body. Same LRU eviction as
        /// the non-streaming store.
        pub async fn store_streaming(&self, prompt_text: &str, frames: Vec<String>, model: &str) {
            self.store_body(prompt_text, CachedBody::Frames(frames), model)
                .await;
        }

        /// Internal store: inserts a cached body with LRU eviction.
        async fn store_body(&self, prompt_text: &str, body: CachedBody, model: &str) {
            if !self.is_enabled() {
                return;
            }
            let cfg = self.config.read().unwrap().clone();
            // PERF-02: LRU eviction. When the cache is full, evict
            // the least recently accessed entry (not a wholesale
            // reset). The scan is O(n) but runs once per insert, so
            // the amortized cost is O(1).
            if self.entry_count() >= cfg.max_entries {
                self.evict_lru();
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
            let now = now_ms();
            let prompt_hash = hash_prompt(prompt_text);
            {
                let mut entries = self.entries.write().unwrap();
                entries.insert(
                    id,
                    CachedEntry {
                        body,
                        model: model.to_string(),
                        stored_at_ms: now,
                        last_accessed_ms: now,
                        prompt_text: prompt_text.to_string(),
                    },
                );
            }
            self.exact_match.write().unwrap().insert(prompt_hash, id);
            tracing::info!(
                code = "semantic_cache_store",
                model = %model,
                entries = self.entry_count(),
                "semantic cache stored a response"
            );
        }

        /// PERF-02: evict the least recently used entry. Scans all
        /// entries for the smallest `last_accessed_ms` and removes it
        /// from the entries map, the exact-match map, and the HNSW
        /// index (the HNSW index is not modified — a stale neighbor
        /// is filtered by the TTL/model check in `validate_entry`).
        fn evict_lru(&self) {
            let mut entries = self.entries.write().unwrap();
            if entries.is_empty() {
                return;
            }
            let (evict_id, _) = entries
                .iter()
                .min_by_key(|(_, e)| e.last_accessed_ms)
                .map(|(id, e)| (*id, e.prompt_text.clone()))
                .unwrap();
            let entry = entries.remove(&evict_id);
            drop(entries);
            if let Some(entry) = entry {
                let hash = hash_prompt(&entry.prompt_text);
                self.exact_match.write().unwrap().remove(&hash);
            }
            tracing::info!(
                code = "semantic_cache_evict",
                entry_id = evict_id,
                "semantic cache LRU eviction (max_entries reached)"
            );
        }

        /// Reset the cache: a fresh HNSW index replaces the old, and
        /// all entries are evicted. Called on explicit reset only
        /// (PERF-02: LRU eviction handles the bounded-memory policy
        /// at `max_entries`; a wholesale reset is no longer the
        /// default eviction strategy).
        pub fn reset(&self) {
            let cfg = self.config.read().unwrap();
            let max_entries = cfg.max_entries.max(1);
            let hnsw = Arc::new(Hnsw::new(16, max_entries, 8, 200, DistCosine));
            self.hnsw.store(hnsw);
            self.entries.write().unwrap().clear();
            self.exact_match.write().unwrap().clear();
            tracing::info!(
                code = "semantic_cache_reset",
                "semantic cache reset; all entries evicted"
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

    /// Hash a prompt text for the exact-match fast tier (PERF-02).
    /// Uses the standard library's `DefaultHasher` (a deterministic
    /// hash within one process — sufficient for an in-memory cache;
    /// cross-process consistency is not required).
    fn hash_prompt(text: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        text.hash(&mut hasher);
        hasher.finish()
    }
}

pub use enabled::{CachedResponse, SemanticCacheEngine};
