//! Analytics bounded context (DW-043): the embedded analytics store.
//!
//! Observability answers "is it healthy right now"; analytics answers
//! "what happened over time, to whom, and why". This domain owns the
//! DURABLE side of that question: a local SQLite database (separate
//! file from the state store, DW-018 — different lifecycle, different
//! write pattern, independent bounded-disk story) holding raw access
//! records for a short retention window and additive rollup tables at
//! 1m/5m/1h/1d granularities with per-granularity retention, plus the
//! query surface over them (dashboard series, Top-N, structured
//! query) served by the admin API, and the scheduled usage-report
//! exports (DW-120, [`exports`]) that turn the same rollups into
//! durable per-consumer statements.
//!
//! # Write path (never blocks the dataplane)
//!
//! The dataplane's `DataPlane` (see `dataplane::proxy`) holds an
//! [`EmbeddedAnalytics`] (set once at startup when the config carries
//! an `analytics` block) and calls [`EmbeddedAnalytics::record`] at
//! request completion — a `try_send` onto a bounded channel. When the
//! channel is full the record is DROPPED (counted, logged throttled):
//! the analytics pipeline must never slow or block a request, the same
//! fire-and-forget posture DW-121's record stream
//! (`events::stream`, a sibling pipeline that ships each record to an
//! external sink instead of the local store) holds. A background
//! writer drains the channel in batched transactions.
//!
//! # The sink seam
//!
//! The M1 extension contract
//! `extensions::analytics::AnalyticsSink` is the OSS/Ent seam (feature
//! analysis 11.4): the embedded store implements it (over the richer
//! per-request fields DW-043 added to `extensions::analytics::Event`).
//! DW-121's raw-record firehose is NOT an implementation of this
//! contract — it streams the completion-time access record (which
//! carries `request_id` and the redacted path the extension event
//! deliberately omits) through its own sink seam in `events::stream`;
//! the federated analytics pipeline (DW-095) remains a future sibling
//! implementation of THIS contract.
//!
//! # Custom dimensions
//!
//! Config-declared dimensions extracted from request HEADERS at
//! completion-time capture (e.g. `x-plan` -> dimension `plan`): they
//! ride the [`AccessRecord`] into
//! raw rows (a JSON object column) and aggregate into their own
//! narrow rollup table. They are analytics-only — deliberately NOT
//! added to the access log, whose field list is redacted by
//! construction and stays that way.

pub mod exports;
pub mod insights;
pub mod query;
pub mod rollup;
pub mod schema;

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tokio::sync::mpsc;

use crate::observability::AccessRecord;

/// Channel capacity between the request path and the writer. Sized so
/// a burst of completions (or a briefly stalled writer transaction)
/// queues rather than drops; drops are counted and throttled-logged.
const CHANNEL_CAP: usize = 4096;

/// Writer batch flush bound (records) — with the flush tick, whichever
/// comes first.
const BATCH_MAX: usize = 1024;

/// How often the rollup/retention worker runs. Rollups are cheap
/// cursor-guarded SQL; 30 s keeps even a 1-minute window's staleness
/// under a minute end-to-end (plus the completion grace below).
const ROLLUP_INTERVAL_MS: u64 = 30_000;

/// Completion GRACE: a fine window is rolled only once its end is at
/// least this far in the past — headroom for the writer's flush tick
/// and batch latency, so a straggler record still lands in the window
/// it belongs to. Records later than the grace are documented as
/// rollup-lost (they remain in `raw` until raw retention expires).
pub const ROLLUP_GRACE_MS: i64 = 60_000;

/// Per-granularity retention defaults (ms) — the single definition
/// lives in [`crate::config::ANALYTICS_DEFAULT_RETENTION_MS`] (the
/// lowest consuming domain); re-exported here for the module's
/// readers.
pub use crate::config::ANALYTICS_DEFAULT_RETENTION_MS as DEFAULT_RETENTION_MS;

/// One raw record as stored (the owned, completion-time copy handed
/// across the channel).
struct RawRecord {
    ts_ms: i64,
    request_id: String,
    correlation_id: String,
    listener: String,
    route: String,
    consumer: String,
    upstream: String,
    method: String,
    status: u16,
    status_class: String,
    duration_ms: f64,
    attempts: u32,
    rate_limited: bool,
    broken: bool,
    shed: bool,
    dims: String,
}

/// The custom-dimensions JSON column for a (name, value) pair list.
fn dims_json(pairs: &[(String, String)]) -> String {
    if pairs.is_empty() {
        return "{}".to_string();
    }
    let map: serde_json::Map<String, serde_json::Value> = pairs
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    serde_json::Value::Object(map).to_string()
}

/// One AI spend record (DW-079): the per-request spend dimensions
/// written to the `ai_spend` table. A PLAIN DTO — deliberately not
/// importing `ai::types::Usage` (the analytics domain may not import
/// the `ai` domain; see `scripts/check_deps.py`). The dataplane
/// converts from `ai::types::Usage` at the call site.
#[derive(Debug, Clone)]
pub struct AiSpendRecord {
    /// Wall-clock ms since the Unix epoch.
    pub ts_ms: i64,
    /// The authenticated consumer name (or "anonymous").
    pub consumer: String,
    /// The consumer type (DW-113): `"user"` or `"agent"`. Defaults to
    /// `"user"` for pre-DW-113 records and anonymous traffic.
    pub consumer_type: String,
    /// The policy-scoped team key (the policy name a `scope: policy`
    /// budget uses), or empty when no team budget binds the request.
    pub team: String,
    /// The serving provider name (`ai.providers[].name`).
    pub provider: String,
    /// The provider's own model identifier (the pricing key).
    pub model: String,
    /// The canary version label (DW-076), or empty for non-canary.
    pub version: String,
    /// Provider-reported prompt (input) tokens.
    pub prompt_tokens: u64,
    /// Provider-reported completion (output) tokens.
    pub completion_tokens: u64,
    /// Total tokens (prompt + completion, or the provider's own total).
    pub total_tokens: u64,
    /// Priced cost in integer micro-USD (usage x pricing table).
    pub cost_micros: u64,
}

/// One AI governance audit event (DW-084): the per-check record
/// written to the `ai_governance_events` table. A PLAIN DTO —
/// deliberately not importing `ai::governance` (the analytics domain
/// may not import the `ai` domain; see `scripts/check_deps.py`). The
/// dataplane converts from `ai::governance::GovernanceVerdict` at the
/// call site.
#[derive(Debug, Clone)]
pub struct AiGovernanceEvent {
    /// Wall-clock ms since the Unix epoch.
    pub ts_ms: i64,
    /// The authenticated consumer name (or "anonymous").
    pub consumer: String,
    /// The denying policy (team) name for a denial, or the FIRST
    /// binding allowlist's policy name for an allow (empty when no
    /// allowlist binds the request).
    pub team: String,
    /// The client-facing model alias the request named.
    pub model: String,
    /// `allow` or `deny`.
    pub verdict: String,
    /// A short reason string (the denial cause; empty for an allow).
    pub reason: String,
}

/// One AI prompt/response log record (DW-081): the per-request
/// capture written to the `ai_prompt_logs` table. A PLAIN DTO —
/// deliberately not importing `ai::types` (the analytics domain may
/// not import the `ai` domain; see `scripts/check_deps.py`). The
/// dataplane serializes and redacts the `ChatRequest`/`ChatResponse`
/// at the call site, passing the redacted JSON strings here. Capture
/// is opt-in (privacy-first); the redaction pass runs BEFORE the
/// record is offered.
#[derive(Debug, Clone)]
pub struct AiPromptLogRecord {
    /// Wall-clock ms since the Unix epoch.
    pub ts_ms: i64,
    /// The request id (correlation handle).
    pub request_id: String,
    /// The authenticated consumer name (or "anonymous").
    pub consumer: String,
    /// The route name that served the request.
    pub route: String,
    /// The serving provider name.
    pub provider: String,
    /// The provider's own model identifier.
    pub model: String,
    /// The canary version label, or empty for non-canary.
    pub version: String,
    /// The REDACTED prompt as JSON (the serialized ChatRequest after
    /// redaction).
    pub prompt_json: String,
    /// The REDACTED response as JSON (the serialized ChatResponse
    /// after redaction, or `{"streamed": true}` for streaming
    /// captures where the full content is not reassembled).
    pub response_json: String,
    /// Whether the request was streaming.
    pub stream: bool,
}

/// One AI experiment assignment record (DW-086): the per-request
/// record written to the `ai_experiment_assignments` table when a
/// request is served by an A/B test alias. A PLAIN DTO — deliberately
/// not importing `ai::experiments` (the analytics domain may not
/// import the `ai` domain; see `scripts/check_deps.py`).
#[derive(Debug, Clone)]
pub struct AiExperimentAssignment {
    /// Wall-clock ms since the Unix epoch.
    pub ts_ms: i64,
    /// The request id (correlation handle).
    pub request_id: String,
    /// The experiment (A/B test) name.
    pub experiment: String,
    /// The selected variant name.
    pub variant: String,
    /// The model alias the variant routes to.
    pub model: String,
    /// The authenticated consumer name (or "anonymous").
    pub consumer: String,
}

/// One AI eval result record (DW-086): the per-case record written to
/// the `ai_eval_results` table when an eval is run via the admin API.
/// A PLAIN DTO — the admin endpoint constructs it from the eval
/// runner's output.
#[derive(Debug, Clone)]
pub struct AiEvalResultRecord {
    /// Wall-clock ms since the Unix epoch.
    pub ts_ms: i64,
    /// The eval name (from config).
    pub eval_name: String,
    /// The model alias the eval ran against.
    pub model: String,
    /// The variant name (when running an A/B test's variants), or
    /// empty.
    pub variant: String,
    /// The prompt version reference (`prompt_name/version_name`), or
    /// empty.
    pub prompt_version: String,
    /// The case index in the golden set.
    pub case_index: usize,
    /// The input prompt.
    pub input: String,
    /// The expected output.
    pub expected: String,
    /// The actual output from the provider.
    pub actual: String,
    /// Whether the case passed (scorer matched).
    pub passed: bool,
    /// The scorer name (`exact_match`, `contains`, `regex`).
    pub scorer: String,
    /// The latency of the provider call in milliseconds.
    pub latency_ms: f64,
}

/// One AI feedback record (DW-086): the per-feedback record written
/// to the `ai_feedback` table when feedback is ingested via the admin
/// API.
#[derive(Debug, Clone)]
pub struct AiFeedbackRecord {
    /// Wall-clock ms since the Unix epoch.
    pub ts_ms: i64,
    /// The request id the feedback refers to.
    pub request_id: String,
    /// The feedback label (e.g. `good`, `bad`, `thumbs_up`).
    pub label: String,
    /// An optional free-form comment.
    pub comment: String,
    /// The authenticated consumer name (or "anonymous").
    pub consumer: String,
    /// The model alias the feedback refers to (optional).
    pub model: String,
}

/// One MCP tool call record (DW-087): the per-call record written to
/// the `mcp_tool_calls` table when a tool call is proxied through the
/// MCP gateway. A PLAIN DTO — deliberately not importing `ai::mcp`
/// (the analytics domain may not import the `ai` domain; see
/// `scripts/check_deps.py`). The dataplane constructs it at the call
/// site.
#[derive(Debug, Clone)]
pub struct McpToolCallRecord {
    /// Wall-clock ms since the Unix epoch.
    pub ts_ms: i64,
    /// The request id (correlation handle).
    pub request_id: String,
    /// The MCP session id (correlates calls within one agent session).
    pub session_id: String,
    /// The authenticated consumer name (or "anonymous").
    pub consumer: String,
    /// The consumer type (DW-113): `"user"` or `"agent"`. Defaults to
    /// `"user"` for pre-DW-113 records and anonymous traffic.
    pub consumer_type: String,
    /// The tool name that was called.
    pub tool_name: String,
    /// Whether the call was authorized (passed the per-tool authz
    /// check). `false` for denied calls.
    pub allowed: bool,
    /// The call duration in milliseconds (from the authz check
    /// through the upstream response).
    pub duration_ms: f64,
    /// An optional error code (e.g. `"unauthorized"`,
    /// `"upstream_error"`, `"timeout"`). `None` for successful calls.
    pub error_code: Option<String>,
    /// The call status: `success`, `error`, or `denied`.
    pub status: String,
}

impl RawRecord {
    /// The extension-event shape of the same record (the
    /// `extensions::analytics::AnalyticsSink` contract's input type).
    fn from_event(event: &crate::extensions::analytics::Event) -> Self {
        RawRecord {
            ts_ms: event.timestamp_ms as i64,
            request_id: String::new(),
            correlation_id: String::new(),
            listener: event.listener.clone().unwrap_or_default(),
            route: event.route.clone().unwrap_or_else(|| "unrouted".into()),
            consumer: event.consumer.clone().unwrap_or_else(|| "anonymous".into()),
            // The extension event carries the ENDPOINT; the raw table's
            // `upstream` column is the queries' upstream axis — the
            // event shape has no separate upstream field, so
            // endpoint-addressed events record the endpoint there.
            upstream: event.endpoint.clone().unwrap_or_default(),
            method: event.method.clone().unwrap_or_default(),
            status: event.status.unwrap_or(0),
            status_class: event
                .status
                .map(|s| format!("{}xx", s / 100))
                .unwrap_or_else(|| "0xx".into()),
            duration_ms: event.duration_ms.unwrap_or(0.0),
            attempts: event.attempts.unwrap_or(0),
            rate_limited: event.rate_limited,
            broken: event.broken,
            shed: event.shed,
            dims: dims_json(&event.attributes),
        }
    }

    fn from(rec: &AccessRecord, now_ms: i64) -> Self {
        RawRecord {
            ts_ms: now_ms,
            request_id: rec.request_id.clone(),
            correlation_id: rec.correlation_id.clone(),
            listener: rec.listener.clone(),
            route: rec.route.clone(),
            consumer: rec.consumer.clone(),
            upstream: rec.upstream.clone().unwrap_or_default(),
            method: rec.method.clone(),
            status: rec.status,
            status_class: crate::observability::status_class(rec.status),
            duration_ms: rec.duration_ms,
            attempts: rec.attempts,
            rate_limited: rec.rate_limited,
            broken: rec.broken,
            shed: rec.shed,
            dims: dims_json(&rec.custom),
        }
    }
}

/// Wall-clock ms since the Unix epoch (the analytics time domain).
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The maximum number of latency samples retained per route per window
/// (DW-092). Capped to bound memory and snapshot-time sort cost
/// (O(n log n) with n <= 1000 — fast enough for an admin-path
/// snapshot, never on the request hot path).
const MAX_LATENCY_SAMPLES: usize = 1000;

/// One per-route sketch within the live rolling window (DW-092).
/// Updated in place under atomics (counts) and a short mutex over a
/// capped latency-sample vector. The route key is held by the parent
/// map, not here.
struct RouteSketch {
    /// Total requests in the current window.
    requests: AtomicU64,
    /// Total errors (status >= 500) in the current window.
    errors: AtomicU64,
    /// Capped latency samples (ms) for percentile computation at
    /// snapshot time. Once the cap is reached, new samples replace the
    /// oldest (a simple ring) so the retained set stays representative
    /// of the recent tail.
    latency_samples: Mutex<LatencySamples>,
}

/// A capped latency-sample buffer with a write cursor (ring
/// replacement once full). The retained set is sorted at snapshot
/// time for nearest-rank percentile selection.
struct LatencySamples {
    samples: Vec<f64>,
    cursor: usize,
}

impl LatencySamples {
    fn new() -> Self {
        LatencySamples {
            samples: Vec::with_capacity(MAX_LATENCY_SAMPLES),
            cursor: 0,
        }
    }

    /// Record one latency sample. Once the cap is reached, the oldest
    /// sample (by insertion order) is overwritten — a bounded ring
    /// that keeps the most recent `MAX_LATENCY_SAMPLES` observations.
    fn push(&mut self, ms: f64) {
        if self.samples.len() < MAX_LATENCY_SAMPLES {
            self.samples.push(ms);
        } else {
            self.samples[self.cursor] = ms;
            self.cursor = (self.cursor + 1) % MAX_LATENCY_SAMPLES;
        }
    }

    /// Nearest-rank percentile over the retained samples (sorted in
    /// place). `p` is 0.0-1.0. Returns 0.0 when no samples are held.
    fn percentile(&mut self, p: f64) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.samples
            .sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p = p.clamp(0.0, 1.0);
        let rank = ((self.samples.len() as f64) * p).ceil() as usize;
        self.samples[rank.clamp(1, self.samples.len()) - 1]
    }

    /// The arithmetic mean of the retained samples.
    fn mean(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.samples.iter().sum::<f64>() / self.samples.len() as f64
    }
}

impl RouteSketch {
    fn new() -> Self {
        RouteSketch {
            requests: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            latency_samples: Mutex::new(LatencySamples::new()),
        }
    }
}

/// One route's snapshot from the current live window (DW-092).
#[derive(Debug, Clone, serde::Serialize)]
pub struct LiveRouteSnapshot {
    /// The route name.
    pub route: String,
    /// Total requests in the current window.
    pub requests: u64,
    /// Total errors (status >= 500) in the current window.
    pub errors: u64,
    /// The error rate as a fraction in [0, 1].
    pub error_rate: f64,
    /// The p50 latency in milliseconds.
    pub p50_ms: f64,
    /// The p95 latency in milliseconds.
    pub p95_ms: f64,
    /// The p99 latency in milliseconds.
    pub p99_ms: f64,
    /// The average (mean) latency in milliseconds.
    pub avg_ms: f64,
}

/// A snapshot of the current live window across all routes (DW-092).
/// Returned by [`EmbeddedAnalytics::live_snapshot`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct LiveSnapshot {
    /// The window's start time (wall-clock ms since the Unix epoch).
    pub window_start_ms: u64,
    /// The window's end time (start + window_size_ms).
    pub window_end_ms: u64,
    /// Per-route snapshots, sorted by route name for stable output.
    pub routes: Vec<LiveRouteSnapshot>,
}

/// Live in-process sketches (DW-092): sub-second-freshness per-route
/// rolling window with counts, errors, and capped latency samples.
/// Maintained inside [`EmbeddedAnalytics`] and updated synchronously
/// on every `record()` call — never blocks the dataplane (atomics for
/// counts, a short mutex over a capped vector for samples). When the
/// window expires, the completed window's aggregates are handed to
/// the insights engine (if attached) for forecasting and anomaly
/// detection.
pub struct LiveSketches {
    /// Per-route current-window data, behind a RwLock so the snapshot
    /// read path (admin) does not block the record write path
    /// (dataplane).
    routes: RwLock<HashMap<String, RouteSketch>>,
    /// The current window's start time (wall-clock ms). Atomic so the
    /// rotation check on the hot path is lock-free.
    window_start_ms: AtomicU64,
    /// The window size in milliseconds (= the freshness target).
    window_size_ms: u64,
    /// The insights engine fed on window rotation (None when insights
    /// are disabled).
    insights: RwLock<Option<Arc<insights::InsightsEngine>>>,
}

impl LiveSketches {
    /// Construct a new live-sketches store with the given window size.
    pub fn new(window_size_ms: u64) -> Arc<Self> {
        Arc::new(LiveSketches {
            routes: RwLock::new(HashMap::new()),
            window_start_ms: AtomicU64::new(0),
            window_size_ms,
            insights: RwLock::new(None),
        })
    }

    /// Attach the insights engine so window rotations feed it. Called
    /// once during [`EmbeddedAnalytics::open`] wiring.
    pub fn set_insights(&self, engine: Arc<insights::InsightsEngine>) {
        *self.insights.write().unwrap() = Some(engine);
    }

    /// The current window's start time (wall-clock ms).
    pub fn window_start(&self) -> u64 {
        self.window_start_ms.load(Ordering::Relaxed)
    }

    /// Record one request completion into the current window. Rotates
    /// the window (handing the completed aggregates to the insights
    /// engine) when `now_ms` has passed the window boundary.
    pub fn record(&self, route: &str, status: u16, duration_ms: f64, now_ms: u64) {
        // Rotate the window if it has expired. The rotation is under
        // the write lock so a concurrent snapshot sees a consistent
        // window boundary.
        let start = self.window_start_ms.load(Ordering::Relaxed);
        if start == 0 || now_ms >= start + self.window_size_ms {
            self.rotate(now_ms);
        }
        // Look up or create the route sketch under a short write lock.
        // The map is keyed by route name; a missing entry is inserted.
        let map = self.routes.read().unwrap();
        if let Some(sketch) = map.get(route) {
            sketch.requests.fetch_add(1, Ordering::Relaxed);
            if status >= 500 {
                sketch.errors.fetch_add(1, Ordering::Relaxed);
            }
            sketch.latency_samples.lock().unwrap().push(duration_ms);
            return;
        }
        drop(map);
        let mut map = self.routes.write().unwrap();
        let sketch = map
            .entry(route.to_string())
            .or_insert_with(RouteSketch::new);
        sketch.requests.fetch_add(1, Ordering::Relaxed);
        if status >= 500 {
            sketch.errors.fetch_add(1, Ordering::Relaxed);
        }
        sketch.latency_samples.lock().unwrap().push(duration_ms);
    }

    /// Rotate the window: snapshot the current aggregates, hand them
    /// to the insights engine (if attached), then reset the per-route
    /// sketches for the new window. The new window starts at `now_ms`
    /// (aligned to the rotation, not the expiry — a missed rotation
    /// catches up to the present).
    fn rotate(&self, now_ms: u64) {
        let mut map = self.routes.write().unwrap();
        let old_start = self.window_start_ms.swap(now_ms, Ordering::Relaxed);
        // Feed the completed window to the insights engine (if any).
        if old_start != 0 {
            let mut total_requests: u64 = 0;
            let mut total_errors: u64 = 0;
            let mut latency_sum: f64 = 0.0;
            let mut latency_count: u64 = 0;
            for sketch in map.values() {
                let req = sketch.requests.load(Ordering::Relaxed);
                let err = sketch.errors.load(Ordering::Relaxed);
                total_requests += req;
                total_errors += err;
                let mean = sketch.latency_samples.lock().unwrap().mean();
                latency_sum += mean * req as f64;
                latency_count += req;
            }
            let avg_latency = if latency_count > 0 {
                latency_sum / latency_count as f64
            } else {
                0.0
            };
            let window = insights::BaselineWindow {
                ts_ms: old_start as i64,
                requests: total_requests,
                errors: total_errors,
                avg_latency_ms: avg_latency,
            };
            if let Some(engine) = self.insights.read().unwrap().as_ref() {
                engine.observe(window);
            }
        }
        // Reset the per-route sketches for the new window. Clearing
        // the map is simplest and avoids retaining stale routes; the
        // first record of the new window re-creates each route's
        // sketch.
        map.clear();
    }

    /// Snapshot the current window's per-route aggregates. Computes
    /// p50/p95/p99 from the retained latency samples (sort-and-pick,
    /// O(n log n) with n capped at 1000). This is an admin-path
    /// operation, never on the request hot path.
    pub fn snapshot(&self, now_ms: u64) -> LiveSnapshot {
        // Rotate if the window has expired so a snapshot reflects a
        // current (non-stale) window.
        let start = self.window_start_ms.load(Ordering::Relaxed);
        if start == 0 || now_ms >= start + self.window_size_ms {
            self.rotate(now_ms);
        }
        let start = self.window_start_ms.load(Ordering::Relaxed);
        let map = self.routes.read().unwrap();
        let mut routes: Vec<LiveRouteSnapshot> = map
            .iter()
            .map(|(route, sketch)| {
                let requests = sketch.requests.load(Ordering::Relaxed);
                let errors = sketch.errors.load(Ordering::Relaxed);
                let (p50, p95, p99, avg) = {
                    let mut samples = sketch.latency_samples.lock().unwrap();
                    (
                        samples.percentile(0.50),
                        samples.percentile(0.95),
                        samples.percentile(0.99),
                        samples.mean(),
                    )
                };
                LiveRouteSnapshot {
                    route: route.clone(),
                    requests,
                    errors,
                    error_rate: if requests == 0 {
                        0.0
                    } else {
                        errors as f64 / requests as f64
                    },
                    p50_ms: p50,
                    p95_ms: p95,
                    p99_ms: p99,
                    avg_ms: avg,
                }
            })
            .collect();
        routes.sort_by(|a, b| a.route.cmp(&b.route));
        LiveSnapshot {
            window_start_ms: start,
            window_end_ms: start + self.window_size_ms,
            routes,
        }
    }
}

/// The embedded analytics store (DW-043): SQLite file + bounded
/// channel + background writer. Rollup/retention workers are spawned
/// by [`EmbeddedAnalytics::spawn_workers`].
pub struct EmbeddedAnalytics {
    conn: Mutex<rusqlite::Connection>,
    tx: mpsc::Sender<RawRecord>,
    rx: Mutex<Option<mpsc::Receiver<RawRecord>>>,
    /// DW-079: the AI spend record channel (same fire-and-forget
    /// posture as the raw record channel — drop and count on full,
    /// never block the request path).
    spend_tx: mpsc::Sender<AiSpendRecord>,
    spend_rx: Mutex<Option<mpsc::Receiver<AiSpendRecord>>>,
    /// Records dropped on a full SPEND channel (the never-block
    /// counter for the DW-079 path).
    spend_dropped: AtomicU64,
    /// DW-084: the AI governance event channel (same fire-and-forget
    /// posture as the spend channel — drop and count on full, never
    /// block the request path).
    gov_tx: mpsc::Sender<AiGovernanceEvent>,
    gov_rx: Mutex<Option<mpsc::Receiver<AiGovernanceEvent>>>,
    /// Records dropped on a full GOVERNANCE channel (the never-block
    /// counter for the DW-084 path).
    gov_dropped: AtomicU64,
    /// DW-081: the AI prompt log channel (same fire-and-forget
    /// posture as the spend/governance channels — drop and count on
    /// full, never block the request path).
    prompt_log_tx: mpsc::Sender<AiPromptLogRecord>,
    prompt_log_rx: Mutex<Option<mpsc::Receiver<AiPromptLogRecord>>>,
    /// Records dropped on a full PROMPT_LOG channel (the never-block
    /// counter for the DW-081 path).
    prompt_log_dropped: AtomicU64,
    /// DW-081: the prompt log retention window in ms. Records older
    /// than this are deleted by the maintenance tick. 0 = no
    /// retention sweep (the default when logging is off). Atomic so
    /// a reload can update it without blocking the maintainer.
    prompt_log_retention_ms: AtomicI64,
    /// DW-086: the experiment assignment channel (same fire-and-forget
    /// posture as the spend/governance/prompt-log channels — drop and
    /// count on full, never block the request path).
    exp_assign_tx: mpsc::Sender<AiExperimentAssignment>,
    exp_assign_rx: Mutex<Option<mpsc::Receiver<AiExperimentAssignment>>>,
    /// Records dropped on a full EXP_ASSIGN channel (the never-block
    /// counter for the DW-086 assignment path).
    exp_assign_dropped: AtomicU64,
    /// DW-086: the eval result channel (same fire-and-forget posture
    /// — the admin eval runner writes results here, and a background
    /// writer drains them into the `ai_eval_results` table).
    eval_result_tx: mpsc::Sender<AiEvalResultRecord>,
    eval_result_rx: Mutex<Option<mpsc::Receiver<AiEvalResultRecord>>>,
    /// Records dropped on a full EVAL_RESULT channel.
    eval_result_dropped: AtomicU64,
    /// DW-086: the feedback channel (same fire-and-forget posture —
    /// the admin feedback endpoint writes records here, and a
    /// background writer drains them into the `ai_feedback` table).
    feedback_tx: mpsc::Sender<AiFeedbackRecord>,
    feedback_rx: Mutex<Option<mpsc::Receiver<AiFeedbackRecord>>>,
    /// Records dropped on a full FEEDBACK channel.
    feedback_dropped: AtomicU64,
    /// DW-087: the MCP tool call channel (same fire-and-forget
    /// posture — drop and count on full, never block the request
    /// path).
    mcp_tx: mpsc::Sender<McpToolCallRecord>,
    mcp_rx: Mutex<Option<mpsc::Receiver<McpToolCallRecord>>>,
    /// Records dropped on a full MCP channel (the never-block
    /// counter for the DW-087 path).
    mcp_dropped: AtomicU64,
    /// Retention config: [raw, 1m, 5m, 1h, 1d] in ms.
    retention_ms: [i64; 5],
    /// Flush tick (ms) — the writer's maximum batch latency.
    flush_ms: u64,
    /// Records dropped on a full channel (the never-block counter).
    dropped: AtomicU64,
    /// DW-092: live in-process sketches (sub-second-freshness per-route
    /// rolling window). None when `analytics.live_sketches` is absent
    /// or disabled — the `GET /analytics/live` endpoint answers
    /// `analytics_not_configured` in that case. Updated synchronously
    /// in [`EmbeddedAnalytics::record`].
    live: Mutex<Option<Arc<LiveSketches>>>,
    /// DW-092: the ML traffic insights engine (EWMA forecasting +
    /// seasonal-baseline anomaly detection). None when
    /// `analytics.insights` is absent or both features are disabled —
    /// the `GET /analytics/forecast` and `GET /analytics/anomalies`
    /// endpoints answer `analytics_not_configured` in that case. Fed
    /// by the live-sketch window rotation.
    insights: Mutex<Option<Arc<insights::InsightsEngine>>>,
}

impl EmbeddedAnalytics {
    /// Open (or create) the analytics database at `path`, apply
    /// migrations, and return the store with its channel wired. The
    /// writer is NOT started here — see
    /// [`EmbeddedAnalytics::spawn_workers`]. `prompt_log_retention_ms`
    /// is the DW-081 prompt log retention window (0 = no sweep).
    pub fn open(
        path: &str,
        retention_ms: [i64; 5],
        flush_ms: u64,
        prompt_log_retention_ms: i64,
    ) -> rusqlite::Result<Arc<Self>> {
        let conn = rusqlite::Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        schema::migrate(&conn)?;
        let (tx, rx) = mpsc::channel(CHANNEL_CAP);
        let (spend_tx, spend_rx) = mpsc::channel(CHANNEL_CAP);
        let (gov_tx, gov_rx) = mpsc::channel(CHANNEL_CAP);
        let (prompt_log_tx, prompt_log_rx) = mpsc::channel(CHANNEL_CAP);
        let (exp_assign_tx, exp_assign_rx) = mpsc::channel(CHANNEL_CAP);
        let (eval_result_tx, eval_result_rx) = mpsc::channel(CHANNEL_CAP);
        let (feedback_tx, feedback_rx) = mpsc::channel(CHANNEL_CAP);
        let (mcp_tx, mcp_rx) = mpsc::channel(CHANNEL_CAP);
        Ok(Arc::new(EmbeddedAnalytics {
            conn: Mutex::new(conn),
            rx: Mutex::new(Some(rx)),
            tx,
            spend_tx,
            spend_rx: Mutex::new(Some(spend_rx)),
            spend_dropped: AtomicU64::new(0),
            gov_tx,
            gov_rx: Mutex::new(Some(gov_rx)),
            gov_dropped: AtomicU64::new(0),
            prompt_log_tx,
            prompt_log_rx: Mutex::new(Some(prompt_log_rx)),
            prompt_log_dropped: AtomicU64::new(0),
            prompt_log_retention_ms: AtomicI64::new(prompt_log_retention_ms),
            exp_assign_tx,
            exp_assign_rx: Mutex::new(Some(exp_assign_rx)),
            exp_assign_dropped: AtomicU64::new(0),
            eval_result_tx,
            eval_result_rx: Mutex::new(Some(eval_result_rx)),
            eval_result_dropped: AtomicU64::new(0),
            feedback_tx,
            feedback_rx: Mutex::new(Some(feedback_rx)),
            feedback_dropped: AtomicU64::new(0),
            mcp_tx,
            mcp_rx: Mutex::new(Some(mcp_rx)),
            mcp_dropped: AtomicU64::new(0),
            retention_ms,
            flush_ms,
            dropped: AtomicU64::new(0),
            live: Mutex::new(None),
            insights: Mutex::new(None),
        }))
    }

    /// Spawn the writer and rollup/retention workers. Exactly one set
    /// per store (the receiver is taken once; a second call returns an
    /// empty set and logs). Both stop on `shutdown`; the writer drains
    /// what is already queued first, then performs a final rollup and
    /// retention pass so a clean restart loses nothing.
    pub fn spawn_workers(
        self: &Arc<Self>,
        shutdown: tokio::sync::watch::Receiver<()>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let Some(mut rx) = self.rx.lock().unwrap().take() else {
            tracing::error!(
                code = "analytics_workers_already_running",
                "analytics workers already spawned for this store; ignoring"
            );
            return Vec::new();
        };
        // DW-079: take the spend receiver alongside the raw receiver —
        // a second call returns nothing for either.
        let spend_rx_opt = self.spend_rx.lock().unwrap().take();
        // DW-084: take the governance receiver alongside the others.
        let gov_rx_opt = self.gov_rx.lock().unwrap().take();
        // DW-081: take the prompt log receiver alongside the others.
        let prompt_log_rx_opt = self.prompt_log_rx.lock().unwrap().take();
        // DW-086: take the experiment assignment, eval result, and
        // feedback receivers alongside the others.
        let exp_assign_rx_opt = self.exp_assign_rx.lock().unwrap().take();
        let eval_result_rx_opt = self.eval_result_rx.lock().unwrap().take();
        let feedback_rx_opt = self.feedback_rx.lock().unwrap().take();
        // DW-087: take the MCP tool call receiver alongside the others.
        let mcp_rx_opt = self.mcp_rx.lock().unwrap().take();
        let mut writer_shutdown = shutdown.clone();
        let writer = {
            let store = Arc::clone(self);
            tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_millis(store.flush_ms));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut batch: Vec<RawRecord> = Vec::with_capacity(BATCH_MAX);
                loop {
                    let drained = tokio::select! {
                        m = rx.recv() => match m {
                            Some(r) => {
                                batch.push(r);
                                batch.len() >= BATCH_MAX
                            }
                            None => {
                                // Channel closed (store dropped): final
                                // flush and stop.
                                store.flush(&batch);
                                return;
                            }
                        },
                        _ = tick.tick() => true,
                        _ = writer_shutdown.changed() => {
                            // Drain what is already queued, then stop.
                            while let Ok(r) = rx.try_recv() {
                                batch.push(r);
                            }
                            store.flush(&batch);
                            store.maintain();
                            return;
                        }
                    };
                    if drained {
                        store.flush(&batch);
                        batch.clear();
                    }
                }
            })
        };
        // DW-079: the spend writer — same fire-and-forget batched
        // transaction shape as the raw writer, draining the spend
        // channel into the `ai_spend` table.
        let spend_writer = if let Some(mut spend_rx) = spend_rx_opt {
            let store = Arc::clone(self);
            let mut spend_shutdown = shutdown.clone();
            Some(tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_millis(store.flush_ms));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut batch: Vec<AiSpendRecord> = Vec::with_capacity(BATCH_MAX);
                loop {
                    let drained = tokio::select! {
                        m = spend_rx.recv() => match m {
                            Some(r) => {
                                batch.push(r);
                                batch.len() >= BATCH_MAX
                            }
                            None => {
                                store.flush_spend(&batch);
                                return;
                            }
                        },
                        _ = tick.tick() => true,
                        _ = spend_shutdown.changed() => {
                            while let Ok(r) = spend_rx.try_recv() {
                                batch.push(r);
                            }
                            store.flush_spend(&batch);
                            return;
                        }
                    };
                    if drained {
                        store.flush_spend(&batch);
                        batch.clear();
                    }
                }
            }))
        } else {
            None
        };
        // DW-084: the governance event writer — same fire-and-forget
        // batched transaction shape as the spend writer, draining the
        // governance channel into the `ai_governance_events` table.
        let gov_writer = if let Some(mut gov_rx) = gov_rx_opt {
            let store = Arc::clone(self);
            let mut gov_shutdown = shutdown.clone();
            Some(tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_millis(store.flush_ms));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut batch: Vec<AiGovernanceEvent> = Vec::with_capacity(BATCH_MAX);
                loop {
                    let drained = tokio::select! {
                        m = gov_rx.recv() => match m {
                            Some(r) => {
                                batch.push(r);
                                batch.len() >= BATCH_MAX
                            }
                            None => {
                                store.flush_governance(&batch);
                                return;
                            }
                        },
                        _ = tick.tick() => true,
                        _ = gov_shutdown.changed() => {
                            while let Ok(r) = gov_rx.try_recv() {
                                batch.push(r);
                            }
                            store.flush_governance(&batch);
                            return;
                        }
                    };
                    if drained {
                        store.flush_governance(&batch);
                        batch.clear();
                    }
                }
            }))
        } else {
            None
        };
        // DW-081: the prompt log writer — same fire-and-forget batched
        // transaction shape as the governance writer, draining the
        // prompt log channel into the `ai_prompt_logs` table.
        let prompt_log_writer = if let Some(mut prompt_log_rx) = prompt_log_rx_opt {
            let store = Arc::clone(self);
            let mut prompt_log_shutdown = shutdown.clone();
            Some(tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_millis(store.flush_ms));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut batch: Vec<AiPromptLogRecord> = Vec::with_capacity(BATCH_MAX);
                loop {
                    let drained = tokio::select! {
                        m = prompt_log_rx.recv() => match m {
                            Some(r) => {
                                batch.push(r);
                                batch.len() >= BATCH_MAX
                            }
                            None => {
                                store.flush_prompt_log(&batch);
                                return;
                            }
                        },
                        _ = tick.tick() => true,
                        _ = prompt_log_shutdown.changed() => {
                            while let Ok(r) = prompt_log_rx.try_recv() {
                                batch.push(r);
                            }
                            store.flush_prompt_log(&batch);
                            return;
                        }
                    };
                    if drained {
                        store.flush_prompt_log(&batch);
                        batch.clear();
                    }
                }
            }))
        } else {
            None
        };
        // DW-086: the experiment assignment writer — same
        // fire-and-forget batched transaction shape, draining the
        // assignment channel into the `ai_experiment_assignments` table.
        let exp_assign_writer = if let Some(mut exp_assign_rx) = exp_assign_rx_opt {
            let store = Arc::clone(self);
            let mut exp_assign_shutdown = shutdown.clone();
            Some(tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_millis(store.flush_ms));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut batch: Vec<AiExperimentAssignment> = Vec::with_capacity(BATCH_MAX);
                loop {
                    let drained = tokio::select! {
                        m = exp_assign_rx.recv() => match m {
                            Some(r) => {
                                batch.push(r);
                                batch.len() >= BATCH_MAX
                            }
                            None => {
                                store.flush_exp_assign(&batch);
                                return;
                            }
                        },
                        _ = tick.tick() => true,
                        _ = exp_assign_shutdown.changed() => {
                            while let Ok(r) = exp_assign_rx.try_recv() {
                                batch.push(r);
                            }
                            store.flush_exp_assign(&batch);
                            return;
                        }
                    };
                    if drained {
                        store.flush_exp_assign(&batch);
                        batch.clear();
                    }
                }
            }))
        } else {
            None
        };
        // DW-086: the eval result writer — same fire-and-forget
        // batched transaction shape, draining the eval result channel
        // into the `ai_eval_results` table.
        let eval_result_writer = if let Some(mut eval_result_rx) = eval_result_rx_opt {
            let store = Arc::clone(self);
            let mut eval_result_shutdown = shutdown.clone();
            Some(tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_millis(store.flush_ms));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut batch: Vec<AiEvalResultRecord> = Vec::with_capacity(BATCH_MAX);
                loop {
                    let drained = tokio::select! {
                        m = eval_result_rx.recv() => match m {
                            Some(r) => {
                                batch.push(r);
                                batch.len() >= BATCH_MAX
                            }
                            None => {
                                store.flush_eval_result(&batch);
                                return;
                            }
                        },
                        _ = tick.tick() => true,
                        _ = eval_result_shutdown.changed() => {
                            while let Ok(r) = eval_result_rx.try_recv() {
                                batch.push(r);
                            }
                            store.flush_eval_result(&batch);
                            return;
                        }
                    };
                    if drained {
                        store.flush_eval_result(&batch);
                        batch.clear();
                    }
                }
            }))
        } else {
            None
        };
        // DW-086: the feedback writer — same fire-and-forget batched
        // transaction shape, draining the feedback channel into the
        // `ai_feedback` table.
        let feedback_writer = if let Some(mut feedback_rx) = feedback_rx_opt {
            let store = Arc::clone(self);
            let mut feedback_shutdown = shutdown.clone();
            Some(tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_millis(store.flush_ms));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut batch: Vec<AiFeedbackRecord> = Vec::with_capacity(BATCH_MAX);
                loop {
                    let drained = tokio::select! {
                        m = feedback_rx.recv() => match m {
                            Some(r) => {
                                batch.push(r);
                                batch.len() >= BATCH_MAX
                            }
                            None => {
                                store.flush_feedback(&batch);
                                return;
                            }
                        },
                        _ = tick.tick() => true,
                        _ = feedback_shutdown.changed() => {
                            while let Ok(r) = feedback_rx.try_recv() {
                                batch.push(r);
                            }
                            store.flush_feedback(&batch);
                            return;
                        }
                    };
                    if drained {
                        store.flush_feedback(&batch);
                        batch.clear();
                    }
                }
            }))
        } else {
            None
        };
        // DW-087: the MCP tool call writer — same fire-and-forget
        // batched transaction shape, draining the MCP channel into
        // the `mcp_tool_calls` table.
        let mcp_writer = if let Some(mut mcp_rx) = mcp_rx_opt {
            let store = Arc::clone(self);
            let mut mcp_shutdown = shutdown.clone();
            Some(tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_millis(store.flush_ms));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut batch: Vec<McpToolCallRecord> = Vec::with_capacity(BATCH_MAX);
                loop {
                    let drained = tokio::select! {
                        m = mcp_rx.recv() => match m {
                            Some(r) => {
                                batch.push(r);
                                batch.len() >= BATCH_MAX
                            }
                            None => {
                                store.flush_mcp_tool_call(&batch);
                                return;
                            }
                        },
                        _ = tick.tick() => true,
                        _ = mcp_shutdown.changed() => {
                            while let Ok(r) = mcp_rx.try_recv() {
                                batch.push(r);
                            }
                            store.flush_mcp_tool_call(&batch);
                            return;
                        }
                    };
                    if drained {
                        store.flush_mcp_tool_call(&batch);
                        batch.clear();
                    }
                }
            }))
        } else {
            None
        };
        let maintainer = {
            let store = Arc::clone(self);
            let mut shutdown2 = shutdown.clone();
            tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_millis(ROLLUP_INTERVAL_MS));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = tick.tick() => store.maintain(),
                        _ = shutdown2.changed() => return,
                    }
                }
            })
        };
        let mut handles = vec![writer, maintainer];
        if let Some(h) = spend_writer {
            handles.push(h);
        }
        if let Some(h) = gov_writer {
            handles.push(h);
        }
        if let Some(h) = prompt_log_writer {
            handles.push(h);
        }
        if let Some(h) = exp_assign_writer {
            handles.push(h);
        }
        if let Some(h) = eval_result_writer {
            handles.push(h);
        }
        if let Some(h) = feedback_writer {
            handles.push(h);
        }
        if let Some(h) = mcp_writer {
            handles.push(h);
        }
        handles
    }

    /// One batched transaction of raw INSERTs. Errors are logged and
    /// swallowed (a failed analytics batch must never propagate into
    /// the worker loop) — the records are lost, the counter is not
    /// bumped (they were accepted; the DISK failed).
    fn flush(&self, batch: &[RawRecord]) {
        if batch.is_empty() {
            return;
        }
        let conn = self.conn.lock().unwrap();
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_batch_begin_failed",
                    "analytics batch lost: {e}"
                );
                return;
            }
        };
        let mut stmt = match tx.prepare(
            "INSERT INTO raw (ts_ms, request_id, correlation_id, listener,
                              route, consumer, upstream, method, status,
                              status_class, duration_ms, attempts,
                              rate_limited, broken, shed, dims)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16)",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_batch_prepare_failed",
                    "analytics batch lost: {e}"
                );
                return;
            }
        };
        let mut ok = true;
        for r in batch {
            let res = stmt.execute(rusqlite::params![
                r.ts_ms,
                r.request_id,
                r.correlation_id,
                r.listener,
                r.route,
                r.consumer,
                r.upstream,
                r.method,
                r.status,
                r.status_class,
                r.duration_ms,
                r.attempts,
                r.rate_limited,
                r.broken,
                r.shed,
                r.dims,
            ]);
            if let Err(e) = res {
                tracing::warn!(
                    code = "analytics_insert_failed",
                    "analytics record lost: {e}"
                );
                ok = false;
            }
        }
        drop(stmt);
        if ok || !batch.is_empty() {
            // Commit even with per-row failures: the surviving rows are
            // valid analytics input.
            if let Err(e) = tx.commit() {
                tracing::warn!(
                    code = "analytics_commit_failed",
                    "analytics batch lost: {e}"
                );
            }
        }
    }

    /// One batched transaction of `ai_spend` INSERTs (DW-079). Same
    /// swallow-and-log posture as [`flush`]: a failed batch is lost,
    /// the counter is not bumped (the records were accepted; the DISK
    /// failed).
    fn flush_spend(&self, batch: &[AiSpendRecord]) {
        if batch.is_empty() {
            return;
        }
        let conn = self.conn.lock().unwrap();
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_spend_batch_begin_failed",
                    "ai_spend batch lost: {e}"
                );
                return;
            }
        };
        let mut stmt = match tx.prepare(
            "INSERT INTO ai_spend (ts_ms, consumer, consumer_type, team, provider, model, version,
                                   prompt_tokens, completion_tokens, total_tokens, cost_micros)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_spend_batch_prepare_failed",
                    "ai_spend batch lost: {e}"
                );
                return;
            }
        };
        let mut ok = true;
        for r in batch {
            let res = stmt.execute(rusqlite::params![
                r.ts_ms,
                r.consumer,
                r.consumer_type,
                r.team,
                r.provider,
                r.model,
                r.version,
                r.prompt_tokens as i64,
                r.completion_tokens as i64,
                r.total_tokens as i64,
                r.cost_micros as i64,
            ]);
            if let Err(e) = res {
                tracing::warn!(
                    code = "analytics_spend_insert_failed",
                    "ai_spend record lost: {e}"
                );
                ok = false;
            }
        }
        drop(stmt);
        if ok || !batch.is_empty() {
            if let Err(e) = tx.commit() {
                tracing::warn!(
                    code = "analytics_spend_commit_failed",
                    "ai_spend batch lost: {e}"
                );
            }
        }
    }

    /// One batched transaction of `ai_governance_events` INSERTs
    /// (DW-084). Same swallow-and-log posture as [`flush_spend`]: a
    /// failed batch is lost, the counter is not bumped (the records
    /// were accepted; the DISK failed).
    fn flush_governance(&self, batch: &[AiGovernanceEvent]) {
        if batch.is_empty() {
            return;
        }
        let conn = self.conn.lock().unwrap();
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_governance_batch_begin_failed",
                    "ai_governance_events batch lost: {e}"
                );
                return;
            }
        };
        let mut stmt = match tx.prepare(
            "INSERT INTO ai_governance_events \
             (ts_ms, consumer, team, model, verdict, reason) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_governance_batch_prepare_failed",
                    "ai_governance_events batch lost: {e}"
                );
                return;
            }
        };
        let mut ok = true;
        for r in batch {
            let res = stmt.execute(rusqlite::params![
                r.ts_ms, r.consumer, r.team, r.model, r.verdict, r.reason,
            ]);
            if let Err(e) = res {
                tracing::warn!(
                    code = "analytics_governance_insert_failed",
                    "ai_governance_events record lost: {e}"
                );
                ok = false;
            }
        }
        drop(stmt);
        if ok || !batch.is_empty() {
            if let Err(e) = tx.commit() {
                tracing::warn!(
                    code = "analytics_governance_commit_failed",
                    "ai_governance_events batch lost: {e}"
                );
            }
        }
    }

    /// One batched transaction of `ai_prompt_logs` INSERTs (DW-081).
    /// Same swallow-and-log posture as [`flush_governance`]: a failed
    /// batch is lost, the counter is not bumped (the records were
    /// accepted; the DISK failed).
    fn flush_prompt_log(&self, batch: &[AiPromptLogRecord]) {
        if batch.is_empty() {
            return;
        }
        let conn = self.conn.lock().unwrap();
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_prompt_log_batch_begin_failed",
                    "ai_prompt_logs batch lost: {e}"
                );
                return;
            }
        };
        let mut stmt = match tx.prepare(
            "INSERT INTO ai_prompt_logs \
             (ts_ms, request_id, consumer, route, provider, model, version, \
              prompt_json, response_json, stream) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_prompt_log_batch_prepare_failed",
                    "ai_prompt_logs batch lost: {e}"
                );
                return;
            }
        };
        let mut ok = true;
        for r in batch {
            let res = stmt.execute(rusqlite::params![
                r.ts_ms,
                r.request_id,
                r.consumer,
                r.route,
                r.provider,
                r.model,
                r.version,
                r.prompt_json,
                r.response_json,
                r.stream as i64,
            ]);
            if let Err(e) = res {
                tracing::warn!(
                    code = "analytics_prompt_log_insert_failed",
                    "ai_prompt_logs record lost: {e}"
                );
                ok = false;
            }
        }
        drop(stmt);
        if ok || !batch.is_empty() {
            if let Err(e) = tx.commit() {
                tracing::warn!(
                    code = "analytics_prompt_log_commit_failed",
                    "ai_prompt_logs batch lost: {e}"
                );
            }
        }
    }

    /// One batched transaction of `ai_experiment_assignments` INSERTs
    /// (DW-086). Same swallow-and-log posture as the other flush
    /// methods.
    fn flush_exp_assign(&self, batch: &[AiExperimentAssignment]) {
        if batch.is_empty() {
            return;
        }
        let conn = self.conn.lock().unwrap();
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_exp_assign_batch_begin_failed",
                    "ai_experiment_assignments batch lost: {e}"
                );
                return;
            }
        };
        let mut stmt = match tx.prepare(
            "INSERT INTO ai_experiment_assignments \
             (ts_ms, request_id, experiment, variant, model, consumer) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_exp_assign_batch_prepare_failed",
                    "ai_experiment_assignments batch lost: {e}"
                );
                return;
            }
        };
        let mut ok = true;
        for r in batch {
            let res = stmt.execute(rusqlite::params![
                r.ts_ms,
                r.request_id,
                r.experiment,
                r.variant,
                r.model,
                r.consumer,
            ]);
            if let Err(e) = res {
                tracing::warn!(
                    code = "analytics_exp_assign_insert_failed",
                    "ai_experiment_assignments record lost: {e}"
                );
                ok = false;
            }
        }
        drop(stmt);
        if ok || !batch.is_empty() {
            if let Err(e) = tx.commit() {
                tracing::warn!(
                    code = "analytics_exp_assign_commit_failed",
                    "ai_experiment_assignments batch lost: {e}"
                );
            }
        }
    }

    /// One batched transaction of `ai_eval_results` INSERTs (DW-086).
    /// Same swallow-and-log posture as the other flush methods.
    fn flush_eval_result(&self, batch: &[AiEvalResultRecord]) {
        if batch.is_empty() {
            return;
        }
        let conn = self.conn.lock().unwrap();
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_eval_result_batch_begin_failed",
                    "ai_eval_results batch lost: {e}"
                );
                return;
            }
        };
        let mut stmt = match tx.prepare(
            "INSERT INTO ai_eval_results \
             (ts_ms, eval_name, model, variant, prompt_version, case_index, \
              input, expected, actual, passed, scorer, latency_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_eval_result_batch_prepare_failed",
                    "ai_eval_results batch lost: {e}"
                );
                return;
            }
        };
        let mut ok = true;
        for r in batch {
            let res = stmt.execute(rusqlite::params![
                r.ts_ms,
                r.eval_name,
                r.model,
                r.variant,
                r.prompt_version,
                r.case_index as i64,
                r.input,
                r.expected,
                r.actual,
                r.passed as i64,
                r.scorer,
                r.latency_ms,
            ]);
            if let Err(e) = res {
                tracing::warn!(
                    code = "analytics_eval_result_insert_failed",
                    "ai_eval_results record lost: {e}"
                );
                ok = false;
            }
        }
        drop(stmt);
        if ok || !batch.is_empty() {
            if let Err(e) = tx.commit() {
                tracing::warn!(
                    code = "analytics_eval_result_commit_failed",
                    "ai_eval_results batch lost: {e}"
                );
            }
        }
    }

    /// One batched transaction of `ai_feedback` INSERTs (DW-086).
    /// Same swallow-and-log posture as the other flush methods.
    fn flush_feedback(&self, batch: &[AiFeedbackRecord]) {
        if batch.is_empty() {
            return;
        }
        let conn = self.conn.lock().unwrap();
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_feedback_batch_begin_failed",
                    "ai_feedback batch lost: {e}"
                );
                return;
            }
        };
        let mut stmt = match tx.prepare(
            "INSERT INTO ai_feedback \
             (ts_ms, request_id, label, comment, consumer, model) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_feedback_batch_prepare_failed",
                    "ai_feedback batch lost: {e}"
                );
                return;
            }
        };
        let mut ok = true;
        for r in batch {
            let res = stmt.execute(rusqlite::params![
                r.ts_ms,
                r.request_id,
                r.label,
                r.comment,
                r.consumer,
                r.model,
            ]);
            if let Err(e) = res {
                tracing::warn!(
                    code = "analytics_feedback_insert_failed",
                    "ai_feedback record lost: {e}"
                );
                ok = false;
            }
        }
        drop(stmt);
        if ok || !batch.is_empty() {
            if let Err(e) = tx.commit() {
                tracing::warn!(
                    code = "analytics_feedback_commit_failed",
                    "ai_feedback batch lost: {e}"
                );
            }
        }
    }

    /// One batched transaction of `mcp_tool_calls` INSERTs (DW-087).
    /// Same swallow-and-log posture as the other flush methods.
    fn flush_mcp_tool_call(&self, batch: &[McpToolCallRecord]) {
        if batch.is_empty() {
            return;
        }
        let conn = self.conn.lock().unwrap();
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_mcp_batch_begin_failed",
                    "mcp_tool_calls batch lost: {e}"
                );
                return;
            }
        };
        let mut stmt = match tx.prepare(
            "INSERT INTO mcp_tool_calls \
             (ts_ms, request_id, session_id, consumer, consumer_type, tool_name, allowed, \
              duration_ms, error_code, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_mcp_batch_prepare_failed",
                    "mcp_tool_calls batch lost: {e}"
                );
                return;
            }
        };
        let mut ok = true;
        for r in batch {
            let res = stmt.execute(rusqlite::params![
                r.ts_ms,
                r.request_id,
                r.session_id,
                r.consumer,
                r.consumer_type,
                r.tool_name,
                r.allowed as i64,
                r.duration_ms,
                r.error_code,
                r.status,
            ]);
            if let Err(e) = res {
                tracing::warn!(
                    code = "analytics_mcp_insert_failed",
                    "mcp_tool_calls record lost: {e}"
                );
                ok = false;
            }
        }
        drop(stmt);
        if ok || !batch.is_empty() {
            if let Err(e) = tx.commit() {
                tracing::warn!(
                    code = "analytics_mcp_commit_failed",
                    "mcp_tool_calls batch lost: {e}"
                );
            }
        }
    }

    /// One rollup + retention pass (cursor-guarded; safe to run at any
    /// time, from the ticker or shutdown).
    fn maintain(&self) {
        let conn = self.conn.lock().unwrap();
        let now = now_ms();
        let mut rolled = 0usize;
        match rollup::roll_raw_to_1m(&conn, now, ROLLUP_GRACE_MS) {
            Ok(n) => rolled = n,
            Err(e) => tracing::warn!(
                code = "analytics_rollup_failed",
                "raw->1m rollup failed: {e}"
            ),
        }
        for stage in 0..rollup::GRANULARITIES_MS.len() - 1 {
            if let Err(e) = rollup::roll_cascade(&conn, stage, now, ROLLUP_GRACE_MS) {
                tracing::warn!(
                    code = "analytics_cascade_failed",
                    "cascade stage {stage} failed: {e}"
                );
            }
        }
        if let Err(e) = rollup::sweep_retention(
            &conn,
            self.retention_ms[0],
            self.retention_ms[1..].try_into().unwrap(),
            now,
            256,
        ) {
            tracing::warn!(
                code = "analytics_retention_failed",
                "retention sweep failed: {e}"
            );
        } else if rolled > 0 {
            tracing::debug!(
                code = "analytics_rollup",
                windows = rolled,
                "rollup pass complete"
            );
        }
        // DW-081: prompt log retention sweep. Records older than the
        // configured retention window are deleted. A retention of 0
        // means no sweep (logging is off or unconfigured).
        let retention_ms = self.prompt_log_retention_ms.load(Ordering::Relaxed);
        if retention_ms > 0 {
            let cutoff = now.saturating_sub(retention_ms);
            if let Err(e) = conn.execute("DELETE FROM ai_prompt_logs WHERE ts_ms < ?1", [cutoff]) {
                tracing::warn!(
                    code = "analytics_prompt_log_retention_failed",
                    "ai_prompt_logs retention sweep failed: {e}"
                );
            }
        }
    }

    /// Records accepted by `record` but dropped (channel full). The
    /// honest loss counter for the never-block posture.
    pub fn dropped_records(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Run a short locked access against the store's connection (the
    /// admin read path, and the exports ledger's single-row record
    /// writes). The connection is shared with the writer behind one
    /// mutex; access is sized for the "week under 100 ms" contract, so
    /// contention is short and rare.
    pub fn query<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        let conn = self.conn.lock().unwrap();
        f(&conn)
    }

    /// The request-completion hot path (DW-043): fire-and-forget record
    /// of one finished request. NEVER blocks — a bounded-channel
    /// `try_send` that drops and counts on full. DW-092: also feeds the
    /// live in-process sketches (synchronous, lock-free counts + a
    /// short mutex over a capped sample vector) when attached.
    pub fn record(&self, rec: &AccessRecord) {
        let ts = now_ms();
        // DW-092: feed the live sketches synchronously (never blocks —
        // atomics for counts, a short mutex over a capped vector).
        if let Ok(live) = self.live.lock() {
            if let Some(sketches) = live.as_ref() {
                sketches.record(&rec.route, rec.status, rec.duration_ms, ts as u64);
            }
        }
        let raw = RawRecord::from(rec, ts);
        self.offer(raw);
    }

    /// Attach the live sketches (DW-092). Called once during startup
    /// wiring (dwara-bin) when `analytics.live_sketches.enabled`. The
    /// insights engine, when also configured, is attached to the
    /// sketches so window rotations feed it.
    pub fn set_live_sketches(&self, sketches: Arc<LiveSketches>) {
        *self.live.lock().unwrap() = Some(sketches);
    }

    /// Attach the insights engine (DW-092). Called once during startup
    /// wiring when `analytics.insights.forecast` or
    /// `analytics.insights.anomaly_baseline`. Also wired into the live
    /// sketches so window rotations feed the engine.
    pub fn set_insights(&self, engine: Arc<insights::InsightsEngine>) {
        if let Ok(live) = self.live.lock() {
            if let Some(sketches) = live.as_ref() {
                sketches.set_insights(Arc::clone(&engine));
            }
        }
        *self.insights.lock().unwrap() = Some(engine);
    }

    /// The live sketches store when attached (DW-092; None = the
    /// `GET /analytics/live` endpoint answers
    /// `analytics_not_configured`).
    pub fn live_sketches(&self) -> Option<Arc<LiveSketches>> {
        self.live.lock().unwrap().as_ref().map(Arc::clone)
    }

    /// The insights engine when attached (DW-092; None = the
    /// `GET /analytics/forecast` and `GET /analytics/anomalies`
    /// endpoints answer `analytics_not_configured`).
    pub fn insights_engine(&self) -> Option<Arc<insights::InsightsEngine>> {
        self.insights.lock().unwrap().as_ref().map(Arc::clone)
    }

    /// Snapshot the current live window (DW-092). Returns None when
    /// live sketches are not attached.
    pub fn live_snapshot(&self) -> Option<LiveSnapshot> {
        let live = self.live.lock().unwrap();
        live.as_ref().map(|s| s.snapshot(now_ms() as u64))
    }

    /// Forecast the next window (DW-092). Returns None when the
    /// insights engine is not attached or forecasting is disabled.
    pub fn insights_forecast(&self) -> Option<insights::ForecastResult> {
        let engine = self.insights.lock().unwrap();
        engine.as_ref().map(|e| e.forecast(now_ms()))
    }

    /// Detect whether the current live window is anomalous (DW-092).
    /// Builds a `BaselineWindow` from the current live snapshot and
    /// hands it to the insights engine. Returns None when the insights
    /// engine is not attached or anomaly detection is disabled.
    pub fn insights_detect_anomaly(&self) -> Option<insights::AnomalyResult> {
        // Clone the engine Arc and drop the insights lock BEFORE
        // acquiring the live lock — `set_insights` takes the live lock
        // first, so locking insights-then-live here would invert the
        // order and risk a deadlock.
        let engine = {
            let guard = self.insights.lock().unwrap();
            guard.as_ref()?.clone()
        };
        // Build the current window from the live snapshot so the
        // anomaly check reflects the in-flight window, not a stale
        // rotation.
        let snapshot = self.live_snapshot()?;
        let mut total_requests: u64 = 0;
        let mut total_errors: u64 = 0;
        let mut latency_sum: f64 = 0.0;
        let mut latency_count: u64 = 0;
        for r in &snapshot.routes {
            total_requests += r.requests;
            total_errors += r.errors;
            latency_sum += r.avg_ms * r.requests as f64;
            latency_count += r.requests;
        }
        let avg_latency = if latency_count > 0 {
            latency_sum / latency_count as f64
        } else {
            0.0
        };
        let current = insights::BaselineWindow {
            ts_ms: snapshot.window_start_ms as i64,
            requests: total_requests,
            errors: total_errors,
            avg_latency_ms: avg_latency,
        };
        Some(engine.detect_anomaly(&current))
    }

    /// Offer one raw record to the writer channel; drop-and-count on a
    /// full channel (the never-block policy shared by the hot path and
    /// the extension-seam impl below).
    fn offer(&self, raw: RawRecord) {
        if self.tx.try_send(raw).is_err() {
            let n = self.dropped.fetch_add(1, Ordering::Relaxed);
            if n.is_multiple_of(4096) {
                tracing::warn!(
                    code = "analytics_channel_full",
                    total_dropped = n + 1,
                    "analytics channel full; dropping records (never blocking the dataplane)"
                );
            }
        }
    }

    /// The AI spend hot path (DW-079): fire-and-forget record of one
    /// completed AI request's spend dimensions. NEVER blocks — a
    /// bounded-channel `try_send` that drops and counts on full (the
    /// same never-block posture as [`Self::record`]).
    pub fn offer_ai_spend(&self, rec: AiSpendRecord) {
        if self.spend_tx.try_send(rec).is_err() {
            let n = self.spend_dropped.fetch_add(1, Ordering::Relaxed);
            if n.is_multiple_of(4096) {
                tracing::warn!(
                    code = "analytics_spend_channel_full",
                    total_dropped = n + 1,
                    "ai_spend channel full; dropping records (never blocking the dataplane)"
                );
            }
        }
    }

    /// AI spend records accepted by [`Self::offer_ai_spend`] but dropped
    /// (channel full). The honest loss counter for the DW-079 path.
    pub fn dropped_spend_records(&self) -> u64 {
        self.spend_dropped.load(Ordering::Relaxed)
    }

    /// The AI governance event hot path (DW-084): fire-and-forget
    /// record of one governance check outcome. NEVER blocks — a
    /// bounded-channel `try_send` that drops and counts on full (the
    /// same never-block posture as [`Self::offer_ai_spend`]).
    pub fn offer_ai_governance_event(&self, rec: AiGovernanceEvent) {
        if self.gov_tx.try_send(rec).is_err() {
            let n = self.gov_dropped.fetch_add(1, Ordering::Relaxed);
            if n.is_multiple_of(4096) {
                tracing::warn!(
                    code = "analytics_governance_channel_full",
                    total_dropped = n + 1,
                    "ai_governance_events channel full; dropping records (never blocking the dataplane)"
                );
            }
        }
    }

    /// AI governance events accepted by
    /// [`Self::offer_ai_governance_event`] but dropped (channel full).
    /// The honest loss counter for the DW-084 path.
    pub fn dropped_governance_events(&self) -> u64 {
        self.gov_dropped.load(Ordering::Relaxed)
    }

    /// The AI prompt log hot path (DW-081): fire-and-forget record of
    /// one captured prompt/response pair (already redacted). NEVER
    /// blocks — a bounded-channel `try_send` that drops and counts on
    /// full (the same never-block posture as
    /// [`Self::offer_ai_governance_event`]).
    pub fn offer_ai_prompt_log(&self, rec: AiPromptLogRecord) {
        if self.prompt_log_tx.try_send(rec).is_err() {
            let n = self.prompt_log_dropped.fetch_add(1, Ordering::Relaxed);
            if n.is_multiple_of(4096) {
                tracing::warn!(
                    code = "analytics_prompt_log_channel_full",
                    total_dropped = n + 1,
                    "ai_prompt_logs channel full; dropping records (never blocking the dataplane)"
                );
            }
        }
    }

    /// AI prompt log records accepted by [`Self::offer_ai_prompt_log`]
    /// but dropped (channel full). The honest loss counter for the
    /// DW-081 path.
    pub fn dropped_prompt_log_records(&self) -> u64 {
        self.prompt_log_dropped.load(Ordering::Relaxed)
    }

    /// Update the prompt log retention window (DW-081). Called on
    /// reload when the logging config changes. A retention of 0
    /// disables the sweep.
    pub fn set_prompt_log_retention_ms(&self, retention_ms: i64) {
        self.prompt_log_retention_ms
            .store(retention_ms, Ordering::Relaxed);
    }

    /// The experiment assignment hot path (DW-086): fire-and-forget
    /// record of one A/B test variant selection. NEVER blocks — a
    /// bounded-channel `try_send` that drops and counts on full.
    pub fn offer_ai_experiment_assignment(&self, rec: AiExperimentAssignment) {
        if self.exp_assign_tx.try_send(rec).is_err() {
            let n = self.exp_assign_dropped.fetch_add(1, Ordering::Relaxed);
            if n.is_multiple_of(4096) {
                tracing::warn!(
                    code = "analytics_exp_assign_channel_full",
                    total_dropped = n + 1,
                    "ai_experiment_assignments channel full; dropping records \
                     (never blocking the dataplane)"
                );
            }
        }
    }

    /// Experiment assignment records accepted but dropped (channel
    /// full). The honest loss counter for the DW-086 assignment path.
    pub fn dropped_exp_assign_records(&self) -> u64 {
        self.exp_assign_dropped.load(Ordering::Relaxed)
    }

    /// The eval result path (DW-086): fire-and-forget record of one
    /// eval case result. NEVER blocks — a bounded-channel `try_send`
    /// that drops and counts on full.
    pub fn offer_ai_eval_result(&self, rec: AiEvalResultRecord) {
        if self.eval_result_tx.try_send(rec).is_err() {
            let n = self.eval_result_dropped.fetch_add(1, Ordering::Relaxed);
            if n.is_multiple_of(4096) {
                tracing::warn!(
                    code = "analytics_eval_result_channel_full",
                    total_dropped = n + 1,
                    "ai_eval_results channel full; dropping records"
                );
            }
        }
    }

    /// Eval result records accepted but dropped (channel full).
    pub fn dropped_eval_result_records(&self) -> u64 {
        self.eval_result_dropped.load(Ordering::Relaxed)
    }

    /// The feedback path (DW-086): fire-and-forget record of one
    /// feedback entry. NEVER blocks — a bounded-channel `try_send`
    /// that drops and counts on full.
    pub fn offer_ai_feedback(&self, rec: AiFeedbackRecord) {
        if self.feedback_tx.try_send(rec).is_err() {
            let n = self.feedback_dropped.fetch_add(1, Ordering::Relaxed);
            if n.is_multiple_of(4096) {
                tracing::warn!(
                    code = "analytics_feedback_channel_full",
                    total_dropped = n + 1,
                    "ai_feedback channel full; dropping records"
                );
            }
        }
    }

    /// Feedback records accepted but dropped (channel full).
    pub fn dropped_feedback_records(&self) -> u64 {
        self.feedback_dropped.load(Ordering::Relaxed)
    }

    /// The MCP tool call hot path (DW-087): fire-and-forget record of
    /// one proxied tool call. NEVER blocks — a bounded-channel
    /// `try_send` that drops and counts on full.
    pub fn offer_mcp_tool_call(&self, rec: McpToolCallRecord) {
        if self.mcp_tx.try_send(rec).is_err() {
            let n = self.mcp_dropped.fetch_add(1, Ordering::Relaxed);
            if n.is_multiple_of(4096) {
                tracing::warn!(
                    code = "analytics_mcp_channel_full",
                    total_dropped = n + 1,
                    "mcp_tool_calls channel full; dropping records (never blocking the dataplane)"
                );
            }
        }
    }

    /// MCP tool call records accepted but dropped (channel full).
    /// The honest loss counter for the DW-087 path.
    pub fn dropped_mcp_tool_call_records(&self) -> u64 {
        self.mcp_dropped.load(Ordering::Relaxed)
    }
}

/// The M1 extension contract (feature analysis 11.4): the embedded
/// store IS an `extensions::analytics::AnalyticsSink`. The trait's
/// failure model allows perpetual `Ok` — "accepted", not "persisted" —
/// which is exactly the drop-and-count policy here (a full channel is
/// the sink's own overload to absorb, not the caller's problem).
#[async_trait::async_trait]
impl crate::extensions::analytics::AnalyticsSink for EmbeddedAnalytics {
    async fn record(
        &self,
        event: crate::extensions::analytics::Event,
    ) -> Result<(), crate::extensions::ExtensionsError> {
        self.offer(RawRecord::from_event(&event));
        Ok(())
    }
}
