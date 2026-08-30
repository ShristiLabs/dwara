//! Configuration schema v1 for the gateway (frozen domain vocabulary).
//!
//! The types in this module model the source form of a dwara configuration
//! file. Compilation into a runtime snapshot is a later concern
//! (config-compile pipeline); here we define strict, self-describing types:
//!
//! - every struct rejects unknown fields (`deny_unknown_fields`),
//! - field order follows declaration order on serialization,
//! - the root type [`Gateway`] exports a JSON Schema via `schemars`.
//!
//! YAML <-> typed conversions are provided by [`parse_gateway`] (YAML text to
//! typed value, with path-precise error messages) and [`gateway_to_yaml`]
//! (typed value back to normalized YAML text). Round-trip guarantee:
//! `parse_gateway(gateway_to_yaml(cfg))` always succeeds and yields a value
//! that serializes to the identical normalized text (stable normalization,
//! not byte-identity with the original input).
//!
//! Submodules carry the parts of the config CONTRACT that are more than
//! serde shapes: [`credentials`] defines the credential selector/stored-hash
//! formats every credential holder must agree on plus the `${...}`
//! secret-reference grammar (DW-045), [`limits`] the numeric
//! bounds validation enforces, [`net`] the trusted-proxy IP/CIDR
//! grammar shared by validation and the runtime matchers,
//! [`versioning`] the HTTP-date and media-type grammar of the API
//! versioning aids (DW-048), and [`transforms`] the JSON-pointer
//! grammar and shapes of the request/response transforms and
//! security-header injection (DW-028). [`cache`] carries the
//! route-scoped response-caching grammar (DW-037).

pub mod cache;
pub mod credentials;
pub mod limits;
pub mod net;
pub mod transforms;
pub mod versioning;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cache::RouteCache;
use transforms::{Masking, SecurityHeaders, Transforms};

/// Error produced when a configuration document fails to parse.
///
/// Carries the dotted path of the offending node (e.g. `listeners[0].port`)
/// and the underlying serde message.
#[derive(Debug)]
pub struct ConfigError {
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "config error at {}: {}", self.path, self.message)
    }
}

impl std::error::Error for ConfigError {}

/// Root of a dwara configuration: one gateway process, N listeners, and one
/// compiled config generation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    /// Entry points the gateway binds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<Listener>,
    /// Match rules routing requests to services.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<Route>,
    /// Logical APIs being exposed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<Service>,
    /// Load-balancing pools.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<Upstream>,
    /// API caller identities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumers: Vec<Consumer>,
    /// Named reusable rule bundles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<Policy>,
    /// Gateway-level (global) policy attachment (#123): names of policies
    /// from the `policies` list that apply to EVERY request the gateway
    /// serves — the LEAST specific link of the frozen precedence chain
    /// consumer > route > service > listener > global. Named
    /// `global_policies` (not `policies`, which is the policy REGISTRY at
    /// this level) so the two roles cannot be confused. All applicable
    /// levels' rules AND together (see the rate-limiter module docs), so a
    /// global policy is an additional constraint on every request, not a
    /// default that more specific levels replace. Global policies also
    /// apply to UNROUTED traffic: a request whose path matches no route
    /// is rate-limited by them before the 404 is answered (the reserved
    /// paths /healthz, /readyz, and /metrics stay exempt).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub global_policies: Vec<String>,
    /// Gateway-level (global) authorization rules (#123): the least
    /// specific link of the authorization precedence chain
    /// consumer > route > service > listener > global (see [`Authz`] for
    /// the rule semantics and the `authz` module for the merge: a deny at
    /// ANY level wins; otherwise the most specific level with rules
    /// governs). Applies to every request that resolved a route
    /// (authorization runs after route resolution per the documented
    /// request-path order). Same validation rules as route-level
    /// authorization; see [`Authz`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authz>,
    /// IP addresses / CIDR ranges of proxies whose `X-Forwarded-For` claims
    /// are trusted (gateway-level; the direct connection peer must be in
    /// this list for an inbound XFF chain to be preserved and extended).
    /// Each entry must be an IP address (e.g. `10.1.2.3`) or a CIDR
    /// (e.g. `10.0.0.0/8`); anything else fails validation. Empty (the
    /// default) trusts nobody: every proxied request carries an XFF of
    /// exactly the direct peer, and inbound XFF values are discarded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<String>,
    /// Gateway-level concurrency cap (DW-015): the maximum number of
    /// requests admitted concurrently across the WHOLE gateway. Absent
    /// (the default) is unlimited; 0 is invalid (validation rejects it —
    /// omit the field for unlimited). Over-cap requests are rejected
    /// immediately with 503 "gateway saturated" (no queueing). A slot is
    /// reserved at request admission and released when the response body
    /// completes (or the connection drops). The reserved paths
    /// `/healthz` and `/readyz` bypass the cap so liveness/readiness
    /// probes still answer under saturation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_requests: Option<u32>,
    /// Monitor mode (DW-041) for the gateway concurrency cap's load
    /// shedding: when the cap is saturated and a request would be shed,
    /// the would-shed is LOGGED and counted
    /// (`dwara_policy_dry_run_total{phase="load_shed"}` + a
    /// `dwara::policy` warn event) and the request is ADMITTED over the
    /// cap instead — deliberately exceeding `max_concurrent_requests` so
    /// an operator can observe what a cap would shed (and at which
    /// priorities) before enforcing it. Only meaningful with a cap set;
    /// validation rejects it on an uncapped gateway (it would be a
    /// no-op flag that reads as coverage).
    #[serde(default, skip_serializing_if = "is_false")]
    pub load_shed_dry_run: bool,
    /// JWT verification providers (DW-019): trusted token issuers whose
    /// keys are fetched from a JWKS endpoint. Each provider independently
    /// verifies `Authorization: Bearer` tokens (alg allowlist, iss/aud,
    /// exp with leeway) and maps the token to a consumer — via the
    /// provider's explicit `consumer` binding, or by matching a
    /// consumer's `jwt` credential `issuer` against the token's `iss`
    /// claim. Empty (the default): the gateway does not interpret Bearer
    /// tokens and forwards `Authorization` upstream untouched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jwt_providers: Vec<JwtProvider>,
    /// Admin API listener (DW-022, decision 6): mTLS-ONLY management
    /// endpoint. Absent (the default): no admin listener is started at
    /// all — the gateway is admin-silent until an operator configures
    /// one. When present, `tls` must carry all three files (server
    /// cert, key, and the CA that client certificates must chain to);
    /// a missing `client_ca_file` is rejected by validation — plaintext
    /// admin is not a supported production shape. The dev fallback
    /// (`DWARA_ADMIN_DEV=1`, dwara-bin) allows loopback-only plaintext
    /// and is loudly dev-only. The admin listener's bind set is fixed
    /// at startup; changes take effect on restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<AdminConfig>,
    /// Deliberate opt-in to running a gateway with ZERO routes (#129,
    /// maintainer decision). Default false: validation rejects a
    /// route-less config. An empty route set is schema-valid (every
    /// collection defaults empty), and a truncated or torn config
    /// write (truncate-then-save, common in naive editors) is
    /// schema-valid too — publishing it would drop ALL routing
    /// mid-run (every request 404s while the file "looks fine"). The
    /// guard applies to cold start AND hot reload alike; a rejected
    /// reload keeps the running generation serving. Set this to true
    /// only for deliberate route-less shapes (e.g. a gateway whose
    /// sole job is the admin API): with the flag set, unrouted
    /// requests answer 404 after listener/global policy checks, per
    /// the documented request-path order.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_empty_routes: bool,
    /// HMAC request-signing verification policy (DW-036): the
    /// gateway-wide clock-skew window applied to the
    /// `X-Dwara-Timestamp` header of every signed request. Absent
    /// (the default) = [`DEFAULT_HMAC_CLOCK_SKEW_SECS`] (±5 minutes).
    /// See the `security::authn` module docs for the full
    /// signing contract (canonical string, headers, replay window).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_auth: Option<HmacAuth>,
    /// Alert/event webhook targets (DW-044): every gateway event whose
    /// kind appears in a target's `events` list is POSTed to that
    /// target's `url` as one JSON envelope (id, kind, timestamp,
    /// gateway instance, payload). Delivery runs on a background task,
    /// never on the request path; emission is a bounded non-blocking
    /// hand-off (a full queue drops the event and counts the drop), so
    /// webhook failures can never stall the dataplane. Header values
    /// may be inline or `${...}` secret references (DW-045) — inline
    /// values are redacted in every config echo. See the `events`
    /// module docs for the envelope, the retry/budget shape, and the
    /// egress posture. Empty (the default): no webhooks, and events
    /// are still counted (emitted/dropped) but delivered nowhere.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub webhooks: Vec<Webhook>,
    /// The embedded analytics store (DW-043). Absent (the default):
    /// no analytics database, request records go nowhere beyond the
    /// Prometheus families and the sampled access log, and the admin
    /// API's analytics endpoints answer 404. When present, the
    /// gateway opens a SEPARATE SQLite file (never the state store's
    /// database) at `path`, feeds every completed request's access
    /// record to it on a fire-and-forget channel (a full channel
    /// DROPS and counts — analytics can never slow the dataplane),
    /// rolls raw records up through 1m/5m/1h/1d additive tables with
    /// per-granularity retention, and serves the dashboard/Top-N/
    /// structured-query endpoints from the admin listener. See the
    /// `analytics` module docs for the write path and the bounded-disk
    /// story. Part of startup wiring (the database opens once); the
    /// DIMENSIONS list is read live from the current generation so a
    /// reload can add or rename dimensions without a restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analytics: Option<AnalyticsConfig>,
    /// Real-time access-record stream (DW-121, the opt-in firehose out):
    /// every completed request's access record — not rollups, not the
    /// discrete DW-044 ops events — streamed to an external sink in
    /// flushed batches. Complements, never replaces, the embedded
    /// analytics store: the two are configured independently and a
    /// deployment can run either, both, or neither. Absent (the
    /// default): no stream. The pipeline is fire-and-forget end to end
    /// (a bounded channel that drops and counts — it can never slow or
    /// block the dataplane). See the `events::stream` module docs for
    /// the wire format, the batching contract, and the failure
    /// isolation story. Startup wiring arms the pipeline (the channel
    /// capacity is fixed at boot); the sink set — including the
    /// enabled/disabled state — is live per config generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analytics_stream: Option<AnalyticsStreamConfig>,
    /// The GeoIP database (DW-050): MaxMind-format .mmdb file backing
    /// `authorization.geoip` country/ASN predicates. Absent: geo rules
    /// are rejected by validation (an unevaluable gate is an authoring
    /// error, not a silent pass).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip: Option<GeoipConfig>,
}

/// The embedded analytics store config (DW-043, `gateway.analytics`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyticsConfig {
    /// Filesystem path of the analytics SQLite database. The file is
    /// created (and migrated) on first open. A separate file from the
    /// state store on purpose: retention deletes and incremental
    /// vacuum churn must never compact the identity store.
    pub path: String,
    /// Maximum batch latency of the background writer, in
    /// milliseconds (default 1000; validated to [100, 60 000]). Not a
    /// correctness knob — the rollup grace covers multiples of this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flush_ms: Option<u64>,
    /// Per-store retention, in milliseconds (defaults: raw 24 h, 1m
    /// 48 h, 5m 7 d, 1h 30 d, 1d 365 d). Validation enforces each
    /// floor (a granularity must outlive its own window comfortably)
    /// and monotonicity (no coarser table may expire before a finer
    /// one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<AnalyticsRetention>,
    /// Custom dimensions (DW-043): request-header-sourced tags that
    /// become analytics dimensions — `x-plan` as dimension `plan`,
    /// for consumer tier / plan / feature-flag style cuts the fixed
    /// dimensions cannot express. Extracted at request completion
    /// capture; analytics-only (never added to the access log). At
    /// most 16 (cardinality guard); values are capped at 128 bytes
    /// (longer values are skipped for that request).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dimensions: Vec<AnalyticsDimension>,
    /// Scheduled usage-report exports (DW-120): durable CSV/JSON
    /// dumps of the per-consumer usage statement, one file set per
    /// closed UTC calendar window, written by a background worker
    /// that reuses the analytics store's scheduling machinery. Absent
    /// (the default): no exports run and the admin export endpoints
    /// answer that exports are not configured. See the
    /// `analytics::exports` module docs for the schedule, the
    /// statement's reconciliation contract with the query API, and
    /// the quota-column window-alignment rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exports: Option<AnalyticsExports>,
}

/// Scheduled usage-report exports (DW-120, `analytics.exports`).
///
/// The exports worker ticks on the same background machinery as the
/// rollup cascade, closes each UTC calendar window of the configured
/// [`AnalyticsExportWindow`] kind once its data has settled, and
/// writes one file per configured format into `directory` (created on
/// demand; unwritable directories fail the run LOUD in the run record
/// and logs — never the dataplane). Parquet is deliberately NOT a v1
/// format: the arrow/parquet dependency weight is deferred (see the
/// DW-156 backlog issue).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyticsExports {
    /// Directory the export files are written into (created on demand
    /// if missing). One deterministic file per (window, format); a
    /// re-export of the same window overwrites it (idempotent output,
    /// the rollup recompute philosophy).
    pub directory: String,
    /// The schedule/window kind (fixed UTC calendar windows). Default
    /// `daily` (midnight-to-midnight UTC — aligned with the quota
    /// daily budget's window, so a daily statement's quota column is
    /// exactly that day's counter).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<AnalyticsExportWindow>,
    /// Output formats, a subset of `csv`/`json`; omitted or empty
    /// means BOTH csv and json (the default). Validation rejects only
    /// duplicates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub formats: Vec<AnalyticsExportFormat>,
}

/// One export schedule kind (DW-120, `analytics.exports.window`).
/// Closed set; fixed UTC calendar windows.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum AnalyticsExportWindow {
    Hourly,
    Daily,
    Monthly,
}

/// One export output format (DW-120, `analytics.exports.formats[]`).
/// Closed set: `csv`, `json`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum AnalyticsExportFormat {
    Csv,
    Json,
}

/// Per-granularity retention (DW-043, `analytics.retention`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyticsRetention {
    /// Raw access records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_ms: Option<i64>,
    /// The 1-minute rollup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m1_ms: Option<i64>,
    /// The 5-minute rollup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m5_ms: Option<i64>,
    /// The 1-hour rollup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h1_ms: Option<i64>,
    /// The 1-day rollup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d1_ms: Option<i64>,
}

/// Default per-granularity retention (ms), indexed [raw, 1m, 5m, 1h,
/// 1d] — a week of traffic at every granularity a week query wants,
/// bounded disk at the 1-minute grain (DW-043). Lives in `config`
/// (the lowest consuming domain) so both validation and the analytics
/// store read ONE definition.
pub const ANALYTICS_DEFAULT_RETENTION_MS: [i64; 5] = [
    86_400_000,     // raw
    172_800_000,    // 1m
    604_800_000,    // 5m
    2_592_000_000,  // 1h
    31_536_000_000, // 1d
];

impl AnalyticsRetention {
    /// Resolve to the effective [raw, m1, m5, h1, d1] millisecond
    /// set, defaulting absent entries (and clamping each to its
    /// floor so programmatic builders cannot under-retain below a
    /// window's own lifetime).
    pub fn effective(&self) -> [i64; 5] {
        let d = ANALYTICS_DEFAULT_RETENTION_MS;
        let floors = [
            5 * 60_000,      // raw: five fine windows
            10 * 60_000,     // m1
            60 * 60_000,     // m5
            24 * 3_600_000,  // h1
            30 * 86_400_000, // d1
        ];
        [
            self.raw_ms.unwrap_or(d[0]).max(floors[0]),
            self.m1_ms.unwrap_or(d[1]).max(floors[1]),
            self.m5_ms.unwrap_or(d[2]).max(floors[2]),
            self.h1_ms.unwrap_or(d[3]).max(floors[3]),
            self.d1_ms.unwrap_or(d[4]).max(floors[4]),
        ]
    }
}

/// GeoIP allow/deny rules on the effective client IP (DW-050,
/// `authorization.geoip`). Countries are ISO 3166-1 alpha-2 codes
/// (case-insensitive in config, compared uppercase); ASNs are plain
/// numbers. Evaluation mirrors `allowed_consumers`/`denied_consumers`:
/// a denied match rejects (403) regardless of the allow lists; a
/// NON-EMPTY allow list admits only matches; empty allow lists
/// constrain nothing. The UNKNOWN case (unresolvable address, no
/// database) matches neither side.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GeoipRules {
    /// Countries allowed (empty = any not denied).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_countries: Vec<String>,
    /// Countries rejected, even when otherwise allowed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_countries: Vec<String>,
    /// Autonomous system numbers allowed (empty = any not denied).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_asns: Vec<u32>,
    /// Autonomous system numbers rejected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_asns: Vec<u32>,
}

/// The GeoIP database config (DW-050, `gateway.geoip`). One MaxMind-
/// format database serves both country and ASN predicates (a
/// GeoLite2-Country, GeoLite2-ASN, or combined database — whichever
/// subtrees it carries are the ones the rules can use). The file is
/// opened at startup (a failed open is LOUD but non-fatal: the gateway
/// serves with geo lookups resolving UNKNOWN) and hot-reloaded: the
/// watcher swaps the reader when the file changes, with no restart.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GeoipConfig {
    /// Path to the .mmdb database file.
    pub path: String,
}

/// One custom analytics dimension (DW-043,
/// `analytics.dimensions[]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyticsDimension {
    /// The dimension name: lowercase `[a-z0-9_]`, at most 32 bytes —
    /// it becomes the rollup table's `dim` key and the query field.
    pub name: String,
    /// The request header whose value is captured (case-insensitive,
    /// as HTTP header names are). The FIRST value of a repeated
    /// header wins; non-UTF-8 and over-128-byte values are skipped.
    pub header: String,
}

/// One alert/event webhook target (DW-044, `gateway.webhooks[]`).
/// Compiled per generation into an `events::webhook::WebhookTarget`
/// (secret references resolved at compile time, URL decomposed); see
/// that module for the delivery contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Webhook {
    /// Absolute `http://` or `https://` URL the envelope is POSTed to.
    /// Host and port come from the URL; the path (and query, if any) is
    /// preserved. `https://` verifies against the public webpki root set
    /// (no `trusted_ca_file` override for webhooks in v1).
    pub url: String,
    /// Event kinds this target receives (subset of the kinds the gateway
    /// emits; validation rejects unknown kinds). At least one entry.
    pub events: Vec<String>,
    /// Extra headers sent on every delivery. Values may be inline or
    /// `${ENV_NAME}` / `${file:/path}` secret references (DW-045),
    /// resolved at config-compile time; inline values are redacted in
    /// every config echo. Use a reference for bearer tokens and signing
    /// secrets.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub headers: std::collections::BTreeMap<String, String>,
    /// TOTAL budget for one delivery (all retry attempts share it):
    /// connect, write, and response-head read per attempt plus the
    /// backoff waits between attempts. A slow or hung target can never
    /// occupy more than this. Default 2000; validation enforces
    /// 1..=[`limits::MAX_WEBHOOK_TIMEOUT_MS`].
    #[serde(
        default = "default_webhook_timeout_ms",
        skip_serializing_if = "is_default_webhook_timeout_ms"
    )]
    pub timeout_ms: u64,
    /// Total attempts per delivery (the first try plus retries). Retries
    /// happen for transport failures and the transient status set
    /// (429/502/503/504), honoring a seconds-form `Retry-After` when the
    /// target sends one. Default 3; validation enforces
    /// 1..=[`limits::MAX_WEBHOOK_ATTEMPTS`].
    #[serde(
        default = "default_webhook_attempts",
        skip_serializing_if = "is_default_webhook_attempts"
    )]
    pub max_attempts: u32,
    /// First backoff between delivery attempts, doubling per retry up to
    /// `backoff_cap_ms` (a `Retry-After` answer replaces the computed
    /// value for that wait). Default 100.
    #[serde(
        default = "default_webhook_backoff_base_ms",
        skip_serializing_if = "is_default_webhook_backoff_base_ms"
    )]
    pub backoff_base_ms: u64,
    /// Upper bound on the computed backoff. Default 1000; must be >=
    /// `backoff_base_ms`.
    #[serde(
        default = "default_webhook_backoff_cap_ms",
        skip_serializing_if = "is_default_webhook_backoff_cap_ms"
    )]
    pub backoff_cap_ms: u64,
}

/// Default `gateway.webhooks[].timeout_ms` (DW-044): one shared
/// delivery budget, generous for a remote alerting endpoint, small
/// enough that a hung target cannot pile up deliveries.
pub const DEFAULT_WEBHOOK_TIMEOUT_MS: u64 = 2_000;
/// Default `gateway.webhooks[].max_attempts` (DW-044).
pub const DEFAULT_WEBHOOK_ATTEMPTS: u32 = 3;
/// Default `gateway.webhooks[].backoff_base_ms` (DW-044).
pub const DEFAULT_WEBHOOK_BACKOFF_BASE_MS: u64 = 100;
/// Default `gateway.webhooks[].backoff_cap_ms` (DW-044).
pub const DEFAULT_WEBHOOK_BACKOFF_CAP_MS: u64 = 1_000;

fn default_webhook_timeout_ms() -> u64 {
    DEFAULT_WEBHOOK_TIMEOUT_MS
}
fn default_webhook_attempts() -> u32 {
    DEFAULT_WEBHOOK_ATTEMPTS
}
fn default_webhook_backoff_base_ms() -> u64 {
    DEFAULT_WEBHOOK_BACKOFF_BASE_MS
}
fn default_webhook_backoff_cap_ms() -> u64 {
    DEFAULT_WEBHOOK_BACKOFF_CAP_MS
}
fn is_default_webhook_timeout_ms(v: &u64) -> bool {
    *v == DEFAULT_WEBHOOK_TIMEOUT_MS
}
fn is_default_webhook_attempts(v: &u32) -> bool {
    *v == DEFAULT_WEBHOOK_ATTEMPTS
}
fn is_default_webhook_backoff_base_ms(v: &u64) -> bool {
    *v == DEFAULT_WEBHOOK_BACKOFF_BASE_MS
}
fn is_default_webhook_backoff_cap_ms(v: &u64) -> bool {
    *v == DEFAULT_WEBHOOK_BACKOFF_CAP_MS
}

/// Real-time access-record stream (DW-121,
/// `gateway.analytics_stream`).
///
/// Every completed request's access record is copied onto a bounded
/// channel at request completion (drop-and-count on full — the stream
/// can never slow the dataplane), and a background flusher turns the
/// queue into ordered batches delivered to the configured sink: one
/// delivery per flushed BATCH, not per record. The channel capacity is
/// fixed at boot; the sink set, flush cadence, and batch bound are read
/// live from the current generation, so a reload can retarget or
/// disable the stream without a restart.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyticsStreamConfig {
    /// Where flushed batches go. One sink in v1 (`type: webhook`); the
    /// set is closed so a second implementation (a Kafka producer is
    /// the documented slot) is an additive config change, not a silent
    /// behavior change.
    pub sink: AnalyticsStreamSink,
    /// Capacity of the bounded record channel (default 8192; validated
    /// to [64, 65536]). The queue's entire memory story: every queued
    /// record is an owned copy, and a full queue DROPS (and counts)
    /// rather than blocking the request path. Startup wiring: the
    /// capacity is fixed when the gateway boots (a live reload changes
    /// the sink and the cadence, not this).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer: Option<u64>,
    /// Maximum batch latency in milliseconds (default 1000; validated
    /// to [100, 60000]): a batch is flushed when it holds
    /// `batch_max` records, reaches the batch byte cap, or this much
    /// time has passed since its first record — whichever comes first.
    /// Read live per flush cycle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flush_ms: Option<u64>,
    /// Maximum records per flushed batch (default 512; validated to
    /// [1, 4096]). With the batch byte cap, whichever comes first. One
    /// batch is one delivery, so this is also the largest single
    /// delivery's record count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_max: Option<u64>,
}

/// The access-record stream's sink (DW-121,
/// `gateway.analytics_stream.sink`). Closed set, internally tagged
/// (`type: webhook`): `webhook` ships today. A Kafka producer is the
/// documented second slot, deliberately not shipped in v1 (the
/// lean-deps rule — the same decision that deferred Parquet to the
/// DW-156 backlog): a sink slot that pulls a client library must earn
/// its dependency weight. The variant payloads carry their own
/// `deny_unknown_fields`, so a misspelled knob inside a sink is still
/// a rejected config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AnalyticsStreamSink {
    /// POST each flushed batch as one NDJSON body (one JSON object per
    /// line, one line per record) to the configured URL, reusing the
    /// DW-044 webhook delivery engine's retry/budget shape — one
    /// delivery (with its retries) per batch.
    Webhook(AnalyticsStreamWebhook),
}

/// The webhook batch sink (DW-121,
/// `gateway.analytics_stream.sink.webhook`). Same URL/header/retry
/// grammar as `gateway.webhooks[]` (DW-044) — the delivery engine is
/// shared — minus the `events` filter (a record stream has no kinds to
/// filter: every record goes to the sink).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyticsStreamWebhook {
    /// Absolute `http://` or `https://` URL the batch is POSTed to.
    /// `https://` verifies against the public webpki root set (no
    /// `trusted_ca_file` override — v1 scope, same as alert webhooks).
    pub url: String,
    /// Headers sent on every batch delivery (e.g. the collector's auth
    /// token). Values may be inline or `${ENV_NAME}` / `${file:/path}`
    /// secret references (DW-045), resolved at config-compile time;
    /// inline values are redacted in every config echo. Use a
    /// reference for bearer tokens and signing secrets.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub headers: std::collections::BTreeMap<String, String>,
    /// TOTAL budget for one batch delivery (all retry attempts share
    /// it), in milliseconds. Default 5000: a BATCH is heavier than a
    /// single alert envelope, and the flusher delivers batches strictly
    /// in order, so this bounds how long one unlucky batch can hold
    /// back the queue. Validation enforces
    /// 1..=[`limits::MAX_WEBHOOK_TIMEOUT_MS`] (the shared engine's
    /// bound).
    #[serde(
        default = "default_stream_webhook_timeout_ms",
        skip_serializing_if = "is_default_stream_webhook_timeout_ms"
    )]
    pub timeout_ms: u64,
    /// Total attempts per batch delivery (first try plus retries);
    /// retries cover transport failures and the transient status set
    /// (429/502/503/504), honoring a seconds-form `Retry-After`.
    /// Default 3; validation enforces
    /// 1..=[`limits::MAX_WEBHOOK_ATTEMPTS`].
    #[serde(
        default = "default_stream_webhook_attempts",
        skip_serializing_if = "is_default_stream_webhook_attempts"
    )]
    pub max_attempts: u32,
    /// First backoff between batch attempts, doubling per retry up to
    /// `backoff_cap_ms` (a `Retry-After` answer replaces the computed
    /// value for that wait). Default 250 — a batch retry is heavier
    /// than an alert retry, so it starts slower.
    #[serde(
        default = "default_stream_webhook_backoff_base_ms",
        skip_serializing_if = "is_default_stream_webhook_backoff_base_ms"
    )]
    pub backoff_base_ms: u64,
    /// Upper bound on the computed backoff. Default 4000; must be >=
    /// `backoff_base_ms`.
    #[serde(
        default = "default_stream_webhook_backoff_cap_ms",
        skip_serializing_if = "is_default_stream_webhook_backoff_cap_ms"
    )]
    pub backoff_cap_ms: u64,
}

/// Default `analytics_stream.buffer` (DW-121): the bounded record
/// channel's capacity when the block is absent at boot (the stream is
/// always constructed so a live reload can arm it). Lives in `config`
/// with the retention defaults — the lowest consuming domain — so
/// validation docs, the stream, and the binary read one definition.
pub const DEFAULT_STREAM_BUFFER: u64 = 8_192;
/// Default `analytics_stream.flush_ms` (DW-121): maximum batch latency.
pub const DEFAULT_STREAM_FLUSH_MS: u64 = 1_000;
/// Default `analytics_stream.batch_max` (DW-121): records per flushed
/// batch.
pub const DEFAULT_STREAM_BATCH_MAX: u64 = 512;
/// Default `analytics_stream.sink.webhook.timeout_ms` (DW-121): a
/// batch carries up to `batch_max` records, so its budget starts
/// heavier than the alert webhook's 2000 but stays far under the
/// one-minute ceiling.
pub const DEFAULT_STREAM_WEBHOOK_TIMEOUT_MS: u64 = 5_000;
/// Default `analytics_stream.sink.webhook.max_attempts` (DW-121).
pub const DEFAULT_STREAM_WEBHOOK_ATTEMPTS: u32 = 3;
/// Default `analytics_stream.sink.webhook.backoff_base_ms` (DW-121).
pub const DEFAULT_STREAM_WEBHOOK_BACKOFF_BASE_MS: u64 = 250;
/// Default `analytics_stream.sink.webhook.backoff_cap_ms` (DW-121).
pub const DEFAULT_STREAM_WEBHOOK_BACKOFF_CAP_MS: u64 = 4_000;

fn default_stream_webhook_timeout_ms() -> u64 {
    DEFAULT_STREAM_WEBHOOK_TIMEOUT_MS
}
fn default_stream_webhook_attempts() -> u32 {
    DEFAULT_STREAM_WEBHOOK_ATTEMPTS
}
fn default_stream_webhook_backoff_base_ms() -> u64 {
    DEFAULT_STREAM_WEBHOOK_BACKOFF_BASE_MS
}
fn default_stream_webhook_backoff_cap_ms() -> u64 {
    DEFAULT_STREAM_WEBHOOK_BACKOFF_CAP_MS
}
fn is_default_stream_webhook_timeout_ms(v: &u64) -> bool {
    *v == DEFAULT_STREAM_WEBHOOK_TIMEOUT_MS
}
fn is_default_stream_webhook_attempts(v: &u32) -> bool {
    *v == DEFAULT_STREAM_WEBHOOK_ATTEMPTS
}
fn is_default_stream_webhook_backoff_base_ms(v: &u64) -> bool {
    *v == DEFAULT_STREAM_WEBHOOK_BACKOFF_BASE_MS
}
fn is_default_stream_webhook_backoff_cap_ms(v: &u64) -> bool {
    *v == DEFAULT_STREAM_WEBHOOK_BACKOFF_CAP_MS
}

/// Gateway-wide HMAC request-signing policy (DW-036). The credential
/// itself (key id + secret) lives on a consumer
/// (`credentials: [{type: hmac, ...}]`); this block carries the
/// VERIFICATION policy that applies to every signed request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HmacAuth {
    /// Maximum accepted absolute difference, in seconds, between the
    /// request's `X-Dwara-Timestamp` and the gateway clock. A timestamp
    /// outside the window is rejected 401 BEFORE any HMAC computation
    /// (an expired window is not a MAC problem). The window is also the
    /// replay window: nonces are remembered for twice this duration.
    /// Default 300 (±5 minutes, the §4.6 recommendation); validation
    /// enforces 1..=3600 (a sub-second window rejects every request
    /// with any clock drift; an unbounded one pins nonce-cache memory
    /// forever).
    #[serde(default = "default_hmac_clock_skew_secs")]
    pub max_clock_skew_secs: u64,
}

/// Default `hmac_auth.max_clock_skew_secs` (±5 minutes, DW-036 §4.6).
pub const DEFAULT_HMAC_CLOCK_SKEW_SECS: u64 = 300;

fn default_hmac_clock_skew_secs() -> u64 {
    DEFAULT_HMAC_CLOCK_SKEW_SECS
}

impl Gateway {
    /// A display-safe copy of this config (DW-045): every INLINE
    /// `api_key` value is replaced by the
    /// [`credentials::redact_inline_secret`] placeholder
    /// (`${redacted:sha256:<prefix>}`); `${...}` references pass through
    /// unchanged (an env-var name or file path is not secret bytes —
    /// the config file itself carries it). This is the TYPED redaction
    /// behind every surface that echoes configuration (admin
    /// `GET /config`); it is deliberately a transform, not a custom
    /// serializer, so it cannot drift from the schema — a future
    /// secret-bearing field fails visibly (its value reaches the dump
    /// unredacted) instead of silently escaping an allowlist regex.
    pub fn redacted(&self) -> Gateway {
        let mut redacted = self.clone();
        for consumer in &mut redacted.consumers {
            for credential in &mut consumer.credentials {
                match credential {
                    Credential::ApiKey { key } => {
                        *key = credentials::redact_inline_secret(key);
                    }
                    // DW-036: the HMAC secret is inline secret material
                    // exactly like an api key — same placeholder, same
                    // unresolvable-by-design round-trip rejection.
                    Credential::Hmac { secret, .. } => {
                        *secret = credentials::redact_inline_secret(secret);
                    }
                    Credential::Jwt { .. } | Credential::Mtls { .. } => {}
                }
            }
        }
        // DW-044: webhook header values are secret-bearing config fields
        // exactly like api keys (bearer tokens, signing secrets) — the
        // same placeholder, the same reference passthrough, the same
        // unresolvable-by-design round-trip rejection.
        for webhook in &mut redacted.webhooks {
            for value in webhook.headers.values_mut() {
                *value = credentials::redact_inline_secret(value);
            }
        }
        redacted
    }
}

/// Admin listener configuration (DW-022).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Bind address of the admin listener. Default `127.0.0.1:2019`
    /// (loopback-only; frozen decision 6) — override only to place the
    /// admin API on a dedicated management interface, and rely on mTLS
    /// for access control: there is no token layer in v1 (the client
    /// certificate IS the auth).
    #[serde(default = "default_admin_bind")]
    pub bind: String,
    /// mTLS material for the admin listener; all three files are
    /// required.
    pub tls: AdminTlsConfig,
}

/// mTLS material for the admin listener (DW-022). Unlike dataplane
/// listeners there is no mode: the admin listener always terminates TLS
/// and always requires a client certificate chaining to `client_ca_file`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdminTlsConfig {
    /// Path to the PEM certificate chain the admin server presents.
    pub cert_file: String,
    /// Path to the PEM private key for `cert_file`.
    pub key_file: String,
    /// Path to the PEM CA bundle client certificates must chain to.
    /// Required (mTLS-only): validation rejects an admin block without
    /// it rather than silently serving no-auth TLS.
    pub client_ca_file: String,
}

fn default_admin_bind() -> String {
    "127.0.0.1:2019".to_string()
}

/// One JWT verification provider (DW-019).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JwtProvider {
    pub name: String,
    /// JWKS endpoint (`http://` or `https://`). Keys are fetched lazily on
    /// the first Bearer request, refreshed after `refresh_secs`, and
    /// re-fetched on an unknown `kid` (key rotation mid-flight).
    pub jwks_url: String,
    /// Path to a PEM file of CA certificates the JWKS fetcher trusts for
    /// its `https://` connection INSTEAD of the default public (webpki)
    /// root set (#121): for JWKS endpoints served over TLS by a private
    /// CA. The file may carry several certificates (a typical CA bundle).
    /// Only meaningful with an `https://` jwks_url — no TLS is negotiated
    /// toward an `http://` endpoint, so validation rejects that
    /// combination. The file must exist and be readable at config compile
    /// time; validation names this field otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_ca_file: Option<String>,
    /// Required token issuer (`iss` claim). Absent: any issuer accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Required audience (`aud` claim). Audience is validated ONLY when
    /// this is configured (#124, maintainer decision): a provider
    /// without an `audience` ACCEPTS tokens that carry any (or no) `aud`
    /// claim — `aud` is not interpreted unless the provider names one.
    /// All other validations (exp, nbf, iss when configured, the
    /// algorithm allowlist) are identical either way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Allowed signature algorithms (default `["RS256", "ES256"]`).
    /// `none` and HMAC (`HS*`) algorithms are never allowed implicitly —
    /// they must not appear in this list; validation rejects them
    /// (asymmetric verification only: the gateway holds no shared
    /// secrets with issuers).
    #[serde(default = "default_jwt_algorithms")]
    pub algorithms: Vec<String>,
    /// JWKS cache staleness bound in seconds (default 300): a cached key
    /// set older than this is refreshed before use.
    #[serde(
        default = "default_jwt_refresh_secs",
        skip_serializing_if = "is_default_jwt_refresh_secs"
    )]
    pub refresh_secs: u64,
    /// exp/nbf clock-skew leeway in seconds (default 30).
    #[serde(
        default = "default_jwt_leeway_secs",
        skip_serializing_if = "is_default_jwt_leeway_secs"
    )]
    pub leeway_secs: u64,
    /// Consumer this provider's tokens authenticate. Absent: the token's
    /// `iss` claim is matched against consumers' `jwt` credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<String>,
    /// How long a key REMOVED from a fresh JWKS fetch keeps verifying
    /// (DW-046), in seconds (default 86400 = 24 h; 0 disables). The
    /// dual-validity window for JWKS rotation: issuers drop the old
    /// key from their JWKS the moment the new one appears, while
    /// previously-issued tokens still carry the old `kid` — during
    /// this grace the gateway honors the immediately-previous key set
    /// for kids the fresh set no longer carries. Only ONE previous set
    /// is retained (rotation is one step at a time). Validation caps
    /// the value at 7 days (604800).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_key_grace_secs: Option<u64>,
}

impl JwtProvider {
    /// `retired_key_grace_secs` resolved to its effective value
    /// (default 86 400; the DW-046 dual-validity window).
    pub fn retired_key_grace_secs(&self) -> u64 {
        self.retired_key_grace_secs.unwrap_or(86_400)
    }
}

fn default_jwt_algorithms() -> Vec<String> {
    vec!["RS256".to_string(), "ES256".to_string()]
}

fn default_jwt_refresh_secs() -> u64 {
    300
}

fn default_jwt_leeway_secs() -> u64 {
    30
}

fn is_default_jwt_refresh_secs(v: &u64) -> bool {
    *v == 300
}

fn is_default_jwt_leeway_secs(v: &u64) -> bool {
    *v == 30
}

/// Entry point: bind address + port + TLS termination (or passthrough) config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub name: String,
    /// Bind address, e.g. `0.0.0.0` or `127.0.0.1`.
    pub address: String,
    pub port: u16,
    #[serde(default = "default_listener_protocol")]
    pub protocol: ListenerProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<ListenerTls>,
    /// Accept a PROXY protocol v1 or v2 header as the FIRST bytes of
    /// every connection on this listener (DW-030), replacing the peer
    /// address the gateway uses everywhere the socket peer is used
    /// today: the authz IP ACL's effective-client-IP base, rate-limit
    /// keying, `X-Forwarded-For` / `X-Real-IP` on the forwarded
    /// request. OPT-IN (default false): a plaintext listener that does
    /// not expect a PROXY line must never interpret the first request
    /// bytes as one, and a client that spoofs a PROXY line on a listener
    /// without this flag is simply serving garbage to the HTTP parser.
    /// The header is read BEFORE the TLS handshake (the L4 LB in front
    /// wraps the whole stream, TLS included) and a MALFORMED header
    /// fails closed: the connection is answered with a `400` error
    /// envelope and closed, never handed to HTTP parsing. A v2 `LOCAL`
    /// command or a v1 `UNKNOWN` line keeps the real peer address (the
    /// spec's own fallback for connections the LB did not originate).
    /// Validation rejects the combination with `tls.mode passthrough`:
    /// a passthrough listener splices raw bytes and never runs the
    /// HTTP pipeline that consumes the client address. Part of the
    /// restart-only bind set (like address/port) — toggling it takes a
    /// restart, not a reload.
    #[serde(default, skip_serializing_if = "is_false")]
    pub proxy_protocol: bool,
    /// Policies attached to this listener (#123): names from the
    /// gateway's `policies` list, applying to every request the listener
    /// accepts (the second-least specific link of the frozen chain
    /// consumer > route > service > listener > global; all applicable
    /// levels' rules AND together — see the rate-limiter module docs).
    /// Listener policies also apply to UNROUTED traffic accepted by this
    /// listener: a request whose path matches no route is rate-limited by
    /// them before the 404 is answered (reserved paths stay exempt).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// Listener-level authorization rules (#123): applies to every
    /// request this listener accepts that resolved a route (authorization
    /// runs after route resolution per the documented request-path
    /// order). Link of the frozen chain consumer > route > service >
    /// listener > global; see [`Authz`] for the rule semantics and the
    /// `authz` module for the merge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authz>,
}

fn default_listener_protocol() -> ListenerProtocol {
    ListenerProtocol::Http
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ListenerProtocol {
    Http,
    Https,
}

/// TLS handling for a listener: terminate at the edge or pass through.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListenerTls {
    #[serde(default = "default_tls_mode")]
    pub mode: TlsMode,
    /// Path to the PEM certificate chain (termination mode only). Serves as
    /// the default/fallback certificate when `certificates` is also set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_file: Option<String>,
    /// Path to the PEM private key (termination mode only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_file: Option<String>,
    /// Additional SNI-scoped certificate pairs (termination mode only).
    /// Each entry serves the listed `server_names`; the single
    /// cert_file/key_file pair (if present) is the fallback for unmatched
    /// or absent SNI. With no single pair, the first entry is the fallback.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<TlsCertificate>,
    /// SNI routing rules for passthrough mode: each entry maps its
    /// `server_names` to an upstream (by name) that receives the raw TLS
    /// bytes. Rejected in terminate mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sni_routes: Vec<SniRoute>,
    /// PEM file of CA certificates that CLIENT certificates must chain
    /// to (#124, termination mode only). When set, the listener
    /// REQUESTS a client certificate and verifies any presented one
    /// against this bundle; a connection without a certificate is still
    /// accepted (other credential families apply) — the verified
    /// certificate is matched against consumers' `mtls` credentials to
    /// resolve an identity, and an UNVERIFIED certificate fails the
    /// handshake (mTLS authn never sees it). Rejected in passthrough
    /// mode (the TLS layer is not terminated, so client certificates
    /// cannot be verified). The file must exist and be readable at
    /// config compile time; validation names this field otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ca_file: Option<String>,
}

/// One SNI-scoped certificate pair for TLS termination.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsCertificate {
    /// Server names (SNI values) this certificate answers. Exact match,
    /// case-insensitive per rustls.
    pub server_names: Vec<String>,
    /// Path to the PEM certificate chain.
    pub cert_file: String,
    /// Path to the PEM private key.
    pub key_file: String,
}

/// One SNI-to-upstream routing rule for TLS passthrough.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SniRoute {
    /// Server names (SNI values) routed to `upstream`. Exact match.
    pub server_names: Vec<String>,
    /// Name of the upstream that receives the spliced TLS stream.
    pub upstream: String,
}

fn default_tls_mode() -> TlsMode {
    TlsMode::Terminate
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    Terminate,
    Passthrough,
}

/// Match rules (path/host/method/header) plus action and attached policies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub name: String,
    /// Name of the service this route targets.
    pub service: String,
    pub r#match: RouteMatch,
    pub action: RouteAction,
    /// Attached policy names. All applicable levels' rules AND together
    /// (see the rate-limiter module docs); the resolution order is
    /// consumer > route > service > listener > global.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// Request priority class for load shedding (DW-016): 0 (lowest) to 10
    /// (highest); absent means the default 5. When the gateway concurrency
    /// cap is saturated, requests at `high_priority` (>= 8) draw from a
    /// small reserved sub-allowance of the cap that lower-priority traffic
    /// cannot use (see `proxy` module docs); preemption is impossible, so
    /// normal traffic is shed first rather than displaced. Validation
    /// rejects values above 10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
    /// Require authenticated requests (DW-019): a request that arrives
    /// WITHOUT a recognized credential (or with an invalid one) is
    /// rejected with 401 and a `WWW-Authenticate` challenge. Absent
    /// (the default) allows anonymous traffic through; note that an
    /// INVALID presented credential is always rejected with 401
    /// regardless of this flag.
    #[serde(default, skip_serializing_if = "is_false")]
    pub auth_required: bool,
    /// Route-scoped CORS policy (DW-027, feature analysis 4.14): controls
    /// how the gateway answers browser cross-origin requests on this
    /// route. When present, a CORS PREFLIGHT (`OPTIONS` carrying both
    /// `Origin` and `Access-Control-Request-Method`) is answered by the
    /// gateway itself, before authentication and never forwarded
    /// upstream; actual (non-preflight) responses carry the policy's
    /// CORS headers. Non-CORS requests are untouched. A preflight on a
    /// route whose `match.methods` list excludes `OPTIONS` never matches
    /// the route (the documented request-path order applies first) —
    /// include `OPTIONS` in the method list of CORS routes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors: Option<Cors>,
    /// Route-scoped response compression (DW-027, feature analysis 4.13):
    /// negotiates gzip/brotli/zstd against the request's `Accept-Encoding`
    /// and compresses the response body per policy. Streaming-safe: the
    /// body is compressed chunk-by-chunk with a per-chunk flush, never
    /// buffered whole. Disabled (absent) by default — the dataplane
    /// forwards bytes untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression: Option<Compression>,
    /// Route-scoped request size limits (DW-027, feature analysis 4.16):
    /// per-route body and header caps enforced after route resolution.
    /// Over-limit requests are rejected by the gateway with the JSON
    /// error envelope (413 for bodies, 431 for headers) before any
    /// upstream contact when the size is declared up front
    /// (`Content-Length`); streaming bodies of unknown length are
    /// aborted as soon as they cross the cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<RequestLimits>,
    /// Route-level authorization rules (DW-020, feature analysis 4.7).
    /// Absent (the default) imposes no authorization on the route. A
    /// PRESENT-but-entirely-empty block (no consumers, groups, scopes,
    /// claims, or `ip_acl`) is likewise a no-op at evaluation time —
    /// it imposes nothing, exactly like an absent one — but it is
    /// always a config-authoring mistake (a rule block with no rules),
    /// so validation REJECTS it: omit the block instead of emptying it.
    /// When present (and non-empty), the rules are evaluated after
    /// authentication and BEFORE
    /// rate limiting; see [`Authz`] for the rule semantics. Presence of
    /// any identity rule implies authentication (an anonymous request is
    /// rejected 401); an `ip_acl`-only block is the one case that can
    /// permit anonymous access (from an allowed IP). Precedence across
    /// levels (consumer > route > service > listener > global) is
    /// resolved by the `authz` module's resolver; every level has a
    /// config attachment point (`consumers[].authorization`,
    /// `services[].authorization`, `listeners[].authorization`, and the
    /// gateway-level `authorization`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authz>,
    /// API deprecation policy (DW-048): emits the standard deprecation
    /// signal headers on this route's responses. See [`Deprecation`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecation: Option<Deprecation>,
    /// Route maintenance mode (DW-041): when present, every request the
    /// route matches is answered by the GATEWAY with a 503 carrying
    /// `Retry-After` and the JSON error envelope (`maintenance` code) —
    /// before route limits, CORS preflight handling (preflights
    /// themselves are exempt, see [`Maintenance`]), authentication, and
    /// the route action (proxy, redirect, and respond actions alike
    /// never run). Toggled by config reload like every route field:
    /// publish a generation with the block to enter maintenance and one
    /// without it to leave. See [`Maintenance`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance: Option<Maintenance>,
    /// Request/response transforms (DW-028, feature analysis 4.12):
    /// header and query manipulation on the forwarded request and the
    /// route's responses, plus the size-capped JSON-pointer body
    /// transform — the transforms surface's ONE explicitly buffering
    /// piece. Absent (the default): bytes and headers flow untouched.
    /// See [`Transforms`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transforms: Option<Transforms>,
    /// Security-header injection (DW-028, feature analysis 5-Security):
    /// HSTS, `X-Content-Type-Options: nosniff`,
    /// `Content-Security-Policy`, and `X-Frame-Options`, stamped on
    /// EVERY response the route emits (action responses and gateway
    /// short-circuits alike), replacing any upstream-sent values — the
    /// gateway is the source of truth at its edge. See
    /// [`SecurityHeaders`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_headers: Option<SecurityHeaders>,
    /// Response field masking (DW-029, feature analysis 5-Security):
    /// redacts the named RFC 6901 JSON pointers from the route's
    /// responses — the floor `fields` for every consumer, plus the
    /// `groups` additions for members of each consumer group — before
    /// any other body-handling stage. The redaction is fail-closed: a
    /// response the gateway cannot prove clean (encoded, non-JSON,
    /// over the cap, unparseable, or missing a configured pointer)
    /// answers 502, never a passthrough. See [`Masking`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masking: Option<Masking>,
    /// Route-scoped response caching (DW-037, feature analysis
    /// 5-Protocol): opts the route's cacheable GET traffic into the
    /// local response cache behind the `CacheStore` extension seam.
    /// Absent (the default): responses are never cached or buffered.
    /// The cache key folds in the route, the consumer, the inbound
    /// path + query, and the effective vary set — masked (DW-029) and
    /// consumer-group-specific variants never cross consumers. Stored
    /// bodies are the POST-masking/transform bytes (replay consistency
    /// under route-scoped policies), stored identity (never compressed;
    /// compression re-negotiates per request), and the decoration tail
    /// (compression onward) re-runs on every replay. See
    /// [`RouteCache`] and `dataplane::response_cache`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<RouteCache>,
    /// Per-route METHOD ALLOWLIST (DW-030): when non-empty, a request
    /// that resolved this route but whose method is not in the list is
    /// answered by the gateway with `405 Method Not Allowed` plus an
    /// `Allow` header listing the configured methods (RFC 9110 10.2.1).
    /// Distinct from `match.methods`, which gates ROUTE RESOLUTION (a
    /// miss falls through to 404 / other routes); this list gates the
    /// ALREADY-matched route. Placement (frozen): after route
    /// resolution and the maintenance 503, before the route limits and
    /// CORS preflight short-circuit and authentication — the allowlist
    /// is a statement about the route, not the request's shape (the
    /// DW-041 maintenance ordering argument), and a CORS PREFLIGHT
    /// (`OPTIONS` + preflight markers) is exempt exactly like the
    /// maintenance 503 (the preflight asks about the GATEWAY's
    /// cross-origin policy, not the resource; failing it would hide the
    /// CORS answer from the browser). Matching is case-insensitive, the
    /// same comparison `match.methods` uses. HEAD is NOT implicitly
    /// granted by GET — a route supporting HEAD alongside GET lists
    /// both (the allowlist is exhaustive by design; implicit grants
    /// would leak methods the operator never named). Empty (the
    /// default) allows every method, exactly like pre-DW-030.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Service-level objectives (DW-052, feature analysis 4.17): the
    /// route's availability target and optional latency objective,
    /// exported as `dwara_slo_burn_rate` / `dwara_slo_target` metrics
    /// over process-local 5m and 1h sliding windows for multiwindow
    /// burn-rate alerting. Availability counts a request BAD only when
    /// the GATEWAY answers 5xx (client errors are the caller's policy,
    /// not this route's availability). Absent (the default): the route
    /// records nothing and exports no SLO series. See [`RouteSlo`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slo: Option<RouteSlo>,
}

/// Per-route SLO objectives (DW-052, `routes[].slo`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteSlo {
    /// Availability target as a PERCENTAGE in (0, 100]: the share of
    /// requests the gateway must answer outside the 5xx class.
    /// `99.9` allows one bad request per thousand.
    pub availability: f64,
    /// Latency objective threshold in milliseconds: a request is BAD
    /// for the latency objective when its end-to-end duration exceeds
    /// this. Absent: no latency objective (only availability is
    /// exported for the route).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    /// Latency target as a PERCENTAGE in (0, 100): the share of
    /// requests that must complete within `latency_ms` (default 99).
    /// Requires `latency_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_target: Option<f64>,
}

/// Route maintenance mode (DW-041): a per-route availability state that
/// short-circuits every matched request with a gateway-generated 503.
///
/// Frozen semantics (enforcement lives in `dataplane::proxy`):
///
/// - Checked IMMEDIATELY after route resolution, BEFORE the route's
///   request limits: maintenance is a statement about the route's
///   availability, not about any one request's shape, so every matched
///   request gets the same 503 + `Retry-After` answer (an over-limit
///   request during maintenance is told "we're down", not "your headers
///   are too big" — fixing the headers would still leave it refused).
/// - The response is `503` with `Retry-After: <retry_after_secs>` (a
///   whole-seconds delay-suggestion, NOT a promise of recovery) and the
///   uniform JSON error envelope; `message` replaces the envelope's
///   default human text (it never leaks upstream internals — it is
///   operator-authored).
/// - CORS: an actual (non-preflight) request on a CORS-configured route
///   gets the policy's actual-response headers on the 503, so a browser
///   client can READ the maintenance envelope cross-origin. A CORS
///   PREFLIGHT is exempt: it still answers 204 exactly as without
///   maintenance. The preflight is a Fetch-protocol handshake about the
///   GATEWAY's cross-origin policy, answered from static config and sent
///   without credentials — failing it would surface in the browser as an
///   opaque CORS error and hide the very 503 the operator wants clients
///   to see on the subsequent actual request.
/// - Reserved paths (`/healthz`, `/readyz`, `/metrics`) never match a
///   route, so probes and scrapes keep answering through maintenance —
///   an orchestrator must not restart a deliberately idling gateway.
/// - Unrouted traffic is unaffected (maintenance is per-route; a 404
///   stays a 404).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Maintenance {
    /// `Retry-After` value, in whole seconds, sent with the 503. Absent:
    /// 60 (one minute — long enough to shed load, short enough that a
    /// client polling for recovery notices the route return). Validation
    /// rejects 0 (it would invite an immediate retry stampede against a
    /// route the operator just took down).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
    /// Human-readable text for the error envelope's `message` field.
    /// Absent: "route under maintenance". Validation rejects an
    /// empty/whitespace string (omit the field for the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Default `maintenance.retry_after_secs` (DW-041).
pub const DEFAULT_MAINTENANCE_RETRY_AFTER_SECS: u64 = 60;

impl Maintenance {
    /// The `Retry-After` seconds to send (the configured value or the
    /// default; validation has rejected 0, so this is always >= 1).
    pub fn retry_after(&self) -> u64 {
        self.retry_after_secs
            .unwrap_or(DEFAULT_MAINTENANCE_RETRY_AFTER_SECS)
            .max(1)
    }

    /// The envelope `message` text (the configured value or the default).
    pub fn message(&self) -> &str {
        self.message.as_deref().unwrap_or("route under maintenance")
    }
}

/// Route-level API deprecation policy (DW-048): automates the RFC
/// deprecation signal headers on every response of the route.
///
/// What the block emits (computed once at snapshot compile; see
/// [`CompiledDeprecation`] and `dataplane::versioning`):
///
/// - `since` (header emitted only when set): `Deprecation:
///   @<unix-seconds>` — the RFC 9745 structured-date form (RFC 9651
///   dates). RFC 9745 carries no URI inside the `Deprecation` field;
///   the human-readable notice travels in the `Link` below.
/// - `sunset` (optional): `Sunset: <HTTP-date>` verbatim — RFC 8594
///   requires an HTTP-date, and validation accepts exactly the
///   IMF-fixdate form generators must send (see `config::versioning`).
/// - `uri` (optional, requires `since`): `Link: <uri>;
///   rel="deprecation"` appended — the RFC 9745 companion link to the
///   migration documentation.
///
/// Semantics (frozen):
///
/// - Headers are stamped on the route's ACTION responses (proxy,
///   redirect, respond) in the response decoration tail — after
///   compression wrapping (the codec only rewrites `Content-Length`,
///   `Content-Encoding`, and `Vary`, so these headers pass through
///   verbatim) and beside the CORS headers (independent families).
///   Gateway-generated short-circuits on the route (413/431 limit
///   rejections, CORS preflights, authn/authz/rate-limit rejections,
///   503 sheds) do NOT carry them: those responses describe the
///   gateway's opinion of the REQUEST, not the route's lifecycle.
///   (The eager HMAC body-digest 401 is an action-path response and
///   DOES carry them.) Unrouted traffic (404) never matches the route
///   at all.
/// - The gateway is the source of truth for the headers it is configured
///   to emit: an upstream-sent `Deprecation`/`Sunset` on a route WITH a
///   `deprecation` block is replaced; on a route WITHOUT one, upstream
///   values pass through untouched. `Link` is appended (a list header —
///   upstream links survive).
/// - Validation rejects: a block with neither `since` nor `sunset` (no
///   effect — omit it), dates that are not IMF-fixdate, a `sunset`
///   already in the past (advertising a removal that already happened;
///   remove the route or extend the date — this also stops a long-lived
///   generation from silently re-publishing a stale sunset), a `sunset`
///   before `since` (removed before deprecated), and a `uri` without
///   `since` (the link documents the `Deprecation` header).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Deprecation {
    /// When this API version was (or will be) deprecated, as an
    /// IMF-fixdate HTTP-date (`Sun, 06 Nov 1994 08:49:37 GMT`). Emits
    /// `Deprecation: @<unix-seconds>` (RFC 9745). A past date is normal
    /// (the deprecation is in effect); a date before 1970 cannot form
    /// the structured date and is rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// When this API version is expected to stop working, as an
    /// IMF-fixdate HTTP-date. Emits `Sunset` (RFC 8594) verbatim.
    /// Validation rejects a date already in the past and a date before
    /// `since`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sunset: Option<String>,
    /// URI of the deprecation/migration notice (absolute `http(s)` URL).
    /// Requires `since` — the RFC 9745 `Link; rel="deprecation"` it
    /// emits documents the `Deprecation` header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

/// Snapshot-compiled form of a [`Deprecation`] block (DW-048): the
/// emitted header VALUES, precomputed at snapshot-compile time — the
/// HTTP-date strings are parsed once here (never per response) and the
/// RFC 9745 structured date is rendered from the parsed seconds. Lives
/// in `config` beside [`CompiledCorsOrigins`] for the same reason:
/// `snapshot` builds it into the route table and `dataplane::versioning`
/// consumes it. Validation has already rejected unparseable dates, so
/// compilation drops nothing on any publishable config; entries that
/// would fail are skipped exactly like the CORS matcher's fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledDeprecation {
    deprecation: Option<String>,
    sunset: Option<String>,
    link: Option<String>,
}

impl CompiledDeprecation {
    /// Compile a (validated) policy's header values.
    pub fn compile(dep: &Deprecation) -> Self {
        CompiledDeprecation {
            deprecation: dep
                .since
                .as_deref()
                .and_then(versioning::parse_http_date)
                .filter(|d| d.unix_seconds() >= 0)
                .map(|d| format!("@{}", d.unix_seconds())),
            sunset: dep
                .sunset
                .as_deref()
                .filter(|s| versioning::parse_http_date(s).is_some())
                .map(str::to_string),
            link: dep
                .uri
                .as_deref()
                .map(|uri| format!("<{uri}>; rel=\"deprecation\"")),
        }
    }

    /// The `Deprecation` header value (`@<unix-seconds>`), if the policy
    /// sets `since`.
    pub fn deprecation_header(&self) -> Option<&str> {
        self.deprecation.as_deref()
    }

    /// The `Sunset` header value (the validated config string, verbatim),
    /// if the policy sets `sunset`.
    pub fn sunset_header(&self) -> Option<&str> {
        self.sunset.as_deref()
    }

    /// The `Link` header value (`<uri>; rel="deprecation"`), if the
    /// policy sets `uri`.
    pub fn link_header(&self) -> Option<&str> {
        self.link.as_deref()
    }
}

/// Route-level authorization rules (DW-020, feature analysis 4.7).
///
/// Rule semantics (frozen here; evaluation lives in the `authz` module):
///
/// - `denied_consumers` / `denied_groups` beat `allowed_*` at the SAME
///   level: within one [`Authz`], a deny always wins a tie.
/// - `allowed_consumers`, when non-empty, is a closed set: the
///   authenticated consumer must be listed. Empty = any authenticated
///   consumer passes the consumer rule.
/// - `allowed_groups`, when non-empty, requires the consumer to be a
///   member of at least one listed group. Group membership comes from
///   the CONFIG consumer's `groups` field; store-only consumers
///   (DWARA_STATE_DB deployments whose consumer has no config entry)
///   have no groups and therefore never satisfy an `allowed_groups`
///   rule (documented limitation until the state store carries groups).
/// - `required_scopes`: every listed scope must appear in the JWT
///   `scope` claim. The claim may be a space-separated string
///   (`"read write"`, the OAuth convention) or a JSON array of strings
///   (`["read", "write"]`, joined to its space-separated form when the
///   identity's claims are captured in `authn`); non-JWT identities
///   (API key / Basic) carry no claims and never satisfy scope rules.
/// - `required_claims`: exact string equality on the stringified claim
///   value; a claim absent from the token fails the match. Only
///   string- and number-valued claims are captured on the identity
///   (see `authn`), so a claim that is a JSON `true`/`false`, `null`,
///   object, or nested structure can NEVER satisfy a `required_claims`
///   entry — there is no stringified form to compare. Comparisons are
///   CASE-SENSITIVE throughout: consumer names, groups, scopes, and
///   claim values must match byte-for-byte.
/// - `ip_acl`: evaluated against the EFFECTIVE client IP — the
///   `X-Forwarded-For`-resolved client when the direct peer is inside
///   `gateway.trusted_proxies` (DW-009 chain), otherwise the direct
///   peer. See [`IpAcl`].
///
/// Authentication implication: an [`Authz`] carrying ANY identity rule
/// (consumer/group/scope/claim) rejects anonymous requests with 401; an
/// `ip_acl`-only [`Authz`] is the one authorization shape that can
/// ADMIT anonymous traffic (from an IP the ACL allows). A denial of an
/// AUTHENTICATED request is 403 (forbidden), never 401.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Authz {
    /// Consumers allowed to call the route (empty = any authenticated).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_consumers: Vec<String>,
    /// Consumers explicitly rejected, even when otherwise allowed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_consumers: Vec<String>,
    /// Groups allowed to call the route (empty = no group constraint).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_groups: Vec<String>,
    /// Groups explicitly rejected, even when otherwise allowed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_groups: Vec<String>,
    /// JWT scopes (from the `scope` claim) every request must carry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_scopes: Vec<String>,
    /// Claims (name -> exact stringified value) every request must
    /// carry. A listed claim absent from the token's claims fails.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub required_claims: std::collections::BTreeMap<String, String>,
    /// IP allow/deny gate on the effective client IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_acl: Option<IpAcl>,
    /// GeoIP gate on the effective client IP (DW-050): country/ASN
    /// allow and deny lists resolved through `gateway.geoip`'s
    /// database. An address the database does not resolve (private
    /// ranges, not-in-DB, no database loaded) is UNKNOWN and matches
    /// NEITHER list: deny-lists keep passing unknowns, allow-lists
    /// keep rejecting them. Requires a `gateway.geoip` block —
    /// validation rejects the predicate without one. See
    /// [`GeoipRules`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip: Option<GeoipRules>,
    /// Monitor mode (DW-041): evaluate this block's rules, LOG and count
    /// every would-be denial (the `dwara_policy_dry_run_total{phase=
    /// "authz"}` counter plus a `dwara::policy` warn event), but let the
    /// request PROCEED as if allowed. The flag is per ATTACHMENT and
    /// mutes only this block's OWN denials: a LIVE deny at any other
    /// level of the chain still enforces (dry run never makes
    /// enforcement more permissive — the resolver walks past a dry deny
    /// and stops only at a live one). Route `auth_required` is an
    /// authentication-phase check, not an authorization rule, and is
    /// never muted by this flag.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
}

/// IP access control on the effective client IP (DW-020, feature
/// analysis 4.15). Entries are IP addresses (e.g. `10.1.2.3`) or CIDRs
/// (e.g. `10.0.0.0/8`); anything else fails config validation (the same
/// parser as `gateway.trusted_proxies`). Evaluation order: the `deny`
/// list first (a match rejects with 403 regardless of the allow list),
/// then the `allow` list, then `default` for IPs matched by neither.
///
/// A `/0` (all-addresses) entry such as `0.0.0.0/0` or `::/0` is
/// REJECTED by validation in the `allow` list: an allow-all entry
/// filters nothing and is always a mistake — the intended shape is an
/// empty allow list with `default: allow` (the ACL's default mode).
/// A `/0` in the `deny` list is meaningful (deny-all) and is accepted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpAcl {
    /// CIDRs/IPs allowed through the gate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// CIDRs/IPs rejected; a deny match wins over any allow match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// What happens to an IP matched by NEITHER list: `allow` (the
    /// default — the lists are exceptions) or `deny` (closed mode — only
    /// allow-listed IPs pass).
    #[serde(
        default = "default_ip_acl_default",
        skip_serializing_if = "is_default_ip_acl_default"
    )]
    pub default: IpAclDefault,
}

/// Fallback decision of an [`IpAcl`] for IPs matched by neither list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum IpAclDefault {
    /// Unmatched IPs pass the IP gate (the default).
    Allow,
    /// Unmatched IPs are rejected: only the allow list passes.
    Deny,
}

fn default_ip_acl_default() -> IpAclDefault {
    IpAclDefault::Allow
}

fn is_default_ip_acl_default(d: &IpAclDefault) -> bool {
    *d == IpAclDefault::Allow
}

/// Route-scoped CORS policy (DW-027, feature analysis 4.14).
///
/// Semantics (frozen; evaluation lives in `dataplane::cors`):
///
/// - `allowed_origins` is a closed set of exact origins
///   (`https://api.example.com`, scheme + host + optional port, compared
///   in normalized form: lowercase scheme/host, default port dropped) or
///   the single entry `*` (any origin). It must be non-empty; `*`
///   combined with `allow_credentials: true` is rejected by validation
///   (the Fetch spec forbids wildcard-credentialed responses).
/// - A PREFLIGHT (`OPTIONS` + `Origin` + `Access-Control-Request-Method`)
///   on a CORS-configured route is answered 204 by the gateway —
///   validated against the policy, never forwarded upstream, and never
///   subject to authn/authz/rate limiting (browsers send preflights
///   without credentials). A preflight that fails validation (origin,
///   method, or requested headers not allowed) still short-circuits:
///   204 with NO CORS headers, which the browser reads as a failed
///   preflight. A plain `OPTIONS` without the preflight markers is NOT
///   intercepted; it proxies normally.
/// - ACTUAL responses on the route carry `Access-Control-Allow-Origin`
///   (`*`, or the echoed request origin when the list is specific),
///   `Access-Control-Allow-Credentials: true` when configured,
///   `Access-Control-Expose-Headers` when configured, and `Vary: Origin`
///   (merged into any existing `Vary`). A request whose `Origin` is not
///   allowed simply gets no CORS headers — the response passes through
///   as-is (same-origin reads do not consult CORS at all).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Cors {
    /// Origins allowed to call this route cross-origin: exact origin
    /// strings (`https://api.example.com`, `http://localhost:8080`) or
    /// `*` (any origin; never together with `allow_credentials`).
    pub allowed_origins: Vec<String>,
    /// Methods allowed for cross-origin requests (preflight echo and
    /// actual-request check). Default: the common API set
    /// GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS. Each entry must be a
    /// valid HTTP method token; comparison is case-insensitive.
    #[serde(default = "default_cors_methods")]
    pub allowed_methods: Vec<String>,
    /// Request headers clients may send: exact header names, or `*` to
    /// allow any requested header (never `*` together with
    /// `allow_credentials`). Validated against the preflight's
    /// `Access-Control-Request-Headers` list; empty means no headers
    /// beyond the CORS-safelisted set are permitted in preflight checks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_headers: Vec<String>,
    /// Response headers exposed to the browser (readable by cross-origin
    /// client script). Absent: only the CORS-safelisted response headers
    /// are exposed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expose_headers: Vec<String>,
    /// Allow credentialed cross-origin requests (cookies, TLS client
    /// certificates). Default false. When true, the origin list must be
    /// specific (`*` is rejected by validation) and responses echo the
    /// request origin rather than sending `*`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_credentials: bool,
    /// `Access-Control-Max-Age` for preflight responses, in seconds (how
    /// long the browser may cache the preflight result). Absent: the
    /// header is omitted (each preflight hits the gateway).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_secs: Option<u64>,
}

fn default_cors_methods() -> Vec<String> {
    ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Canonical form of one origin (DW-027): lowercase scheme and host,
/// default port dropped, no userinfo, no path/query — the exact string
/// the runtime CORS matcher compares request `Origin` values against
/// and validation checks config entries with. `None` when the input is
/// not a well-formed `http(s)` origin. Lives in `config` (the lowest
/// consuming domain) so validation (`snapshot::validate`) and matching
/// (`dataplane::cors`) share one grammar, the same way `net.rs` owns the
/// IP/CIDR grammar.
pub fn normalize_origin(origin: &str) -> Option<String> {
    let uri: hyper::Uri = origin.parse().ok()?;
    let scheme = uri.scheme()?;
    if !matches!(scheme.as_str(), "http" | "https") {
        return None;
    }
    // Browsers never serialize userinfo into an Origin (the grammar is
    // scheme "://" host [":" port]); authority userinfo is a config
    // authoring error or a smuggle attempt, never a real origin.
    if uri.authority().is_some_and(|a| a.as_str().contains('@')) {
        return None;
    }
    let host = uri.host()?;
    let default_port = match scheme.as_str() {
        "http" => 80,
        _ => 443,
    };
    let port = uri
        .port_u16()
        .and_then(|p| (p != default_port).then_some(p));
    // An origin carries no path, query, or fragment; tolerate only the
    // empty path "/" (browsers serialize the origin WITHOUT it, but
    // configs hand-writing "https://host/" are unambiguous).
    match uri.path_and_query() {
        None => {}
        Some(pq) if pq.as_str() == "/" => {}
        _ => return None,
    }
    Some(match port {
        Some(p) => format!("{}://{}:{}", scheme.as_str(), host.to_lowercase(), p),
        None => format!("{}://{}", scheme.as_str(), host.to_lowercase()),
    })
}

/// Snapshot-compiled form of a `cors.allowed_origins` list (DW-027): the
/// wildcard flag plus the normalized form of every specific entry,
/// computed once at snapshot-compile time so the request path never
/// re-parses config strings (per-request work is the request's own
/// origin only). Lives in `config` beside [`normalize_origin`] because
/// the compiled set is the grammar's runtime consumer: `snapshot`
/// builds it into the route table (`snapshot::RouteTable`) and
/// `dataplane::cors` matches against it. Validation has already
/// rejected entries that do not normalize, so compilation drops
/// nothing on any publishable config; entries that would fail
/// normalization are skipped exactly as the pre-compiled matcher was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledCorsOrigins {
    wildcard: bool,
    origins: Vec<String>,
}

impl CompiledCorsOrigins {
    /// Compile a (validated) policy's origin list.
    pub fn compile(cors: &Cors) -> Self {
        CompiledCorsOrigins {
            wildcard: cors.allowed_origins.iter().any(|o| o == "*"),
            origins: cors
                .allowed_origins
                .iter()
                .filter(|o| *o != "*")
                .filter_map(|o| normalize_origin(o))
                .collect(),
        }
    }

    /// Does a request `Origin` value match this set? `*` matches any
    /// origin string; otherwise normalized exact match (the same
    /// comparison the pre-compiled matcher ran, without re-normalizing
    /// the config side per request).
    pub fn allows(&self, origin: &str) -> bool {
        if self.wildcard {
            return true;
        }
        let Some(request_origin) = normalize_origin(origin) else {
            return false;
        };
        self.origins.iter().any(|o| o == &request_origin)
    }

    /// Was the list the single entry `*`?
    pub fn wildcard(&self) -> bool {
        self.wildcard
    }
}

/// Route-scoped response compression policy (DW-027, feature analysis
/// 4.13).
///
/// Semantics (frozen; negotiation and encoding live in
/// `dataplane::compression`):
///
/// - `algorithms` is the PREFERENCE order: the first entry the request's
///   `Accept-Encoding` accepts wins. `q=0` entries in `Accept-Encoding`
///   are treated as refusal.
/// - `level` is clamped per algorithm at encode time (gzip 0-9, brotli
///   0-11, zstd 0-22; validation bounds the field to 0-22). Absent: the
///   algorithm's library default.
/// - `min_size` skips compression of responses whose size is known and
///   below it — a declared `Content-Length` or the exact size of the
///   gateway's own respond/redirect bodies. Responses of UNKNOWN length
///   (streaming) are always candidates.
/// - `content_types` (when non-empty) restricts compression to responses
///   whose `Content-Type` starts with one of the entries; entries are
///   lowercase prefix matches (e.g. `text/`). `excluded_content_types`
///   is checked after the include list and wins (the way to express
///   "compress everything text/ except `text/event-stream`").
/// - Responses carrying an existing `Content-Encoding`, 1xx/204/304
///   statuses, zero-length bodies, and 101 upgrade responses are never
///   compressed. `Vary: Accept-Encoding` is merged into every response
///   on a compression-configured route that is not already encoded —
///   compressed or not — so caches key correctly.
/// - The compressed body streams chunk-by-chunk with a flush per chunk
///   (streaming/SSE-friendly, at a small compression-ratio cost); the
///   gateway never buffers the whole body to compress it. The frame
///   codec's internal buffer is bounded by the chunk size.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Compression {
    /// Enabled algorithms in preference order (default gzip, brotli,
    /// zstd). Must be non-empty and duplicate-free (validation).
    #[serde(default = "default_compression_algorithms")]
    pub algorithms: Vec<CompressionAlgorithm>,
    /// Compression level; clamped per algorithm (gzip <= 9, brotli <= 11,
    /// zstd <= 22). Absent: library default per algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    /// Minimum response size (bytes) to compress, applied whenever the
    /// size is known: a declared `Content-Length` or the body's exact
    /// size (the gateway's own respond/redirect bodies, which carry no
    /// `Content-Length`). Below it the response passes through (still
    /// carrying `Vary: Accept-Encoding`). Default 1024. Responses of
    /// unknown length (streaming) are always candidates.
    #[serde(default = "default_compression_min_size")]
    pub min_size: u64,
    /// Content-Type prefix include list (lowercase, e.g. `text/`,
    /// `application/json`); empty = every content type is a candidate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content_types: Vec<String>,
    /// Content-Type prefix exclude list, checked after `content_types`;
    /// a match passes the response through uncompressed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_content_types: Vec<String>,
}

fn default_compression_algorithms() -> Vec<CompressionAlgorithm> {
    vec![
        CompressionAlgorithm::Gzip,
        CompressionAlgorithm::Brotli,
        CompressionAlgorithm::Zstd,
    ]
}

fn default_compression_min_size() -> u64 {
    1024
}

/// One response compression algorithm (DW-027).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum CompressionAlgorithm {
    Gzip,
    Brotli,
    Zstd,
}

impl CompressionAlgorithm {
    /// The `Accept-Encoding` / `Content-Encoding` token of the algorithm.
    pub fn encoding_token(self) -> &'static str {
        match self {
            CompressionAlgorithm::Gzip => "gzip",
            CompressionAlgorithm::Brotli => "br",
            CompressionAlgorithm::Zstd => "zstd",
        }
    }
}

/// Snapshot-compiled form of a compression policy's content-type prefix
/// lists (DW-027): every include/exclude entry trimmed and lowercased
/// once at snapshot-compile time; the request path compares the
/// response's (lowercased) media type against the precomputed prefixes
/// instead of re-normalizing config strings per response. Same
/// placement rationale as [`CompiledCorsOrigins`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledContentTypeFilter {
    include: Vec<String>,
    exclude: Vec<String>,
}

impl CompiledContentTypeFilter {
    /// Compile a (validated) policy's prefix lists.
    pub fn compile(policy: &Compression) -> Self {
        fn normalize_list(list: &[String]) -> Vec<String> {
            list.iter().map(|p| p.trim().to_lowercase()).collect()
        }
        CompiledContentTypeFilter {
            include: normalize_list(&policy.content_types),
            exclude: normalize_list(&policy.excluded_content_types),
        }
    }

    /// Is `media_type` (lowercase, parameters stripped) a compression
    /// candidate? An empty include list admits every type; the exclude
    /// list is checked after it and wins.
    pub fn allows(&self, media_type: &str) -> bool {
        (self.include.is_empty() || self.include.iter().any(|p| media_type.starts_with(p)))
            && !self.exclude.iter().any(|p| media_type.starts_with(p))
    }
}

/// Route-scoped request size limits (DW-027, feature analysis 4.16).
///
/// Semantics (frozen; enforcement lives in `dataplane::hardening`):
///
/// - Header limits (`max_header_count`, `max_header_bytes`) are checked
///   immediately after route resolution, before CORS preflight handling
///   and authentication; a violation answers 431 with the JSON error
///   envelope. `max_header_bytes` is the SUM of all header name and
///   value bytes of the request (hyper's per-connection buffer limits
///   still apply beneath this, process-wide).
/// - `max_body_bytes`: a request whose `Content-Length` declares more is
///   rejected 413 before any upstream contact. A body of UNKNOWN length
///   (chunked / h2 without content-length) is wrapped in a counting
///   guard: crossing the cap aborts the request (the upstream attempt
///   fails; the client receives 413 when the failure precedes the
///   upstream's response headers, a torn stream otherwise).
/// - A block with NO field set is rejected by validation (always an
///   authoring mistake; omit the block).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestLimits {
    /// Maximum request body size in bytes (declared via `Content-Length`
    /// or enforced streaming). Absent: unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
    /// Maximum number of header fields on the request. Absent:
    /// unlimited (hyper's parser bound applies).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_header_count: Option<u32>,
    /// Maximum total size of request headers (names + values, bytes).
    /// Absent: unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_header_bytes: Option<u64>,
    /// Monitor mode (DW-041): evaluate the limits, LOG and count every
    /// would-be rejection (`dwara_policy_dry_run_total{phase="route_
    /// limits"}` + a `dwara::policy` warn event), but let the request
    /// PROCEED — including its body: the streaming `max_body_bytes` guard
    /// is not armed, so a chunked body that would have been aborted mid-
    /// stream streams through (only the cheap up-front checks — header
    /// count/bytes, a declared `Content-Length` — are observable in dry
    /// run). The staging tool for turning limits on against live traffic
    /// without breaking clients.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
}

/// Matching rules for incoming requests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteMatch {
    pub path: PathMatch,
    /// Exact host match (e.g. `api.example.com`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Allowed HTTP methods; empty means all methods.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Exact header matches.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub headers: std::collections::BTreeMap<String, String>,
    /// Query-parameter matches; every entry must match (AND). Name-only
    /// entries match on presence; a `value` requires an exact raw match (no
    /// percent-decoding in v1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query: Vec<NameValueMatch>,
    /// Cookie matches (parsed from the `Cookie` header); every entry must
    /// match (AND). Name-only entries match on presence; a `value` requires
    /// an exact match (no cookie-unquoting in v1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cookies: Vec<NameValueMatch>,
    /// Media-type version selection (DW-048): a bare `type/subtype` the
    /// request's `Accept` header must name explicitly, e.g.
    /// `application/vnd.acme.v2+json`. A comma-separated Accept list
    /// matches on ANY entry; parameters and q-values on the request side
    /// are ignored; wildcard entries (`*/*`, `type/*`) and a missing
    /// Accept header never match — version selection requires the client
    /// to NAME the version, so unconstrained clients fall through to the
    /// route without this criterion (the unversioned default). Like every
    /// non-path criterion this is AND-ed and applied AFTER path
    /// resolution: a miss does not fall through to another route (404),
    /// and two routes cannot share one path to offer multiple versions —
    /// version families use distinct paths (`/v1/`, `/v2/`) or this
    /// criterion on a versioned path. Validation rejects anything but a
    /// bare lowercase-able `type/subtype` (`config::versioning` owns the
    /// grammar). Responses of a matched route carry `Vary: Accept`
    /// (merged), so shared caches key on the negotiated representation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept: Option<String>,
}

/// One query-parameter or cookie criterion: the parameter/cookie must be
/// present; when `value` is given it must equal that exact string.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NameValueMatch {
    pub name: String,
    /// Exact value required; `None` means "present is enough".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// How a route's path pattern is interpreted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathMatch {
    #[serde(rename = "type")]
    pub kind: PathMatchKind,
    /// The pattern value, e.g. `/v1/users` or `/v1/.*`.
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PathMatchKind {
    Exact,
    Prefix,
    Regex,
}

/// What the gateway does when a route matches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteAction {
    /// Forward to the route's service (its upstream).
    ///
    /// `rewrite` (at most ONE per action in v1) is applied to the inbound
    /// path before the request is sent upstream; the query string is always
    /// preserved verbatim.
    Proxy {
        #[serde(skip_serializing_if = "Option::is_none")]
        rewrite: Option<PathRewrite>,
    },
    Redirect {
        #[serde(skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        status: u16,
    },
    Respond {
        status: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        body: Option<String>,
        /// Extra response headers (name -> value), emitted verbatim.
        #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        headers: std::collections::BTreeMap<String, String>,
    },
}

/// Path rewrite applied before proxying (DW-010). Exactly one variant per
/// proxy action; there is no rewrite chaining in v1. All variants operate
/// on the path component only — the inbound query string is re-attached
/// untouched.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PathRewrite {
    /// Strip the route's matched prefix (the `match.path.value` with
    /// trailing slashes trimmed) from the front of the request path.
    /// Meaningful for prefix-kind routes; for other kinds it strips the
    /// pattern's byte length when the path starts with the pattern value
    /// and is a no-op otherwise. If nothing remains (or the remainder
    /// lacks a leading `/`), the result is normalized to `/rest`.
    StripPrefix {},
    /// Replace a literal prefix: when the request path starts with
    /// `prefix`, that prefix is replaced by `replacement`; otherwise this
    /// rewrite is a no-op (the path is forwarded unchanged).
    ReplacePrefix { prefix: String, replacement: String },
    /// Replace the FIRST regex match on the request path with
    /// `substitution`. Substitution references: `$1`..`$9` / `${n}` for
    /// capture groups of `pattern`; `$name` / `${name}` for named capture
    /// groups of `pattern`, falling back to path parameters captured by
    /// the route's `{param}` template. Unknown references expand to the
    /// empty string. The pattern must compile — checked at config compile
    /// time, never at request time.
    Regex {
        pattern: String,
        substitution: String,
    },
}

/// The logical API being exposed: base path, version, default policies;
/// targets exactly one upstream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub name: String,
    /// Name of the upstream this service targets.
    pub upstream: String,
    /// Base path prefix the API is served under (e.g. `/v1`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// Service-level authorization rules (#123): applies to every request
    /// whose route targets this service. Link of the frozen chain
    /// consumer > route > service > listener > global (a deny at any
    /// level wins; otherwise the most specific level with rules governs —
    /// see [`Authz`] and the `authz` module). Same validation rules as
    /// route-level authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authz>,
}

/// Load-balancing pool: algorithm, protocol, endpoints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    #[serde(default = "default_load_balancer")]
    pub load_balancer: LoadBalancer,
    /// Protocol used toward upstream endpoints.
    #[serde(default = "default_upstream_protocol")]
    pub protocol: UpstreamProtocol,
    /// Path to a PEM file of CA certificates this upstream's TLS
    /// connections trust INSTEAD of the default public (webpki) root set
    /// (#121): the way to proxy an `https`/`http2` upstream whose server
    /// certificate chains to a private CA. The file may carry several
    /// certificates (a typical CA bundle). Only meaningful for the TLS
    /// protocols — no TLS is negotiated toward `http1` endpoints, so
    /// validation rejects that combination. Active `http` health probes
    /// for this upstream verify against the same roots. The file must
    /// exist and be readable at config compile time; validation names
    /// this field otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_ca_file: Option<String>,
    pub endpoints: Vec<Endpoint>,
    /// Maximum number of concurrent outbound connections to this upstream
    /// (active plus pooled idle). Defaults to 64 when absent. Enforced by
    /// the upstream client (DW-008); excess connection attempts wait for a
    /// slot rather than fail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_cap: Option<u32>,
    /// Slow-start window in milliseconds (DW-011): an endpoint entering the
    /// upstream's set ramps its effective load-balancing weight from ~0 up
    /// to its configured weight over this window. Absent (or 0) disables
    /// the ramp. Applies to the weighted algorithms (round_robin; ip_hash
    /// vnode counts stay fixed so ring consistency is preserved).
    /// Validation bounds the value to at most 10 minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slow_start_ms: Option<u64>,
    /// Passive health checking / outlier detection (DW-012): eject
    /// endpoints that fail real traffic (transport errors and 5xx), let
    /// them back via half-open trial probes after `eject_ms`. Absent
    /// disables passive health entirely (no ejections).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<PassiveHealth>,
    /// Active health checks (DW-013): synthetic HTTP/TCP probes per
    /// endpoint on a fixed interval with full jitter. Probe results report
    /// into the SAME per-endpoint ejection machinery as passive health, so
    /// an endpoint failing its probes leaves load-balancer rotation and a
    /// success streak returns it. Requires the passive `health` block
    /// (which owns the ejection/recovery windows); rejected by validation
    /// otherwise. Absent disables active probing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_health: Option<ActiveHealth>,
    /// Upstream retries (DW-014): bounded per-request retry attempts with
    /// exponential backoff + full jitter, a retry budget, and opt-in
    /// size-capped request-body buffering. Absent (or `attempts` left at
    /// its default 0) disables retries entirely: every request gets exactly
    /// one attempt and the proxy path keeps its zero-copy streaming body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<RetryConfig>,
    /// Per-upstream circuit breaker (DW-015): opens the WHOLE upstream on
    /// consecutive failures or a rolling error ratio, fails fast with 503
    /// while open, probes half-open after `breaker.open_ms`. Absent
    /// disables the breaker entirely (no fail-fast, behavior identical to
    /// pre-DW-015).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breaker: Option<BreakerConfig>,
    /// Maximum number of requests WAITING for an outbound connection slot
    /// to this upstream (DW-015). 0/absent (the default) means unbounded
    /// queueing — the DW-008 `connection_cap` behavior. A positive value
    /// rejects excess requests IMMEDIATELY with 503 "upstream saturated"
    /// instead of letting them wait.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pending: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<Timeouts>,
}

/// Upstream retry knobs (DW-014). All fields default; a `retries:` block
/// with no keys is equivalent to retries off (`attempts` defaults to 0).
///
/// Frozen semantics (see `upstream`/`proxy`/`retries` module docs):
/// - `attempts` is the maximum number of RETRIES beyond the first attempt
///   (0 = off). Validation caps it at 10.
/// - Only requests whose body was fully buffered within `buffer_max_bytes`
///   may be retried; an over-cap body streams without retry. Buffering is
///   opt-in: the default (0) buffers only empty bodies, so the default
///   proxy path stays unbuffered.
/// - Retries happen strictly BEFORE response headers arrive on the final
///   attempt; a response body that dies mid-stream is never retried (its
///   failure is reported to passive health instead).
/// - Every retried attempt is charged against the upstream's rolling-window
///   retry budget (`budget_percent`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetryConfig {
    /// Maximum retries beyond the first attempt (default 0 = off).
    #[serde(default = "default_retry_attempts")]
    pub attempts: u32,
    /// Retry non-idempotent POST requests. Default false: POST is never
    /// retried unless an operator explicitly opts in here (a retried POST
    /// may replay a body the upstream already partially processed).
    #[serde(default = "default_retry_post", skip_serializing_if = "is_false")]
    pub retry_post: bool,
    /// Exponential backoff base in milliseconds (default 25): the nominal
    /// delay before retry n is `min(base * 2^(n-1), backoff_cap_ms)`.
    #[serde(default = "default_retry_backoff_base_ms")]
    pub backoff_base_ms: u64,
    /// Exponential backoff ceiling in milliseconds (default 250). Must be
    /// >= `backoff_base_ms`.
    #[serde(default = "default_retry_backoff_cap_ms")]
    pub backoff_cap_ms: u64,
    /// Response statuses that trigger a retry when received as the upstream
    /// response status (default `[502, 503, 504]`). Each entry must be a
    /// valid 4xx/5xx status. An empty list disables status-based retries.
    #[serde(default = "default_retry_statuses")]
    pub retry_statuses: Vec<u16>,
    /// Retry on transport errors (connect timeout/refusal/reset/framing)
    /// and per-attempt read timeouts (default true).
    #[serde(default = "default_retry_transport", skip_serializing_if = "is_true")]
    pub retry_transport: bool,
    /// Retry budget: the maximum percentage of requests to this upstream,
    /// in a rolling window, that may be retries (default 10). Must be in
    /// (0, 100]. When the budget is exhausted, failing requests fail
    /// through to the client instead of retrying.
    #[serde(default = "default_retry_budget_percent")]
    pub budget_percent: u32,
    /// Request-body buffering cap in bytes (default 0 = no buffering). A
    /// request body is buffered (and becomes replayable) only while it fits
    /// within this cap; larger bodies stream and are never retried.
    #[serde(default)]
    pub buffer_max_bytes: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        RetryConfig {
            attempts: default_retry_attempts(),
            retry_post: default_retry_post(),
            backoff_base_ms: default_retry_backoff_base_ms(),
            backoff_cap_ms: default_retry_backoff_cap_ms(),
            retry_statuses: default_retry_statuses(),
            retry_transport: default_retry_transport(),
            budget_percent: default_retry_budget_percent(),
            buffer_max_bytes: 0,
        }
    }
}

fn default_retry_attempts() -> u32 {
    0
}

fn default_retry_post() -> bool {
    false
}

fn default_retry_backoff_base_ms() -> u64 {
    25
}

fn default_retry_backoff_cap_ms() -> u64 {
    250
}

fn default_retry_statuses() -> Vec<u16> {
    vec![502, 503, 504]
}

fn default_retry_transport() -> bool {
    true
}

fn default_retry_budget_percent() -> u32 {
    10
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Per-upstream circuit breaker knobs (DW-015). All fields default; a
/// `breaker:` block with no keys enables the breaker with the defaults.
///
/// Frozen semantics (see the `breaker` module docs):
/// - The breaker gates the WHOLE upstream (all endpoints); per-endpoint
///   ejection (DW-012) is an independent layer beneath it.
/// - It opens on `consecutive_failures` consecutive failures (5xx or
///   transport) OR an in-window error ratio >= `error_ratio` once at least
///   `error_volume` observations are in the 60 s window.
/// - While open, requests fail fast with 503 and a `Retry-After` header
///   (seconds until half-open); in-flight requests complete normally.
/// - After `open_ms` a half-open probe (`half_open_probes` concurrent
///   trials) closes the breaker on success or re-opens it on failure.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BreakerConfig {
    /// Consecutive failures (5xx + transport) that open the breaker
    /// (default 5).
    #[serde(default = "default_breaker_consecutive_failures")]
    pub consecutive_failures: u32,
    /// In-window error ratio in (0, 1] that opens the breaker once
    /// `error_volume` observations exist (default 0.5).
    #[serde(default = "default_breaker_error_ratio")]
    pub error_ratio: f64,
    /// Minimum observations in the 60 s window before the ratio is
    /// evaluated (default 20).
    #[serde(default = "default_breaker_error_volume")]
    pub error_volume: u32,
    /// Cooling-off period in milliseconds before a half-open probe is
    /// admitted (default 30000).
    #[serde(default = "default_breaker_open_ms")]
    pub open_ms: u64,
    /// Concurrent trial requests admitted in half-open (default 1).
    #[serde(default = "default_breaker_half_open_probes")]
    pub half_open_probes: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        BreakerConfig {
            consecutive_failures: default_breaker_consecutive_failures(),
            error_ratio: default_breaker_error_ratio(),
            error_volume: default_breaker_error_volume(),
            open_ms: default_breaker_open_ms(),
            half_open_probes: default_breaker_half_open_probes(),
        }
    }
}

fn default_breaker_consecutive_failures() -> u32 {
    5
}

fn default_breaker_error_ratio() -> f64 {
    0.5
}

fn default_breaker_error_volume() -> u32 {
    20
}

fn default_breaker_open_ms() -> u64 {
    30_000
}

fn default_breaker_half_open_probes() -> u32 {
    1
}

fn is_true(b: &bool) -> bool {
    *b
}

/// Passive health / outlier detection knobs (DW-012). All fields default;
/// a `health:` block with no keys enables ejection with the defaults.
///
/// Failure classification: transport errors (connect timeout, refusal,
/// reset) and HTTP statuses >= 500 are failures; 1xx-4xx are successes.
/// 429/408 are deliberately successes in v1 (they describe the caller or
/// queueing, not endpoint health).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PassiveHealth {
    /// Rolling observation window for the failure ratio, in milliseconds
    /// (default 60000).
    #[serde(default = "default_health_window_ms")]
    pub window_ms: u64,
    /// Eject after this many consecutive failures (default 5).
    #[serde(default = "default_health_consecutive_failures")]
    pub consecutive_failures: u32,
    /// Eject when the in-window failure share is >= this ratio AND volume
    /// is >= `failure_min_volume`. Must be in (0, 1] (default 0.5).
    #[serde(default = "default_health_failure_ratio")]
    pub failure_ratio: f64,
    /// Minimum observations in the window before `failure_ratio` applies
    /// (default 20).
    #[serde(default = "default_health_failure_min_volume")]
    pub failure_min_volume: u32,
    /// How long an ejected endpoint stays out of rotation, in milliseconds
    /// (default 30000).
    #[serde(default = "default_health_eject_ms")]
    pub eject_ms: u64,
    /// Trial requests allowed through per half-open recovery attempt
    /// (default 1). A successful probe restores health; a failed probe
    /// re-ejects for another `eject_ms`.
    #[serde(default = "default_health_half_open_probes")]
    pub half_open_probes: u32,
}

impl Default for PassiveHealth {
    fn default() -> Self {
        PassiveHealth {
            window_ms: 60_000,
            consecutive_failures: 5,
            failure_ratio: 0.5,
            failure_min_volume: 20,
            eject_ms: 30_000,
            half_open_probes: 1,
        }
    }
}

fn default_health_window_ms() -> u64 {
    60_000
}

fn default_health_consecutive_failures() -> u32 {
    5
}

fn default_health_failure_ratio() -> f64 {
    0.5
}

fn default_health_failure_min_volume() -> u32 {
    20
}

fn default_health_eject_ms() -> u64 {
    30_000
}

fn default_health_half_open_probes() -> u32 {
    1
}

/// Active health check knobs (DW-013). A block with no keys enables HTTP
/// probes with the defaults.
///
/// Probe semantics (frozen):
/// - `http` probes issue `GET {path}` over HTTP/1.1 DIRECTLY to the
///   endpoint (bypassing load balancing and the pooled client); success is
///   a 2xx status. Redirects (3xx) are NOT followed — a health endpoint
///   answering 3xx is treated as a failure (a load balancer must not chase
///   redirects to decide health).
/// - `tcp` probes succeed when a TCP connection completes within
///   `timeout_ms`.
/// - Full jitter: each loop sleeps `interval_ms` plus a uniform random
///   `0..jitter_ms` before the next probe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActiveHealth {
    /// Probe kind (default `http`).
    #[serde(default = "default_probe_kind")]
    pub kind: ProbeKind,
    /// Path probed by `http` checks (default `/healthz`). Ignored by `tcp`.
    #[serde(
        default = "default_probe_path",
        skip_serializing_if = "is_default_probe_path"
    )]
    pub path: String,
    /// Time between probe attempts in milliseconds (default 5000). Must be
    /// >= `timeout_ms` and >= `jitter_ms`.
    #[serde(default = "default_probe_interval_ms")]
    pub interval_ms: u64,
    /// Per-probe timeout in milliseconds (default 2000), covering connect
    /// plus the response for http probes.
    #[serde(default = "default_probe_timeout_ms")]
    pub timeout_ms: u64,
    /// Consecutive probe SUCCESSES required to (re)admit an ejected
    /// endpoint (default 2).
    #[serde(default = "default_probe_success_threshold")]
    pub success_threshold: u32,
    /// Consecutive probe FAILURES required to eject a healthy endpoint
    /// (default 3). Reports the same per-endpoint streak the passive
    /// checker uses; see the active-health module docs for precedence.
    #[serde(default = "default_probe_failure_threshold")]
    pub failure_threshold: u32,
    /// Full-jitter bound in milliseconds (default 500): each loop sleeps a
    /// uniform random `0..jitter_ms` in addition to `interval_ms`. Must be
    /// <= `interval_ms`.
    #[serde(default = "default_probe_jitter_ms")]
    pub jitter_ms: u64,
}

impl Default for ActiveHealth {
    fn default() -> Self {
        ActiveHealth {
            kind: default_probe_kind(),
            path: default_probe_path(),
            interval_ms: default_probe_interval_ms(),
            timeout_ms: default_probe_timeout_ms(),
            success_threshold: default_probe_success_threshold(),
            failure_threshold: default_probe_failure_threshold(),
            jitter_ms: default_probe_jitter_ms(),
        }
    }
}

fn default_probe_kind() -> ProbeKind {
    ProbeKind::Http
}

fn default_probe_path() -> String {
    "/healthz".to_string()
}

fn is_default_probe_path(p: &str) -> bool {
    p == "/healthz"
}

fn default_probe_interval_ms() -> u64 {
    5_000
}

fn default_probe_timeout_ms() -> u64 {
    2_000
}

fn default_probe_success_threshold() -> u32 {
    2
}

fn default_probe_failure_threshold() -> u32 {
    3
}

fn default_probe_jitter_ms() -> u64 {
    500
}

/// Kind of active health probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProbeKind {
    /// HTTP/1.1 GET to `path`; success = 2xx.
    Http,
    /// TCP connect within the timeout.
    Tcp,
}

fn default_load_balancer() -> LoadBalancer {
    LoadBalancer::RoundRobin
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancer {
    RoundRobin,
    LeastRequests,
    Random,
    IpHash,
}

fn default_upstream_protocol() -> UpstreamProtocol {
    UpstreamProtocol::Http1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
    Http1,
    Http2,
    Https,
}

/// One `address:port` inside an upstream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
    /// Relative traffic weight (default 1 for all endpoints).
    #[serde(
        default = "default_endpoint_weight",
        skip_serializing_if = "is_default_weight"
    )]
    pub weight: u32,
}

fn default_endpoint_weight() -> u32 {
    1
}

fn is_default_weight(w: &u32) -> bool {
    *w == 1
}

/// Timeout hints, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Timeouts {
    /// Connect timeout in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_ms: Option<u64>,
    /// Read timeout in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_ms: Option<u64>,
    /// Write timeout in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_ms: Option<u64>,
    /// Happy-eyeballs inter-connection delay in milliseconds (DW-030,
    /// RFC 8305): when an endpoint's address resolves to multiple
    /// addresses, the first is dialed immediately and each subsequent
    /// address — alternating address families after the resolver's
    /// first — is diailed this long after the previous START; the first
    /// successful connection wins and cancels the losers. Absent: the
    /// RFC 8305 recommended 250 ms. `0` disables racing (addresses are
    /// tried strictly in resolver order, one at a time). The upstream's
    /// `connect_ms` remains the bound over the WHOLE dial: resolution
    /// plus every interleaved attempt plus, for TLS upstreams, the
    /// handshake. Only the overall dial's single outcome reaches
    /// breaker/passive-health accounting — the losing arms of one dial
    /// are never counted as endpoint failures. Validation bounds the
    /// value to at most 10 minutes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub happy_eyeballs_ms: Option<u64>,
}

/// Identity of an API caller (app/team/user); owns credentials, quotas, and
/// the analytics identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Consumer {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<Credential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// Consumer priority class for load shedding (DW-016): 0 (lowest) to 10
    /// (highest). Stored and validated now; it takes effect only once
    /// authentication (DW-019/DW-020) identifies the consumer on a request —
    /// until then, shedding priority comes from the matched route (or the
    /// default 5). Consumer priority overrides the route's when known, but
    /// it does NOT trigger reserved-bucket carving today — only a
    /// high-priority route does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
    /// Consumer group memberships (DW-020): group names this consumer
    /// belongs to, consulted by authorization `allowed_groups` /
    /// `denied_groups` rules. Empty (the default) = no groups. Group
    /// names are free-form strings; validation checks that authorization
    /// rules referencing groups resolve against at least one consumer's
    /// membership. Store-managed consumers carry their own groups in the
    /// state store (#124) — the group NAMESPACE is shared, but
    /// config-time validation can only see config consumers, so a rule
    /// referencing a group that exists solely on store consumers is
    /// flagged (grant at least one config consumer the same group name,
    /// or accept the issue is a false positive for store-only groups).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// Consumer-level authorization rules (#123): the MOST specific link
    /// of the frozen chain consumer > route > service > listener >
    /// global — applies to every request authenticated as this consumer
    /// (naturally only once authentication has identified it). A deny at
    /// any level wins; otherwise the most specific level with rules
    /// governs (see [`Authz`] and the `authz` module). Same validation
    /// rules as route-level authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authz>,
    /// Request budgets for this consumer (DW-033): a daily and/or
    /// monthly request cap counted in fixed UTC calendar windows
    /// (midnight-to-midnight UTC; the first through the last instant of
    /// the UTC month). Budgets are DISTINCT from rate limits: a rate
    /// limit shapes traffic inside seconds or minutes, a budget bounds
    /// total volume across a day or month, and the two mechanisms run
    /// independently (both apply when both are configured). Enforcement
    /// needs the state store (`DWARA_STATE_DB`) for durable counters —
    /// without one, quota config is inert (logged at request time, see
    /// the `state::quotas` module docs). Store-managed consumers have no
    /// config record, so budgets are config-consumer-only in this
    /// edition; a distributed shared-counter variant is the Ent
    /// follow-up (issue "DW-155").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quotas: Option<ConsumerQuotas>,
}

/// Per-consumer request budgets (DW-033): daily and/or monthly request
/// caps in fixed UTC calendar windows, counted by the state store's
/// quota counters. At least one budget must be set and every set budget
/// must be > 0 (validation); a budget of 0 would deny the consumer's
/// first request and is expressed by omitting the field instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsumerQuotas {
    /// Maximum requests per UTC calendar day (midnight to midnight).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daily_requests: Option<u64>,
    /// Maximum requests per UTC calendar month.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monthly_requests: Option<u64>,
}

/// One authenticator bound to a consumer: API key, JWT issuer/audience
/// binding, mTLS client-certificate match, or HMAC signing key (DW-036).
///
/// `Debug` is manual (DW-045): the api-key and hmac-secret values are
/// SECRET and a derived impl would print them — this keeps the config
/// tree safe to Debug-log as a whole (`Gateway` and every holder derive
/// `Debug` over this type).
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Credential {
    ApiKey {
        /// The API key; hashed at rest by the state layer, never logged.
        /// Either the value INLINE (accepted, but redacted to a
        /// `${redacted:...}` placeholder in every config echo — admin
        /// `GET /config`, DW-045) or a reference resolved at
        /// config-compile time: `${ENV_NAME}` (an environment variable)
        /// or `${file:/path/to/secret}` (one trailing newline trimmed).
        /// References are re-read on every reload; an unresolvable
        /// reference fails validation naming this field.
        key: String,
    },
    /// HMAC request-signing credential (DW-036): the consumer presents
    /// per-request signatures over the canonical string documented in
    /// the `security::authn` module docs, carried in the
    /// `X-Dwara-Signature` header family. Unlike API keys the secret
    /// cannot be hash-at-rest stored — recomputing an HMAC needs the
    /// RAW key bytes — so this credential is config-declared only (the
    /// state store's hashed rows cannot serve it) and the resolved
    /// bytes live solely in the authenticator's memory, zeroized on
    /// drop. The pepper (#124) deliberately does NOT apply here: it
    /// guards stored hashes, and there is no stored hash to guard.
    Hmac {
        /// Public key identifier: the `X-Dwara-Key-Id` header value the
        /// client presents to SELECT this credential (the AWS
        /// access-key-id shape — it names the key, it is not secret).
        /// Non-empty visible ASCII, at most 128 bytes; unique across
        /// every consumer (validation rejects duplicates — an ambiguous
        /// selector cannot pick a consumer deterministically).
        key_id: String,
        /// The HMAC-SHA256 signing secret. INLINE values are accepted
        /// (redacted in every config echo, like api keys) but
        /// `${ENV_NAME}` / `${file:/path/to/secret}` references are the
        /// recommended shape; resolved at config-compile time and
        /// re-read on every reload. Must be non-empty; use at least 32
        /// bytes of entropy (shorter keys weaken the MAC construction
        /// — documented, not enforced, the same posture as the pepper).
        secret: String,
    },
    Jwt {
        issuer: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        audiences: Vec<String>,
    },
    Mtls {
        /// SHA-256 fingerprint (lowercase hex of the DER) of the client
        /// certificate. Optional when `subject` is set (#124); a
        /// fingerprint match binds the credential to ONE exact
        /// certificate (a re-issued cert needs a new credential).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fingerprint: Option<String>,
        /// Subject CommonName of the client certificate (#124): the
        /// credential matches any verified client certificate whose
        /// subject CN is exactly this string (case-sensitive). Binding
        /// by subject survives certificate re-issue under the same CN;
        /// the certificate must still chain to a listener's
        /// `client_ca_file` (or be otherwise verified) at the TLS layer
        /// — the matcher only maps an ALREADY-VERIFIED certificate to a
        /// consumer. Exactly one of `subject` / `fingerprint` must be
        /// set (validation rejects both-empty and both-set).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject: Option<String>,
    },
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // DW-045: the api-key and hmac-secret values are the inline
        // secret material in the schema; everything else is binding
        // metadata (issuer, fingerprint, subject, key id) that
        // validation matches, not a secret. Redact exactly the secrets
        // and keep the variant shape so debug output stays useful.
        match self {
            Credential::ApiKey { .. } => f
                .debug_struct("ApiKey")
                .field("key", &"[redacted]")
                .finish(),
            Credential::Hmac { key_id, .. } => f
                .debug_struct("Hmac")
                .field("key_id", key_id)
                .field("secret", &"[redacted]")
                .finish(),
            Credential::Jwt { issuer, audiences } => f
                .debug_struct("Jwt")
                .field("issuer", issuer)
                .field("audiences", audiences)
                .finish(),
            Credential::Mtls {
                subject,
                fingerprint,
            } => f
                .debug_struct("Mtls")
                .field("subject", subject)
                .field("fingerprint", fingerprint)
                .finish(),
        }
    }
}

/// Named reusable rule bundle (rate limit, timeouts, ...); attachable at
/// several scopes. Plugin-backed phases arrive with the M3 plugin system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
    /// Stacked GCRA rate-limit rules (DW-017). Each rule stacks one or
    /// more windows (e.g. `s` AND `hour`); a request is admitted only if
    /// EVERY window of EVERY applicable rule allows it. The legacy
    /// single-window `rate_limit` field above still applies when set (see
    /// its mapping in the rate-limiter module docs); use `rate_limits`
    /// for new configs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rate_limits: Vec<RateLimitRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<Timeouts>,
    /// Monitor mode (DW-041) for this bundle's rate-limit rules: they
    /// still EVALUATE (their GCRA buckets advance exactly as if
    /// enforcing, so denial rates reflect what enforcement would do),
    /// but a request they would deny is LOGGED and counted
    /// (`dwara_policy_dry_run_total{phase="rate_limit"}` + a
    /// `dwara::policy` warn event) and PROCEEDS — no 429, and none of
    /// the rule's `X-RateLimit-*` headers on the response. LIVE policies
    /// attached to the same request still enforce: the flag mutes only
    /// this bundle's own denials. The flag sits on the named bundle (not
    /// on each `policies: [...]` attachment list entry) because rate
    /// limits attach BY NAME at the five precedence levels — marking the
    /// bundle dries every attachment of it uniformly. Timeouts carry no
    /// rejection and are unaffected.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
}

/// One rate-limit rule (DW-017): a key selector plus one or more stacked
/// windows. `selector` names the request attributes that form the
/// counter key (all listed attributes are joined into ONE key, so
/// `[ip, route]` limits each (client IP, route) pair independently);
/// `requests_per` carries the sustained rates per window (at least one
/// window must be present); `burst` is the bucket size (defaults to the
/// window's request count).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateLimitRule {
    /// Optional label (documentation only; not part of the key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Key components: `ip`, `credential`, and/or `route` (at least one;
    /// order does not matter). `credential` falls back to the client IP
    /// until authentication (DW-019) identifies consumers.
    pub selector: Vec<RateLimitSelector>,
    pub requests_per: RateRequestsPer,
    /// Bucket size (burst capacity); must be >= 1 when present. Defaults
    /// to the window's request count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
}

/// One attribute of a rate-limit key (DW-017).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitSelector {
    /// The direct connection peer (the same IP used for X-Real-IP).
    Ip,
    /// The authenticated consumer; until DW-019 this falls back to `ip`.
    Credential,
    /// The matched route's name.
    Route,
}

/// Sustained rates per window (DW-017). At least one field must be set
/// and every set field must be > 0; each set field becomes one stacked
/// GCRA cell (a request must satisfy ALL set windows).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateRequestsPer {
    /// Requests per second.
    #[serde(rename = "s", skip_serializing_if = "Option::is_none")]
    pub per_second: Option<u32>,
    /// Requests per minute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minute: Option<u32>,
    /// Requests per hour.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hour: Option<u32>,
}

/// Local GCRA-style rate limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    /// Maximum requests allowed per window.
    pub requests: u64,
    /// Window length in seconds.
    pub window_seconds: u64,
}

/// Parse a YAML configuration document into a [`Gateway`], rejecting invalid
/// input with path-precise error messages.
///
/// Error-path guarantee: serde-level failures (type mismatches, unknown
/// fields, missing fields) carry a precise dotted path from
/// `serde_path_to_error`, e.g. `routes[0].action`. Raw YAML syntax errors
/// are detected by the scanner before path tracking applies, so their path
/// is coarse (often the root); the precise location is still available as
/// line/column inside the message text itself.
pub fn parse_gateway(text: &str) -> Result<Gateway, ConfigError> {
    let de = serde_path_to_error::deserialize(serde_yaml_ng::Deserializer::from_str(text))
        .map_err(|e| ConfigError {
            path: e.path().to_string(),
            message: e.inner().to_string(),
        })?;
    Ok(de)
}

/// Serialize a [`Gateway`] to normalized YAML text.
///
/// Field order follows struct declaration order; defaulted-empty collections
/// are omitted, so output is stable for a given typed value.
pub fn gateway_to_yaml(gateway: &Gateway) -> Result<String, serde_yaml_ng::Error> {
    serde_yaml_ng::to_string(gateway)
}

/// Build the JSON Schema for the root [`Gateway`] type.
pub fn json_schema() -> schemars::Schema {
    schemars::schema_for!(Gateway)
}
