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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    /// IP addresses / CIDR ranges of proxies whose `X-Forwarded-For` claims
    /// are trusted (gateway-level; the direct connection peer must be in
    /// this list for an inbound XFF chain to be preserved and extended).
    /// Each entry must be an IP address (e.g. `10.1.2.3`) or a CIDR
    /// (e.g. `10.0.0.0/8`); anything else fails validation. Empty (the
    /// default) trusts nobody: every proxied request carries an XFF of
    /// exactly the direct peer, and inbound XFF values are discarded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<String>,
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
    /// Attached policy names (most specific wins: consumer > route > service
    /// > listener > global).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<Timeouts>,
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
}

/// One authenticator bound to a consumer: API key, JWT issuer/audience
/// binding, or mTLS fingerprint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Credential {
    ApiKey {
        /// The API key; hashed at rest by the state layer, never logged.
        key: String,
    },
    Jwt {
        issuer: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        audiences: Vec<String>,
    },
    Mtls {
        /// SHA-256 fingerprint of the client certificate.
        fingerprint: String,
    },
}

/// Named reusable rule bundle (rate limit, timeouts, ...); attachable at
/// several scopes. Plugin-backed phases arrive with the M3 plugin system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<Timeouts>,
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
