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
    /// Required token issuer (`iss` claim). Absent: any issuer accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Required audience (`aud` claim). Absent: any audience accepted.
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
    /// resolved by the `authz` module's resolver; today only the route
    /// link has a config attachment point — the other links activate
    /// when their config fields land.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authz>,
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
    /// membership.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
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
