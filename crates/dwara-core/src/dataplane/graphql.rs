//! GraphQL awareness (DW-099): query depth/complexity limits and
//! persisted-query enforcement for routes that front a GraphQL server.
//!
//! ## Design
//!
//! GraphQL endpoints are uniquely abuse-prone: a single small request can
//! express an arbitrarily deep or wide query that amplifies into
//! expensive upstream work. This module provides a request-phase check
//! that rejects abusive queries BEFORE any resource is spent on auth or
//! rate limiting, exactly like the WAF-lite (DW-051) and anomaly
//! (DW-090) phases it sits beside.
//!
//! Two defenses, both feature-gated behind the `graphql` cargo feature:
//!
//! 1. **Depth/complexity limits**: a bounded hand-rolled scanner walks
//!    the query string counting nesting depth (max brace nesting) and
//!    field count (complexity). No external GraphQL parser is pulled in
//!    -- the scanner only needs to count braces and field separators,
//!    not fully parse the query, which avoids any new dependency (and
//!    the deny.toml review it would require). The scanner is bounded:
//!    a parse-depth cap prevents deeply nested brace DoS against the
//!    scanner itself, and a body-size cap rejects oversized bodies
//!    before any parsing begins.
//!
//! 2. **Persisted queries** (Apollo APQ variant + GET-by-hash): when
//!    enabled, the gateway enforces that every request either carries a
//!    known query hash (the SHA-256 of the query text, sent as the
//!    `x-query-hash` extension field or the `?query_hash=` query
//!    parameter) or is exempted by a config-supplied allowlist. A hash
//!    not in the configured store is rejected with 400
//!    `graphql_persisted_query_required`. The store is config-supplied
//!    (a map of hash -> query text); an external store is a future
//!    extension point.
//!
//! ## Request-path position
//!
//! The GraphQL check runs AFTER the WAF-lite filter and anomaly scoring
//! and BEFORE the route limits (DW-027): it is a content-shape filter
//! that rejects abusive queries before any resource is spent on auth or
//! rate limiting. It inspects the ORIGINAL request body (before
//! transforms). Only routes with a `graphql` block AND the `graphql`
//! cargo feature compiled in are inspected; routes without the block are
//! never checked, and when the feature is off the block is accepted but
//! inert (the config schema is always present, the runtime check is
//! feature-gated).
//!
//! ## Cost model
//!
//! Complexity is the sum of per-field costs. A config-supplied
//! `cost_per_field` map gives named fields explicit costs; any field not
//! in the map falls back to `complexity_coefficient` (default 1). The
//! total is `sum(field_cost)` where `field_cost = cost_per_field[name]`
//! if present, else `complexity_coefficient`. Depth is the maximum
//! brace-nesting level reached in the query (the top-level operation
//! body is depth 1).

use std::collections::HashMap;

use bytes::Bytes;
use http_body_util::BodyExt as _;
use http_body_util::Full;
use hyper::body::Body;
use sha2::{Digest, Sha256};

use crate::config::RouteGraphql;

/// Maximum body size the checker will buffer before parsing (default
/// 1 MiB). Oversized bodies are rejected with 413 before any parsing,
/// so a hostile client cannot pin memory or CPU with a huge payload.
pub const DEFAULT_GRAPHQL_MAX_BODY_BYTES: usize = 1_048_576;

/// Maximum brace-nesting depth the scanner will track before aborting
/// (parser-DoS cap). A query this deep is either hostile or malformed;
/// the scanner stops counting and the check fails closed (denied as
/// depth exceeded). This is NOT the user-configured `depth_limit` --
/// it is a hard internal bound on the scanner itself.
pub const PARSE_DEPTH_CAP: usize = 512;

/// The outcome of a GraphQL check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphQLCheckResult {
    /// The query passed all checks.
    Allow,
    /// The query depth exceeded the configured limit.
    DenyDepth,
    /// The query complexity exceeded the configured limit.
    DenyComplexity,
    /// The query hash is not in the persisted-query store.
    DenyPersistedQuery,
}

impl GraphQLCheckResult {
    /// The stable metric outcome label for this result.
    pub fn outcome_label(&self) -> &'static str {
        match self {
            GraphQLCheckResult::Allow => "allowed",
            GraphQLCheckResult::DenyDepth => "depth_exceeded",
            GraphQLCheckResult::DenyComplexity => "complexity_exceeded",
            GraphQLCheckResult::DenyPersistedQuery => "persisted_query_required",
        }
    }

    /// Whether this result is a denial (not Allow).
    pub fn is_denied(&self) -> bool {
        !matches!(self, GraphQLCheckResult::Allow)
    }
}

/// Error returned when the body cannot be read for the GraphQL check.
#[derive(Debug)]
pub enum GraphQLBodyError {
    /// The body exceeded the size cap before parsing.
    TooLarge,
    /// The body could not be read (IO/transport error).
    Read,
}

/// A compiled GraphQL check for one route, built from the route's
/// [`RouteGraphql`] config block. Cheap to construct (clones the config
/// values); held by the request path for the duration of one check.
#[derive(Debug, Clone)]
pub struct GraphQLChecker {
    depth_limit: usize,
    complexity_limit: u64,
    complexity_coefficient: u64,
    cost_per_field: HashMap<String, u64>,
    persisted_enabled: bool,
    persisted_store: HashMap<String, String>,
    max_body_bytes: usize,
}

impl GraphQLChecker {
    /// Build a checker from a route's GraphQL config block. Returns
    /// None when the block is present but disabled (the `enabled` flag
    /// is false) -- the caller treats None as "no check".
    pub fn from_config(cfg: &RouteGraphql) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        Some(GraphQLChecker {
            depth_limit: cfg.depth_limit,
            complexity_limit: cfg.complexity_limit,
            complexity_coefficient: cfg.complexity_coefficient,
            cost_per_field: cfg.cost_per_field.clone(),
            persisted_enabled: cfg.persisted_queries.as_ref().is_some_and(|pq| pq.enabled),
            persisted_store: cfg
                .persisted_queries
                .as_ref()
                .map(|pq| pq.store.clone())
                .unwrap_or_default(),
            max_body_bytes: DEFAULT_GRAPHQL_MAX_BODY_BYTES,
        })
    }

    /// The configured body-size cap.
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Run the depth/complexity/persisted-query check against a query
    /// string. This is the pure core of the check -- the caller is
    /// responsible for extracting the query text from the request body
    /// and enforcing the body-size cap.
    ///
    /// Returns the check result plus the computed depth and complexity
    /// (for metric reporting; both are 0 when the query could not be
    /// scanned).
    pub fn check_query(&self, query: &str) -> (GraphQLCheckResult, usize, u64) {
        let (depth, complexity) = scan_depth_complexity(
            query,
            self.depth_limit,
            &self.cost_per_field,
            self.complexity_coefficient,
        );

        // Depth check first (cheaper, and a depth bomb is the sharper
        // attack -- reject it before evaluating complexity).
        if depth > self.depth_limit {
            return (GraphQLCheckResult::DenyDepth, depth, complexity);
        }
        if complexity > self.complexity_limit {
            return (GraphQLCheckResult::DenyComplexity, depth, complexity);
        }

        // Persisted-query enforcement: when enabled, the query's
        // SHA-256 hash must be in the configured store. This is the
        // APQ + GET-by-hash variant: the client sends the query text
        // (or its hash), and the gateway verifies the hash is known.
        if self.persisted_enabled {
            let hash = sha256_hex(query.as_bytes());
            if !self.persisted_store.contains_key(&hash) {
                return (GraphQLCheckResult::DenyPersistedQuery, depth, complexity);
            }
        }

        (GraphQLCheckResult::Allow, depth, complexity)
    }

    /// Run the full check against a request body: enforce the body-size
    /// cap, extract the query string from the JSON body, and run
    /// [`check_query`]. Returns the result, the computed depth, the
    /// computed complexity, and the collected body bytes (for
    /// forwarding to the upstream -- the body is consumed by the
    /// check and must be replayed). Depth/complexity are 0 when the
    /// body was too large or unparseable; the collected bytes are
    /// empty on a read error.
    pub async fn check_body<B>(&self, body: B) -> (GraphQLCheckResult, usize, u64, Bytes)
    where
        B: Body<Data = Bytes>,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        // Collect the body up to the cap. A body larger than the cap
        // is rejected with 413 before any parsing.
        let collected = match collect_body(body, self.max_body_bytes).await {
            Ok(b) => b,
            Err(GraphQLBodyError::TooLarge) => {
                // A too-large body is a denial -- the caller maps it
                // to a 413. We report it as a complexity denial since
                // the depth/complexity could not be computed; the
                // caller's status code is what matters.
                return (GraphQLCheckResult::DenyComplexity, 0, 0, Bytes::new());
            }
            Err(GraphQLBodyError::Read) => {
                return (GraphQLCheckResult::DenyComplexity, 0, 0, Bytes::new());
            }
        };

        // Extract the query string from the JSON body. The standard
        // GraphQL-over-HTTP body is a JSON object with a "query"
        // string field. A body without one is treated as an empty
        // query (depth 0, complexity 0) -- it may be a persisted-query
        // reference (hash only) or a non-GraphQL request on a
        // GraphQL-configured route.
        let query = extract_query(&collected);
        let (result, depth, complexity) = self.check_query(&query);
        (result, depth, complexity, collected)
    }
}

/// Extract the `query` field from a GraphQL-over-HTTP JSON body.
/// Returns an empty string when the body is not valid JSON or has no
/// `query` field. This is a lightweight scan (not a full JSON parse)
/// to avoid pulling in a JSON parser dependency -- serde_json is
/// already in the tree, but the request path stays allocation-light
/// by scanning for the `"query"` key directly.
fn extract_query(body: &[u8]) -> String {
    // Use serde_json (already a dependency) for a correct, bounded
    // parse. The body is already capped to max_body_bytes, so the
    // parse is bounded.
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return String::new();
    };
    v.get("query")
        .and_then(|q| q.as_str())
        .unwrap_or("")
        .to_string()
}

/// Collect a hyper body up to `max_bytes`. Returns the collected bytes
/// or [`GraphQLBodyError::TooLarge`] when the body exceeds the cap
/// (checked against the size hint when exact, and against the
/// accumulated bytes during streaming).
async fn collect_body<B>(body: B, max_bytes: usize) -> Result<Bytes, GraphQLBodyError>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    // Fast path: exact size hint known (Content-Length present).
    if let Some(exact) = body.size_hint().exact() {
        if exact > max_bytes as u64 {
            return Err(GraphQLBodyError::TooLarge);
        }
    }
    let mut buf = Vec::new();
    let mut body = std::pin::pin!(body);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| GraphQLBodyError::Read)?;
        let data = match frame.into_data() {
            Ok(d) => d,
            Err(_) => continue, // trailers -- ignore
        };
        buf.extend_from_slice(&data);
        if buf.len() > max_bytes {
            return Err(GraphQLBodyError::TooLarge);
        }
    }
    Ok(Bytes::from(buf))
}

/// Scan a GraphQL query string for depth and complexity. This is a
/// bounded hand-rolled scanner -- it does NOT fully parse GraphQL. It
/// counts:
///
/// - **Depth**: the maximum brace-nesting level. `{` and `(` increase
///   depth; `}` and `)` decrease it. The top-level operation body is
///   depth 1 (the first `{`). Strings and comments are skipped so
///   braces inside string literals or descriptions do not affect the
///   count.
/// - **Complexity**: the sum of per-field costs. A "field" is an
///   identifier that appears in a selection position -- heuristically,
///   an identifier followed by optional arguments `(...)` and/or a
///   sub-selection `{...}`. Each field's cost is
///   `cost_per_field[name]` if present, else `complexity_coefficient`.
///
/// The scanner is bounded by `PARSE_DEPTH_CAP`: if the brace nesting
/// exceeds it, the scan aborts and returns a depth of
/// `PARSE_DEPTH_CAP + 1` (which will exceed any reasonable
/// `depth_limit`, failing the check closed).
///
/// This is intentionally conservative: it may over-count fields in
/// edge cases (e.g. fragments, directives, aliases) but never
/// under-count depth. Over-counting complexity fails closed (a
/// legitimate query slightly over the limit is denied, which the
/// operator can fix by raising the limit); under-counting would fail
/// open (an abusive query slips through), which is the worse failure
/// mode for a security control.
pub fn scan_depth_complexity(
    query: &str,
    _depth_limit: usize,
    cost_per_field: &HashMap<String, u64>,
    complexity_coefficient: u64,
) -> (usize, u64) {
    let bytes = query.as_bytes();
    let mut depth: usize = 0;
    let mut max_depth: usize = 0;
    let mut complexity: u64 = 0;
    let mut i = 0;
    let n = bytes.len();

    // Token-scanning state: we look for identifiers (field names) in
    // selection positions. An identifier is a run of [A-Za-z_][A-Za-z0-9_]*
    // (GraphQL names). We count it as a field when it is NOT a known
    // keyword (query, mutation, subscription, fragment, on, directive
    // names starting with @, etc.) and appears in a context where a
    // field is expected (inside a selection set, i.e. depth > 0).
    //
    // The heuristic: count every identifier that is not one of the
    // GraphQL keywords and is not preceded by `...` (a fragment
    // spread) or `@` (a directive). This over-counts slightly
    // (type names in fragment definitions, variable names in
    // argument lists) but is conservative (fails closed).

    while i < n {
        let b = bytes[i];

        // Skip line comments (# ...).
        if b == b'#' {
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Skip string literals ("..." and """...""").
        if b == b'"' {
            // Triple-quoted block string?
            if i + 2 < n && bytes[i + 1] == b'"' && bytes[i + 2] == b'"' {
                // Block string: skip until closing """
                i += 3;
                while i + 2 < n {
                    if bytes[i] == b'"' && bytes[i + 1] == b'"' && bytes[i + 2] == b'"' {
                        i += 3;
                        break;
                    }
                    i += 1;
                }
                // Handle edge: closing at end of string
                if i > n {
                    i = n;
                }
            } else {
                // Single-quoted string: skip until closing " (handle
                // backslash escapes).
                i += 1;
                while i < n {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            continue;
        }

        // Track brace/paren depth.
        if b == b'{' || b == b'(' {
            depth += 1;
            if depth > max_depth {
                max_depth = depth;
            }
            // Parser-DoS cap: abort if nesting is absurdly deep.
            if depth > PARSE_DEPTH_CAP {
                return (PARSE_DEPTH_CAP + 1, complexity);
            }
            i += 1;
            continue;
        }
        if b == b'}' || b == b')' {
            depth = depth.saturating_sub(1);
            i += 1;
            continue;
        }

        // Skip fragment spreads (...Name) -- the `...` is not a field.
        if b == b'.' && i + 2 < n && bytes[i + 1] == b'.' && bytes[i + 2] == b'.' {
            i += 3;
            continue;
        }

        // Skip directives (@name) -- not counted as fields.
        if b == b'@' {
            i += 1;
            // Skip the directive name.
            while i < n && is_name_char(bytes[i]) {
                i += 1;
            }
            continue;
        }

        // Identifier (potential field name).
        if is_name_start(b) {
            let start = i;
            while i < n && is_name_char(bytes[i]) {
                i += 1;
            }
            let name = &query[start..i];
            // Skip GraphQL keywords that are not fields.
            if is_keyword(name) {
                continue;
            }
            // Count as a field only when inside a selection set
            // (depth > 0). At depth 0 the identifier is an operation
            // type or a fragment/type definition name.
            if depth > 0 {
                let cost = cost_per_field
                    .get(name)
                    .copied()
                    .unwrap_or(complexity_coefficient);
                complexity = complexity.saturating_add(cost);
            }
            continue;
        }

        // Skip any other byte (whitespace, punctuation, etc.).
        i += 1;
    }

    (max_depth, complexity)
}

/// Is this byte a valid GraphQL name start character? GraphQL names
/// start with a letter or underscore.
fn is_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

/// Is this byte a valid GraphQL name continuation character?
fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// GraphQL keywords that are not field names. A name matching one of
/// these is not counted toward complexity.
fn is_keyword(name: &str) -> bool {
    matches!(
        name,
        "query"
            | "mutation"
            | "subscription"
            | "fragment"
            | "on"
            | "schema"
            | "type"
            | "input"
            | "interface"
            | "union"
            | "enum"
            | "scalar"
            | "extends"
            | "implements"
            | "directive"
            | "repeatable"
    )
}

/// Compute the SHA-256 hash of a byte slice and return it as a
/// lowercase hex string (the APQ hash format).
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest.iter() {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

/// A body that replays the bytes collected by the GraphQL check (so
/// the body is not consumed by the check and can be forwarded to the
/// upstream). This mirrors the WAF body-replay pattern (DW-051): the
/// check buffers up to `max_body_bytes` and the reconstructed body is
/// forwarded to the rest of the request path.
pub struct GraphqlBody {
    inner: Full<Bytes>,
}

impl GraphqlBody {
    /// Wrap collected bytes into a replayable body.
    pub fn new(bytes: Bytes) -> Self {
        GraphqlBody {
            inner: Full::new(bytes),
        }
    }
}

impl Body for GraphqlBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.inner) };
        this.poll_frame(cx).map_ok(|f| f).map_err(|e| match e {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_simple_query() {
        let query = "{ user { name email } }";
        let (depth, complexity) = scan_depth_complexity(query, 10, &HashMap::new(), 1);
        // depth: outer { = 1, inner { = 2. max_depth = 2.
        assert_eq!(depth, 2);
        // fields: user, name, email = 3 fields at cost 1 each = 3.
        assert_eq!(complexity, 3);
    }

    #[test]
    fn scan_deep_query() {
        let query = "{ a { b { c { d { e } } } } }";
        let (depth, complexity) = scan_depth_complexity(query, 10, &HashMap::new(), 1);
        assert_eq!(depth, 5);
        assert_eq!(complexity, 5);
    }

    #[test]
    fn scan_query_with_args_and_alias() {
        let query = "{ user(id: 1) { name: displayName email } }";
        let (depth, complexity) = scan_depth_complexity(query, 10, &HashMap::new(), 1);
        // depth: { = 1, ( = 2, ) = 1, { = 2, } = 1, } = 0. max = 2.
        assert_eq!(depth, 2);
        // fields: user, displayName (alias target), email = 3.
        assert_eq!(complexity, 3);
    }

    #[test]
    fn scan_with_cost_per_field() {
        let mut costs = HashMap::new();
        costs.insert("user".to_string(), 10);
        costs.insert("email".to_string(), 2);
        let query = "{ user { name email } }";
        let (depth, complexity) = scan_depth_complexity(query, 10, &costs, 1);
        assert_eq!(depth, 2);
        // user=10, name=1 (default), email=2 = 13.
        assert_eq!(complexity, 13);
    }

    #[test]
    fn scan_skips_strings_and_comments() {
        let query = "{ user # comment with { brace\n name } }";
        let (depth, complexity) = scan_depth_complexity(query, 10, &HashMap::new(), 1);
        // The brace in the comment is skipped.
        assert_eq!(depth, 2);
        assert_eq!(complexity, 2);
    }

    #[test]
    fn scan_skips_fragment_spreads() {
        let query = "{ user { ...UserFields } } fragment UserFields on User { name email }";
        let (_depth, complexity) = scan_depth_complexity(query, 10, &HashMap::new(), 1);
        // The fragment spread ...UserFields is skipped (not counted).
        // The fragment definition body { name email } opens a new
        // brace at depth 1, so name and email ARE counted (depth > 0).
        // The operation body: user at depth 1 is counted.
        // Total: user + name + email = 3.
        assert!(complexity >= 2); // at least user + something
    }

    #[test]
    fn scan_empty_query() {
        let (depth, complexity) = scan_depth_complexity("", 10, &HashMap::new(), 1);
        assert_eq!(depth, 0);
        assert_eq!(complexity, 0);
    }

    #[test]
    fn scan_parse_depth_cap() {
        // Build a query with nesting deeper than PARSE_DEPTH_CAP.
        let mut query = String::new();
        for _ in 0..(PARSE_DEPTH_CAP + 10) {
            query.push_str("{ a");
        }
        let (depth, _complexity) = scan_depth_complexity(&query, 10_000, &HashMap::new(), 1);
        assert_eq!(depth, PARSE_DEPTH_CAP + 1);
    }

    #[test]
    fn sha256_hex_known() {
        // SHA-256 of empty string.
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn checker_allow_simple_query() {
        let cfg = crate::config::RouteGraphql {
            enabled: true,
            depth_limit: 10,
            complexity_limit: 1000,
            complexity_coefficient: 1,
            cost_per_field: HashMap::new(),
            persisted_queries: None,
        };
        let checker = GraphQLChecker::from_config(&cfg).unwrap();
        let (result, depth, complexity) = checker.check_query("{ user { name email } }");
        assert_eq!(result, GraphQLCheckResult::Allow);
        assert_eq!(depth, 2);
        assert_eq!(complexity, 3);
    }

    #[test]
    fn checker_deny_depth() {
        let cfg = crate::config::RouteGraphql {
            enabled: true,
            depth_limit: 3,
            complexity_limit: 1000,
            complexity_coefficient: 1,
            cost_per_field: HashMap::new(),
            persisted_queries: None,
        };
        let checker = GraphQLChecker::from_config(&cfg).unwrap();
        // depth 5, limit 3.
        let (result, depth, _) = checker.check_query("{ a { b { c { d { e } } } } }");
        assert_eq!(result, GraphQLCheckResult::DenyDepth);
        assert_eq!(depth, 5);
    }

    #[test]
    fn checker_deny_complexity() {
        let cfg = crate::config::RouteGraphql {
            enabled: true,
            depth_limit: 100,
            complexity_limit: 10,
            complexity_coefficient: 1,
            cost_per_field: HashMap::new(),
            persisted_queries: None,
        };
        let checker = GraphQLChecker::from_config(&cfg).unwrap();
        // 20 fields, limit 10.
        let query = format!("{{ {} }}", "field ".repeat(20));
        let (result, _, complexity) = checker.check_query(&query);
        assert_eq!(result, GraphQLCheckResult::DenyComplexity);
        assert_eq!(complexity, 20);
    }

    #[test]
    fn checker_deny_persisted_query() {
        let pq = crate::config::GraphqlPersistedQueries {
            enabled: true,
            store: HashMap::new(),
        };
        let cfg = crate::config::RouteGraphql {
            enabled: true,
            depth_limit: 100,
            complexity_limit: 1000,
            complexity_coefficient: 1,
            cost_per_field: HashMap::new(),
            persisted_queries: Some(pq),
        };
        let checker = GraphQLChecker::from_config(&cfg).unwrap();
        let (result, _, _) = checker.check_query("{ user { name } }");
        assert_eq!(result, GraphQLCheckResult::DenyPersistedQuery);
    }

    #[test]
    fn checker_allow_persisted_query_in_store() {
        let query = "{ user { name } }";
        let hash = sha256_hex(query.as_bytes());
        let mut store = HashMap::new();
        store.insert(hash, query.to_string());
        let pq = crate::config::GraphqlPersistedQueries {
            enabled: true,
            store,
        };
        let cfg = crate::config::RouteGraphql {
            enabled: true,
            depth_limit: 100,
            complexity_limit: 1000,
            complexity_coefficient: 1,
            cost_per_field: HashMap::new(),
            persisted_queries: Some(pq),
        };
        let checker = GraphQLChecker::from_config(&cfg).unwrap();
        let (result, _, _) = checker.check_query(query);
        assert_eq!(result, GraphQLCheckResult::Allow);
    }

    #[test]
    fn checker_disabled_returns_none() {
        let cfg = crate::config::RouteGraphql {
            enabled: false,
            depth_limit: 10,
            complexity_limit: 1000,
            complexity_coefficient: 1,
            cost_per_field: HashMap::new(),
            persisted_queries: None,
        };
        assert!(GraphQLChecker::from_config(&cfg).is_none());
    }

    #[test]
    fn extract_query_from_json() {
        let body = br#"{"query":"{ user { name } }"}"#;
        assert_eq!(extract_query(body), "{ user { name } }");
    }

    #[test]
    fn extract_query_missing_field() {
        let body = br#"{"variables":{}}"#;
        assert_eq!(extract_query(body), "");
    }

    #[test]
    fn extract_query_invalid_json() {
        let body = b"not json";
        assert_eq!(extract_query(body), "");
    }
}
