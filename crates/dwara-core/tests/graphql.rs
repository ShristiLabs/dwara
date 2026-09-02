//! Integration tests for GraphQL awareness (DW-099).
//!
//! These tests exercise the GraphQL checker through the public API:
//! `GraphQLChecker::from_config` and `check_query` / `check_body`.
//! They verify depth limit enforcement, complexity limit enforcement,
//! persisted-query enforcement, the body-size cap, the parse-depth
//! cap (parser DoS prevention), and that valid queries pass through.
//!
//! Feature-gated behind the `graphql` cargo feature. The test file
//! uses `#![cfg(feature = "graphql")]` so it compiles to an empty
//! binary without the feature.

#![cfg(feature = "graphql")]

use std::collections::HashMap;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Body as _;

use dwara_core::config::{GraphqlPersistedQueries, RouteGraphql};
use dwara_core::dataplane::graphql::{
    sha256_hex, GraphQLCheckResult, GraphQLChecker, PARSE_DEPTH_CAP,
};

fn config_with(depth_limit: usize, complexity_limit: u64) -> RouteGraphql {
    RouteGraphql {
        enabled: true,
        depth_limit,
        complexity_limit,
        complexity_coefficient: 1,
        cost_per_field: HashMap::new(),
        persisted_queries: None,
    }
}

fn checker_with(depth_limit: usize, complexity_limit: u64) -> GraphQLChecker {
    GraphQLChecker::from_config(&config_with(depth_limit, complexity_limit))
        .expect("enabled config produces a checker")
}

// --- depth limit enforcement -------------------------------------------

#[test]
fn depth_limit_denies_deep_query() {
    // Query at depth 5, limit 3 -> denied.
    let checker = checker_with(3, 1000);
    let query = "{ a { b { c { d { e } } } } }";
    let (result, depth, _) = checker.check_query(query);
    assert_eq!(result, GraphQLCheckResult::DenyDepth);
    assert_eq!(depth, 5);
}

#[test]
fn depth_limit_allows_shallow_query() {
    // Query at depth 2, limit 3 -> allowed.
    let checker = checker_with(3, 1000);
    let query = "{ user { name } }";
    let (result, depth, _) = checker.check_query(query);
    assert_eq!(result, GraphQLCheckResult::Allow);
    assert_eq!(depth, 2);
}

#[test]
fn depth_limit_boundary() {
    // Query at depth exactly equal to the limit -> allowed.
    let checker = checker_with(3, 1000);
    let query = "{ a { b { c } } }";
    let (result, depth, _) = checker.check_query(query);
    assert_eq!(result, GraphQLCheckResult::Allow);
    assert_eq!(depth, 3);
}

// --- complexity limit enforcement --------------------------------------

#[test]
fn complexity_limit_denies_wide_query() {
    // Query with 20 fields, limit 10 -> denied.
    let checker = checker_with(100, 10);
    let query = format!("{{ {} }}", "field ".repeat(20));
    let (result, _, complexity) = checker.check_query(&query);
    assert_eq!(result, GraphQLCheckResult::DenyComplexity);
    assert_eq!(complexity, 20);
}

#[test]
fn complexity_limit_allows_small_query() {
    // Query with 3 fields, limit 10 -> allowed.
    let checker = checker_with(100, 10);
    let query = "{ user { name email } }";
    let (result, _, complexity) = checker.check_query(query);
    assert_eq!(result, GraphQLCheckResult::Allow);
    assert_eq!(complexity, 3);
}

#[test]
fn complexity_with_cost_per_field() {
    let mut costs = HashMap::new();
    costs.insert("expensive".to_string(), 100);
    let cfg = RouteGraphql {
        enabled: true,
        depth_limit: 100,
        complexity_limit: 50,
        complexity_coefficient: 1,
        cost_per_field: costs,
        persisted_queries: None,
    };
    let checker = GraphQLChecker::from_config(&cfg).unwrap();
    // One field with cost 100, limit 50 -> denied.
    let (result, _, complexity) = checker.check_query("{ expensive }");
    assert_eq!(result, GraphQLCheckResult::DenyComplexity);
    assert_eq!(complexity, 100);
}

// --- persisted query enforcement ---------------------------------------

#[test]
fn persisted_query_denies_unknown_hash() {
    let pq = GraphqlPersistedQueries {
        enabled: true,
        store: HashMap::new(),
    };
    let cfg = RouteGraphql {
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
fn persisted_query_allows_known_hash() {
    let query = "{ user { name } }";
    let hash = sha256_hex(query.as_bytes());
    let mut store = HashMap::new();
    store.insert(hash, query.to_string());
    let pq = GraphqlPersistedQueries {
        enabled: true,
        store,
    };
    let cfg = RouteGraphql {
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
fn persisted_query_disabled_allows_anything() {
    let pq = GraphqlPersistedQueries {
        enabled: false,
        store: HashMap::new(),
    };
    let cfg = RouteGraphql {
        enabled: true,
        depth_limit: 100,
        complexity_limit: 1000,
        complexity_coefficient: 1,
        cost_per_field: HashMap::new(),
        persisted_queries: Some(pq),
    };
    let checker = GraphQLChecker::from_config(&cfg).unwrap();
    let (result, _, _) = checker.check_query("{ user { name } }");
    assert_eq!(result, GraphQLCheckResult::Allow);
}

// --- body size cap -----------------------------------------------------

#[test]
fn body_size_cap_rejects_oversized_body() {
    let checker = checker_with(100, 1000);
    // Build a body larger than the default 1 MiB cap.
    let big_value = "x".repeat(2 * 1024 * 1024);
    let body_json = format!(r#"{{"query":"{big_value}"}}"#);
    let body = Full::new(Bytes::from(body_json));
    // Use the runtime to drive the async check.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (result, _, _, _) = runtime.block_on(checker.check_body(body));
    // A too-large body is rejected (reported as DenyComplexity since
    // depth/complexity could not be computed; the caller maps the
    // status code).
    assert_eq!(result, GraphQLCheckResult::DenyComplexity);
}

// --- parse depth cap (parser DoS prevention) --------------------------

#[test]
fn parse_depth_cap_prevents_parser_dos() {
    // Build a query with nesting deeper than PARSE_DEPTH_CAP.
    let mut query = String::new();
    for _ in 0..(PARSE_DEPTH_CAP + 10) {
        query.push_str("{ a");
    }
    let checker = checker_with(10_000, 1_000_000);
    let (result, depth, _) = checker.check_query(&query);
    // The scanner aborts at PARSE_DEPTH_CAP + 1, which exceeds the
    // configured depth_limit (10_000 is less than PARSE_DEPTH_CAP + 1
    // = 513). Wait: 10_000 > 513, so the depth check would pass.
    // Let's use a smaller depth_limit.
    assert_eq!(depth, PARSE_DEPTH_CAP + 1);
    // With depth_limit > PARSE_DEPTH_CAP, the depth check passes but
    // the query is still malformed. Verify the cap was hit.
    assert!(depth > PARSE_DEPTH_CAP);
    // The result may be Allow or Deny depending on depth_limit; the
    // key assertion is that the scanner did not hang or panic.
    let _ = result;
}

#[test]
fn parse_depth_cap_with_low_limit_denies() {
    let mut query = String::new();
    for _ in 0..(PARSE_DEPTH_CAP + 10) {
        query.push_str("{ a");
    }
    let checker = checker_with(100, 1_000_000);
    let (result, depth, _) = checker.check_query(&query);
    assert_eq!(depth, PARSE_DEPTH_CAP + 1);
    assert_eq!(result, GraphQLCheckResult::DenyDepth);
}

// --- valid query passes through ---------------------------------------

#[test]
fn valid_query_passes() {
    let checker = checker_with(10, 1000);
    let query = "{ user { id name email posts { title } } }";
    let (result, depth, complexity) = checker.check_query(query);
    assert_eq!(result, GraphQLCheckResult::Allow);
    assert_eq!(depth, 3);
    // Fields: user, id, name, email, posts, title = 6.
    assert_eq!(complexity, 6);
}

#[test]
fn valid_query_with_operation_keyword() {
    let checker = checker_with(10, 1000);
    let query = "query GetUser { user { id name } }";
    let (result, depth, complexity) = checker.check_query(query);
    assert_eq!(result, GraphQLCheckResult::Allow);
    // depth: query keyword at depth 0, then { = 1, { = 2. max = 2.
    assert_eq!(depth, 2);
    // Fields: user, id, name = 3 (query keyword not counted).
    assert_eq!(complexity, 3);
}

// --- check_body with JSON body ----------------------------------------

#[test]
fn check_body_extracts_query_from_json() {
    let checker = checker_with(10, 1000);
    let body = Full::new(Bytes::from(r#"{"query":"{ user { name } }"}"#));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (result, depth, complexity, collected) = runtime.block_on(checker.check_body(body));
    assert_eq!(result, GraphQLCheckResult::Allow);
    assert_eq!(depth, 2);
    assert_eq!(complexity, 2);
    // The collected body is forwarded to the upstream.
    assert!(!collected.is_empty());
}

#[test]
fn check_body_empty_body_passes() {
    let checker = checker_with(10, 1000);
    let body = Full::new(Bytes::new());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (result, depth, complexity, _) = runtime.block_on(checker.check_body(body));
    // Empty body -> empty query -> depth 0, complexity 0 -> allowed.
    assert_eq!(result, GraphQLCheckResult::Allow);
    assert_eq!(depth, 0);
    assert_eq!(complexity, 0);
}

#[test]
fn check_body_non_json_passes() {
    let checker = checker_with(10, 1000);
    let body = Full::new(Bytes::from("not json"));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (result, _, _, _) = runtime.block_on(checker.check_body(body));
    // Non-JSON body -> empty query -> allowed (not a GraphQL request).
    assert_eq!(result, GraphQLCheckResult::Allow);
}

// --- disabled checker --------------------------------------------------

#[test]
fn disabled_graphql_returns_none() {
    let cfg = RouteGraphql {
        enabled: false,
        depth_limit: 10,
        complexity_limit: 1000,
        complexity_coefficient: 1,
        cost_per_field: HashMap::new(),
        persisted_queries: None,
    };
    assert!(GraphQLChecker::from_config(&cfg).is_none());
}

// --- config schema: feature gate (without graphql feature, config
//     is accepted but inert) -------------------------------------------
// This test runs WITHOUT the graphql feature to verify the config
// schema is always present. It is in a separate test file section
// guarded by cfg(not(feature = "graphql")) -- but since this entire
// file is cfg(feature = "graphql"), we test the inverse here: the
// config struct exists and parses regardless of the feature.

#[test]
fn graphql_config_parses() {
    use dwara_core::config::parse_gateway;
    let yaml = r#"
listeners:
  - name: main
    address: 127.0.0.1
    port: 8080
routes:
  - name: graphql-api
    service: backend
    match:
      path:
        type: prefix
        value: /graphql
    action:
      type: proxy
    graphql:
      enabled: true
      depth_limit: 10
      complexity_limit: 1000
      complexity_coefficient: 1
      persisted_queries:
        enabled: false
services:
  - name: backend
    upstream: backend
upstreams:
  - name: backend
    endpoints:
      - address: 127.0.0.1
        port: 9000
"#;
    let gateway = parse_gateway(yaml).expect("graphql config parses");
    let graphql = gateway.routes[0]
        .graphql
        .as_ref()
        .expect("graphql block present");
    assert!(graphql.enabled);
    assert_eq!(graphql.depth_limit, 10);
    assert_eq!(graphql.complexity_limit, 1000);
}

#[test]
fn graphql_config_with_cost_per_field_parses() {
    use dwara_core::config::parse_gateway;
    let yaml = r#"
listeners:
  - name: main
    address: 127.0.0.1
    port: 8080
routes:
  - name: graphql-api
    service: backend
    match:
      path:
        type: prefix
        value: /graphql
    action:
      type: proxy
    graphql:
      enabled: true
      depth_limit: 10
      complexity_limit: 1000
      cost_per_field:
        expensiveField: 50
        nested: 5
services:
  - name: backend
    upstream: backend
upstreams:
  - name: backend
    endpoints:
      - address: 127.0.0.1
        port: 9000
"#;
    let gateway = parse_gateway(yaml).expect("graphql config with costs parses");
    let graphql = gateway.routes[0].graphql.as_ref().unwrap();
    assert_eq!(graphql.cost_per_field.get("expensiveField"), Some(&50));
    assert_eq!(graphql.cost_per_field.get("nested"), Some(&5));
}

// --- snapshot validation -----------------------------------------------

#[test]
fn validation_rejects_zero_depth_limit() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::validate;
    let yaml = r#"
listeners:
  - name: main
    address: 127.0.0.1
    port: 8080
routes:
  - name: graphql-api
    service: backend
    match:
      path:
        type: prefix
        value: /graphql
    action:
      type: proxy
    graphql:
      enabled: true
      depth_limit: 0
      complexity_limit: 1000
services:
  - name: backend
    upstream: backend
upstreams:
  - name: backend
    endpoints:
      - address: 127.0.0.1
        port: 9000
"#;
    let gateway = parse_gateway(yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "graphql.depth_limit"
                && i.message.contains("depth_limit must be > 0")),
        "zero depth_limit must be rejected: {issues:?}"
    );
}

#[test]
fn validation_rejects_zero_complexity_limit() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::validate;
    let yaml = r#"
listeners:
  - name: main
    address: 127.0.0.1
    port: 8080
routes:
  - name: graphql-api
    service: backend
    match:
      path:
        type: prefix
        value: /graphql
    action:
      type: proxy
    graphql:
      enabled: true
      depth_limit: 10
      complexity_limit: 0
services:
  - name: backend
    upstream: backend
upstreams:
  - name: backend
    endpoints:
      - address: 127.0.0.1
        port: 9000
"#;
    let gateway = parse_gateway(yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues.iter().any(|i| i.field == "graphql.complexity_limit"
            && i.message.contains("complexity_limit must be > 0")),
        "zero complexity_limit must be rejected: {issues:?}"
    );
}

#[test]
fn validation_allows_disabled_graphql_with_zero_limits() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::validate;
    let yaml = r#"
listeners:
  - name: main
    address: 127.0.0.1
    port: 8080
routes:
  - name: graphql-api
    service: backend
    match:
      path:
        type: prefix
        value: /graphql
    action:
      type: proxy
    graphql:
      enabled: false
      depth_limit: 0
      complexity_limit: 0
services:
  - name: backend
    upstream: backend
upstreams:
  - name: backend
    endpoints:
      - address: 127.0.0.1
        port: 9000
"#;
    let gateway = parse_gateway(yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        !issues.iter().any(|i| i.field.starts_with("graphql.")),
        "disabled graphql block with zero limits should not be rejected: {issues:?}"
    );
}

#[test]
fn validation_rejects_empty_persisted_query_hash() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::validate;
    let yaml = r#"
listeners:
  - name: main
    address: 127.0.0.1
    port: 8080
routes:
  - name: graphql-api
    service: backend
    match:
      path:
        type: prefix
        value: /graphql
    action:
      type: proxy
    graphql:
      enabled: true
      depth_limit: 10
      complexity_limit: 1000
      persisted_queries:
        enabled: true
        store:
          "": "some query"
services:
  - name: backend
    upstream: backend
upstreams:
  - name: backend
    endpoints:
      - address: 127.0.0.1
        port: 9000
"#;
    let gateway = parse_gateway(yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues.iter().any(
            |i| i.field == "graphql.persisted_queries.store" && i.message.contains("non-empty")
        ),
        "empty persisted query hash must be rejected: {issues:?}"
    );
}
