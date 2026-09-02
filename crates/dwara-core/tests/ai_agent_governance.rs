//! Agent principal & governance tests (DW-113): consumer_type threading,
//! per-agent tool allowlists, per-agent token budgets, and typed
//! analytics attribution.

use dwara_core::config::{parse_gateway, ConsumerType};

// ---------------------------------------------------------------------------
// 1. ConsumerType: serde round-trips snake_case
// ---------------------------------------------------------------------------

#[test]
fn consumer_type_serde_round_trips() {
    assert_eq!(
        serde_json::to_string(&ConsumerType::User).unwrap(),
        "\"user\""
    );
    assert_eq!(
        serde_json::to_string(&ConsumerType::Agent).unwrap(),
        "\"agent\""
    );
    assert_eq!(
        serde_json::from_str::<ConsumerType>("\"user\"").unwrap(),
        ConsumerType::User
    );
    assert_eq!(
        serde_json::from_str::<ConsumerType>("\"agent\"").unwrap(),
        ConsumerType::Agent
    );
}

// ---------------------------------------------------------------------------
// 2. ConsumerType: default is User
// ---------------------------------------------------------------------------

#[test]
fn consumer_type_default_is_user() {
    assert_eq!(ConsumerType::default(), ConsumerType::User);
}

// ---------------------------------------------------------------------------
// 3. ConsumerType: YAML parses agent and user
// ---------------------------------------------------------------------------

#[test]
fn consumer_type_parses_from_yaml() {
    let yaml = r#"
listeners:
  - name: l
    address: 0.0.0.0
    port: 8080
routes:
  - name: r
    service: svc
    match:
      path:
        type: exact
        value: /x
    action:
      type: proxy
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 9001
consumers:
  - name: agent-bot
    type: agent
    credentials:
      - type: api_key
        key: agent-key
    tool_allowlist: [search, fetch]
    token_budget:
      tokens_per_min: 1000
      scope: consumer
  - name: human-user
    type: user
    credentials:
      - type: api_key
        key: user-key
"#;
    let gw = parse_gateway(yaml).expect("parses");
    assert_eq!(gw.consumers.len(), 2);
    assert_eq!(gw.consumers[0].consumer_type, ConsumerType::Agent);
    assert_eq!(gw.consumers[1].consumer_type, ConsumerType::User);
    assert_eq!(gw.consumers[0].tool_allowlist, vec!["search", "fetch"]);
    assert!(gw.consumers[0].token_budget.is_some());
    assert!(gw.consumers[1].token_budget.is_none());
}

// ---------------------------------------------------------------------------
// 4. ConsumerType: defaults to user when omitted
// ---------------------------------------------------------------------------

#[test]
fn consumer_type_defaults_to_user_when_omitted() {
    let yaml = r#"
listeners:
  - name: l
    address: 0.0.0.0
    port: 8080
routes:
  - name: r
    service: svc
    match:
      path:
        type: exact
        value: /x
    action:
      type: proxy
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 9001
consumers:
  - name: c
    credentials:
      - type: api_key
        key: k
"#;
    let gw = parse_gateway(yaml).expect("parses");
    assert_eq!(gw.consumers[0].consumer_type, ConsumerType::User);
    assert!(gw.consumers[0].tool_allowlist.is_empty());
    assert!(gw.consumers[0].token_budget.is_none());
}

// ---------------------------------------------------------------------------
// 5. Tool allowlist: CompiledMcp.consumer_allowed_tool
// ---------------------------------------------------------------------------

#[test]
fn tool_allowlist_compiles_and_filters() {
    use dwara_core::ai::mcp::CompiledMcp;

    let yaml = r#"
listeners:
  - name: l
    address: 0.0.0.0
    port: 8080
routes:
  - name: r
    service: svc
    match:
      path:
        type: exact
        value: /x
    action:
      type: proxy
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 9001
consumers:
  - name: agent-bot
    type: agent
    credentials:
      - type: api_key
        key: k
    tool_allowlist: [search, fetch]
  - name: open-user
    type: user
    credentials:
      - type: api_key
        key: k2
ai:
  mcp:
    path: /mcp
    tools:
      search:
        description: Search
        upstream: pool
        path: /search
        input_schema: {}
      delete:
        description: Delete
        upstream: pool
        path: /delete
        input_schema: {}
"#;
    let gw = parse_gateway(yaml).expect("parses");
    let mcp_config = gw.ai.as_ref().and_then(|a| a.mcp.as_ref()).expect("mcp");
    let compiled = CompiledMcp::compile(mcp_config, &gw).expect("compiles");

    // agent-bot: allowed search and fetch, denied delete.
    assert!(compiled.consumer_allowed_tool("agent-bot", "search"));
    assert!(compiled.consumer_allowed_tool("agent-bot", "fetch"));
    assert!(!compiled.consumer_allowed_tool("agent-bot", "delete"));

    // open-user: no allowlist -> all tools allowed.
    assert!(compiled.consumer_allowed_tool("open-user", "search"));
    assert!(compiled.consumer_allowed_tool("open-user", "delete"));

    // Unknown consumer: no allowlist -> all tools allowed (fail-open).
    assert!(compiled.consumer_allowed_tool("unknown", "search"));
    assert!(compiled.consumer_allowed_tool("unknown", "delete"));
}

// ---------------------------------------------------------------------------
// 6. Per-agent token budget: resolves before the policy chain
// ---------------------------------------------------------------------------

#[test]
fn per_agent_token_budget_resolves_before_policy_chain() {
    use dwara_core::ai::budget::{AiBudgetEngine, BudgetLedger, BudgetVerdict};

    let yaml = r#"
listeners:
  - name: l
    address: 0.0.0.0
    port: 8080
routes:
  - name: r
    service: svc
    match:
      path:
        type: exact
        value: /x
    action:
      type: proxy
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 9001
consumers:
  - name: agent-bot
    type: agent
    credentials:
      - type: api_key
        key: k
    token_budget:
      tokens_per_min: 500
      scope: consumer
policies:
  - name: global-budget
    token_budget:
      tokens_per_min: 10000
      scope: policy
global_policies: [global-budget]
"#;
    let gw = parse_gateway(yaml).expect("parses");
    let ledger = std::sync::Arc::new(BudgetLedger::default());
    let engine = AiBudgetEngine::compile_with_ledger(&gw, ledger);

    // The agent consumer binds the 500 tpm budget (not the 10000 tpm
    // global budget). Verify by checking that spending 501 tokens is
    // denied (over the 500 budget) while 500 is allowed.
    let guard = engine
        .resolve(
            Some("agent-bot"),
            &[],
            &[],
            &[],
            &[],
            &["global-budget".to_string()],
        )
        .expect("resolves a budget");

    // 500 tokens: within budget.
    let verdict = guard.check(0);
    assert_eq!(verdict, BudgetVerdict::Allowed);

    // Spend 500 tokens (the full budget). `spend` returns whether the
    // spend CROSSED the limit (strictly greater), not whether it was
    // allowed. 500 == 500 so it did not cross.
    use dwara_core::ai::types::Usage;
    let usage = Usage {
        prompt_tokens: Some(500),
        completion_tokens: Some(0),
        total_tokens: Some(500),
    };
    let crossed = guard.spend(0, usage, 0);
    assert!(!crossed, "500 tokens did not cross the 500 limit");

    // Now check again: spent 500 >= limit 500, so the next request
    // should be denied.
    let verdict2 = guard.check(0);
    assert_ne!(verdict2, BudgetVerdict::Allowed, "over-budget denied");

    // A consumer without a per-agent budget falls through to the
    // policy chain (the 10000 tpm global budget).
    let guard2 = engine
        .resolve(
            Some("other-user"),
            &[],
            &[],
            &[],
            &[],
            &["global-budget".to_string()],
        )
        .expect("resolves a budget");
    let verdict3 = guard2.check(0);
    assert_eq!(verdict3, BudgetVerdict::Allowed);
}

// ---------------------------------------------------------------------------
// 7. Snapshot validation: tool_allowlist references unknown tool
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_tool_allowlist_referencing_unknown_tool() {
    let yaml = r#"
listeners:
  - name: l
    address: 0.0.0.0
    port: 8080
routes:
  - name: r
    service: svc
    match:
      path:
        type: exact
        value: /x
    action:
      type: proxy
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 9001
consumers:
  - name: agent-bot
    type: agent
    credentials:
      - type: api_key
        key: k
    tool_allowlist: [search, nonexistent]
ai:
  mcp:
    path: /mcp
    tools:
      search:
        description: Search
        upstream: pool
        path: /search
        input_schema: {}
"#;
    let gw = parse_gateway(yaml).expect("parses");
    let issues = dwara_core::snapshot::validate(&gw);
    let found = issues
        .iter()
        .any(|i| i.entity == "consumer" && i.name == "agent-bot" && i.field == "tool_allowlist");
    assert!(
        found,
        "validation should flag the unknown tool: {:?}",
        issues
    );
}

// ---------------------------------------------------------------------------
// 8. Snapshot validation: tool_allowlist without an MCP block
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_tool_allowlist_without_mcp_block() {
    let yaml = r#"
listeners:
  - name: l
    address: 0.0.0.0
    port: 8080
routes:
  - name: r
    service: svc
    match:
      path:
        type: exact
        value: /x
    action:
      type: proxy
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 9001
consumers:
  - name: agent-bot
    type: agent
    credentials:
      - type: api_key
        key: k
    tool_allowlist: [search]
"#;
    let gw = parse_gateway(yaml).expect("parses");
    let issues = dwara_core::snapshot::validate(&gw);
    let found = issues
        .iter()
        .any(|i| i.entity == "consumer" && i.name == "agent-bot" && i.field == "tool_allowlist");
    assert!(
        found,
        "validation should flag the allowlist with no MCP block: {:?}",
        issues
    );
}

// ---------------------------------------------------------------------------
// 9. Snapshot validation: per-consumer token_budget with zero tokens
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_consumer_token_budget_with_zero_tokens() {
    let yaml = r#"
listeners:
  - name: l
    address: 0.0.0.0
    port: 8080
routes:
  - name: r
    service: svc
    match:
      path:
        type: exact
        value: /x
    action:
      type: proxy
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 9001
consumers:
  - name: agent-bot
    type: agent
    credentials:
      - type: api_key
        key: k
    token_budget:
      tokens_per_min: 0
      scope: consumer
"#;
    let gw = parse_gateway(yaml).expect("parses");
    let issues = dwara_core::snapshot::validate(&gw);
    let found = issues.iter().any(|i| {
        i.entity == "consumer" && i.name == "agent-bot" && i.field == "token_budget.tokens_per_min"
    });
    assert!(
        found,
        "validation should flag zero tokens_per_min: {:?}",
        issues
    );
}

// ---------------------------------------------------------------------------
// 10. Snapshot validation: per-consumer token_budget with no windows
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_consumer_token_budget_with_no_windows() {
    let yaml = r#"
listeners:
  - name: l
    address: 0.0.0.0
    port: 8080
routes:
  - name: r
    service: svc
    match:
      path:
        type: exact
        value: /x
    action:
      type: proxy
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 9001
consumers:
  - name: agent-bot
    type: agent
    credentials:
      - type: api_key
        key: k
    token_budget:
      scope: consumer
"#;
    let gw = parse_gateway(yaml).expect("parses");
    let issues = dwara_core::snapshot::validate(&gw);
    let found = issues
        .iter()
        .any(|i| i.entity == "consumer" && i.name == "agent-bot" && i.field == "token_budget");
    assert!(
        found,
        "validation should flag an empty budget: {:?}",
        issues
    );
}

// ---------------------------------------------------------------------------
// 11. Analytics: consumer_type in AiSpendRecord and McpToolCallRecord
// ---------------------------------------------------------------------------

#[test]
fn analytics_records_carry_consumer_type() {
    use dwara_core::analytics::{AiSpendRecord, McpToolCallRecord};

    let spend = AiSpendRecord {
        ts_ms: 1000,
        consumer: "agent-bot".to_string(),
        consumer_type: "agent".to_string(),
        team: "".to_string(),
        provider: "p".to_string(),
        model: "m".to_string(),
        version: "".to_string(),
        prompt_tokens: 10,
        completion_tokens: 20,
        total_tokens: 30,
        cost_micros: 100,
    };
    assert_eq!(spend.consumer_type, "agent");

    let mcp_call = McpToolCallRecord {
        ts_ms: 1000,
        request_id: "rid".to_string(),
        session_id: "sid".to_string(),
        consumer: "agent-bot".to_string(),
        consumer_type: "agent".to_string(),
        tool_name: "search".to_string(),
        allowed: true,
        duration_ms: 5.0,
        error_code: None,
        status: "ok".to_string(),
    };
    assert_eq!(mcp_call.consumer_type, "agent");
}

// ---------------------------------------------------------------------------
// 12. Analytics: schema v8 migration adds consumer_type columns
// ---------------------------------------------------------------------------

#[test]
fn analytics_schema_v8_adds_consumer_type_columns() {
    use dwara_core::analytics::schema::{migrate, LATEST_SCHEMA_VERSION};
    use rusqlite::Connection;

    let dir = tempfile::tempdir().unwrap();
    let conn = Connection::open(dir.path().join("test.db")).unwrap();

    // Create the v7 schema (tables with the pre-v8 column set).
    // Includes a minimal `raw` table so the v9 migration (which ALTERs
    // `raw` to add request_id/correlation_id) can run.
    conn.execute_batch(
        "CREATE TABLE ai_spend (
            ts_ms INTEGER NOT NULL,
            consumer TEXT NOT NULL,
            team TEXT NOT NULL,
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            version TEXT NOT NULL,
            prompt_tokens INTEGER NOT NULL,
            completion_tokens INTEGER NOT NULL,
            total_tokens INTEGER NOT NULL,
            cost_micros INTEGER NOT NULL
        );
        CREATE TABLE mcp_tool_calls (
            ts_ms INTEGER NOT NULL,
            request_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            consumer TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            allowed INTEGER NOT NULL,
            duration_ms REAL NOT NULL,
            error_code TEXT,
            status TEXT NOT NULL
        );
        CREATE TABLE raw (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_ms INTEGER NOT NULL,
            listener TEXT NOT NULL,
            route TEXT NOT NULL,
            consumer TEXT NOT NULL,
            upstream TEXT NOT NULL,
            method TEXT NOT NULL,
            status INTEGER NOT NULL,
            status_class TEXT NOT NULL,
            duration_ms REAL NOT NULL,
            attempts INTEGER NOT NULL,
            rate_limited INTEGER NOT NULL,
            broken INTEGER NOT NULL,
            shed INTEGER NOT NULL,
            dims TEXT NOT NULL
        );
        PRAGMA user_version = 7;",
    )
    .unwrap();

    migrate(&conn).unwrap();

    let v: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, i64::from(LATEST_SCHEMA_VERSION));

    let cols: Vec<String> = conn
        .prepare("PRAGMA table_info(ai_spend)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    assert!(
        cols.iter().any(|c| c == "consumer_type"),
        "ai_spend should have a consumer_type column: {:?}",
        cols
    );

    let cols2: Vec<String> = conn
        .prepare("PRAGMA table_info(mcp_tool_calls)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    assert!(
        cols2.iter().any(|c| c == "consumer_type"),
        "mcp_tool_calls should have a consumer_type column: {:?}",
        cols2
    );

    // Verify the default is 'user'.
    conn.execute(
        "INSERT INTO ai_spend (ts_ms, consumer, team, provider, model, version,
                                prompt_tokens, completion_tokens, total_tokens, cost_micros)
         VALUES (1, 'c', '', 'p', 'm', '', 1, 2, 3, 4)",
        [],
    )
    .unwrap();
    let ct: String = conn
        .query_row(
            "SELECT consumer_type FROM ai_spend WHERE ts_ms = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ct, "user");
}
