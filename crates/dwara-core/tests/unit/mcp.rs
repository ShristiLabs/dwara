//! Unit tests for `mcp` (relocated from src).

#![cfg(feature = "mcp")]

use dwara_core::mcp::{
    AgentIdentity, McpServer, MockToolHandler, Permission, ToolCallRequest, ToolCallResponse,
    ToolDefinition,
};
use serde_json::Value;

#[test]
fn server_has_standard_tools() {
    let server = McpServer::new();
    assert!(server.tool_count() >= 10);

    assert!(server.get_tool("list_routes").is_some());
    assert!(server.get_tool("get_route").is_some());
    assert!(server.get_tool("create_route").is_some());
    assert!(server.get_tool("update_route").is_some());
    assert!(server.get_tool("delete_route").is_some());
    assert!(server.get_tool("list_services").is_some());
    assert!(server.get_tool("get_stats").is_some());
    assert!(server.get_tool("get_health").is_some());
    assert!(server.get_tool("get_config").is_some());
    assert!(server.get_tool("purge_cache").is_some());
}

#[test]
fn tool_definitions_have_permissions() {
    let server = McpServer::new();

    assert_eq!(
        server.get_tool("list_routes").unwrap().required_permission,
        Permission::Read
    );
    assert_eq!(
        server.get_tool("create_route").unwrap().required_permission,
        Permission::Write
    );
    assert_eq!(
        server.get_tool("delete_route").unwrap().required_permission,
        Permission::Write
    );
    assert_eq!(
        server.get_tool("purge_cache").unwrap().required_permission,
        Permission::Admin
    );
}

#[test]
fn agent_read_only_can_list_routes() {
    let server = McpServer::new();
    let agent = AgentIdentity::read_only("agent-1");

    let tools = server.list_tools_for(&agent);
    assert!(tools.iter().any(|t| t.name == "list_routes"));
    assert!(!tools.iter().any(|t| t.name == "create_route"));
    assert!(!tools.iter().any(|t| t.name == "purge_cache"));
}

#[test]
fn agent_read_write_can_create_but_not_purge() {
    let server = McpServer::new();
    let agent = AgentIdentity::read_write("agent-1");

    let tools = server.list_tools_for(&agent);
    assert!(tools.iter().any(|t| t.name == "list_routes"));
    assert!(tools.iter().any(|t| t.name == "create_route"));
    assert!(!tools.iter().any(|t| t.name == "purge_cache"));
}

#[test]
fn agent_admin_can_do_everything() {
    let server = McpServer::new();
    let agent = AgentIdentity::admin("agent-1");

    let tools = server.list_tools_for(&agent);
    assert!(tools.iter().any(|t| t.name == "list_routes"));
    assert!(tools.iter().any(|t| t.name == "create_route"));
    assert!(tools.iter().any(|t| t.name == "purge_cache"));
}

#[test]
fn execute_unknown_tool() {
    let server = McpServer::new();
    let agent = AgentIdentity::admin("agent-1");
    let handler = MockToolHandler::new();

    let request = ToolCallRequest {
        name: "nonexistent".to_string(),
        arguments: Value::Object(serde_json::Map::new()),
    };

    let response = server.execute(&request, &agent, &handler);
    assert!(!response.success);
    assert_eq!(response.error_code, Some("unknown_tool".to_string()));
}

#[test]
fn execute_permission_denied() {
    let server = McpServer::new();
    let agent = AgentIdentity::read_only("agent-1");
    let handler = MockToolHandler::new();

    let request = ToolCallRequest {
        name: "create_route".to_string(),
        arguments: serde_json::json!({
            "name": "test-route",
            "service": "test-service",
            "path": "/test"
        }),
    };

    let response = server.execute(&request, &agent, &handler);
    assert!(!response.success);
    assert_eq!(response.error_code, Some("permission_denied".to_string()));
}

#[test]
fn execute_read_tool_succeeds() {
    let server = McpServer::new();
    let agent = AgentIdentity::read_only("agent-1");
    let handler = MockToolHandler::new().with_response(
        "list_routes",
        serde_json::json!({"routes": ["route-1", "route-2"]}),
    );

    let request = ToolCallRequest {
        name: "list_routes".to_string(),
        arguments: Value::Object(serde_json::Map::new()),
    };

    let response = server.execute(&request, &agent, &handler);
    assert!(response.success);
    assert!(response.result.get("routes").is_some());
}

#[test]
fn execute_write_tool_succeeds_with_write_perm() {
    let server = McpServer::new();
    let agent = AgentIdentity::read_write("agent-1");
    let handler =
        MockToolHandler::new().with_response("create_route", serde_json::json!({"created": true}));

    let request = ToolCallRequest {
        name: "create_route".to_string(),
        arguments: serde_json::json!({
            "name": "test-route",
            "service": "test-service",
            "path": "/test"
        }),
    };

    let response = server.execute(&request, &agent, &handler);
    assert!(response.success);
    assert_eq!(response.result.get("created"), Some(&Value::Bool(true)));
}

#[test]
fn execute_admin_tool_succeeds_with_admin_perm() {
    let server = McpServer::new();
    let agent = AgentIdentity::admin("agent-1");
    let handler =
        MockToolHandler::new().with_response("purge_cache", serde_json::json!({"purged": true}));

    let request = ToolCallRequest {
        name: "purge_cache".to_string(),
        arguments: serde_json::json!({"route": "all"}),
    };

    let response = server.execute(&request, &agent, &handler);
    assert!(response.success);
}

#[test]
fn execute_admin_tool_denied_without_admin_perm() {
    let server = McpServer::new();
    let agent = AgentIdentity::read_write("agent-1");
    let handler = MockToolHandler::new();

    let request = ToolCallRequest {
        name: "purge_cache".to_string(),
        arguments: serde_json::json!({"route": "all"}),
    };

    let response = server.execute(&request, &agent, &handler);
    assert!(!response.success);
    assert_eq!(response.error_code, Some("permission_denied".to_string()));
}

#[test]
fn execute_missing_required_field() {
    let server = McpServer::new();
    let agent = AgentIdentity::admin("agent-1");
    let handler = MockToolHandler::new();

    let request = ToolCallRequest {
        name: "create_route".to_string(),
        arguments: serde_json::json!({
            "name": "test-route"
            // missing service and path
        }),
    };

    let response = server.execute(&request, &agent, &handler);
    assert!(!response.success);
    assert_eq!(response.error_code, Some("invalid_arguments".to_string()));
}

#[test]
fn execute_unknown_field_rejected() {
    let server = McpServer::new();
    let agent = AgentIdentity::admin("agent-1");
    let handler = MockToolHandler::new();

    let request = ToolCallRequest {
        name: "create_route".to_string(),
        arguments: serde_json::json!({
            "name": "test-route",
            "service": "svc",
            "path": "/test",
            "unknown_field": "should be rejected"
        }),
    };

    let response = server.execute(&request, &agent, &handler);
    assert!(!response.success);
    assert_eq!(response.error_code, Some("invalid_arguments".to_string()));
}

// --- Done-when: MCP client creates a route, reads stats, and is
//     denied out-of-scope operations ---

#[test]
fn done_when_mcp_client_creates_route_reads_stats_denied_out_of_scope() {
    let server = McpServer::new();
    let agent = AgentIdentity::read_write("mcp-client");
    let handler = MockToolHandler::new()
        .with_response(
            "create_route",
            serde_json::json!({"created": true, "route": "api-v2"}),
        )
        .with_response(
            "get_stats",
            serde_json::json!({"requests_total": 12345, "errors_total": 10}),
        );

    // 1. Create a route (write permission -- should succeed).
    let create_req = ToolCallRequest {
        name: "create_route".to_string(),
        arguments: serde_json::json!({
            "name": "api-v2",
            "service": "backend-v2",
            "path": "/api/v2"
        }),
    };
    let create_resp = server.execute(&create_req, &agent, &handler);
    assert!(create_resp.success);
    assert_eq!(create_resp.result.get("created"), Some(&Value::Bool(true)));

    // 2. Read stats (read permission -- should succeed).
    let stats_req = ToolCallRequest {
        name: "get_stats".to_string(),
        arguments: Value::Object(serde_json::Map::new()),
    };
    let stats_resp = server.execute(&stats_req, &agent, &handler);
    assert!(stats_resp.success);
    assert_eq!(
        stats_resp.result.get("requests_total"),
        Some(&Value::Number(serde_json::Number::from(12345)))
    );

    // 3. Purge cache (admin permission -- should be denied).
    let purge_req = ToolCallRequest {
        name: "purge_cache".to_string(),
        arguments: serde_json::json!({"route": "all"}),
    };
    let purge_resp = server.execute(&purge_req, &agent, &handler);
    assert!(!purge_resp.success);
    assert_eq!(purge_resp.error_code, Some("permission_denied".to_string()));
}

// --- Serialization ---

#[test]
fn tool_definition_serialization() {
    let tool = ToolDefinition {
        name: "test".to_string(),
        description: "test tool".to_string(),
        input_schema: serde_json::json!({"type": "object"}),
        required_permission: Permission::Read,
    };

    let json = serde_json::to_string(&tool).unwrap();
    let deserialized: ToolDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(tool, deserialized);
}

#[test]
fn tool_call_request_serialization() {
    let request = ToolCallRequest {
        name: "list_routes".to_string(),
        arguments: Value::Object(serde_json::Map::new()),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: ToolCallRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request, deserialized);
}

#[test]
fn tool_call_response_serialization() {
    let response = ToolCallResponse {
        success: true,
        result: Value::String("ok".to_string()),
        error_code: None,
    };

    let json = serde_json::to_string(&response).unwrap();
    let deserialized: ToolCallResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);
}

#[test]
fn permission_serialization() {
    assert_eq!(
        serde_json::to_string(&Permission::Read).unwrap(),
        "\"read\""
    );
    assert_eq!(
        serde_json::to_string(&Permission::Write).unwrap(),
        "\"write\""
    );
    assert_eq!(
        serde_json::to_string(&Permission::Admin).unwrap(),
        "\"admin\""
    );
}

#[test]
fn agent_identity_serialization() {
    let agent = AgentIdentity::read_only("test-agent");

    let json = serde_json::to_string(&agent).unwrap();
    let deserialized: AgentIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(agent, deserialized);
}

#[test]
fn agent_has_permission() {
    let agent = AgentIdentity::read_write("test");
    assert!(agent.has_permission(Permission::Read));
    assert!(agent.has_permission(Permission::Write));
    assert!(!agent.has_permission(Permission::Admin));
}

#[test]
fn list_tools_returns_all() {
    let server = McpServer::new();
    let tools = server.list_tools();
    assert_eq!(tools.len(), server.tool_count());
}

#[test]
fn list_tools_for_read_only_filters_correctly() {
    let server = McpServer::new();
    let agent = AgentIdentity::read_only("test");
    let tools = server.list_tools_for(&agent);

    // All tools should be Read permission.
    assert!(tools
        .iter()
        .all(|t| t.required_permission == Permission::Read));
    // No Write or Admin tools.
    assert!(!tools
        .iter()
        .any(|t| t.required_permission == Permission::Write));
    assert!(!tools
        .iter()
        .any(|t| t.required_permission == Permission::Admin));
}
