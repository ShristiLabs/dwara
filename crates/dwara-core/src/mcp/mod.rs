//! Agent-operable administration via MCP (DW-112).
//!
//! Expose the admin API as an MCP (Model Context Protocol) server with
//! tools for route/service/policy CRUD, stats, and analytics queries.
//! RBAC-scoped tool access -- AI agents operate dwara.
//!
//! ## MCP tools
//!
//! The MCP server exposes the following tools:
//!
//! - `list_routes` -- list all routes in the current config
//! - `get_route` -- get a single route by name
//! - `create_route` -- create a new route
//! - `update_route` -- update an existing route
//! - `delete_route` -- delete a route
//! - `list_services` -- list all services
//! - `get_stats` -- get gateway stats
//! - `get_health` -- get gateway health
//! - `get_config` -- dump the current config
//!
//! ## RBAC
//!
//! Tool access is RBAC-scoped: each tool requires a permission, and
//! the MCP server checks the agent's permissions before executing a
//! tool. Out-of-scope operations are denied.
//!
//! ## JSON-first
//!
//! All tool inputs and outputs are JSON. The CLI also has a
//! `--json` flag for JSON-first output mode.
//!
//! ## Feature gate
//!
//! The `mcp` cargo feature must be enabled.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// MCP protocol types
// ---------------------------------------------------------------------------

/// An MCP tool definition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// The tool name.
    pub name: String,
    /// The tool description.
    pub description: String,
    /// The JSON Schema for the tool's input parameters.
    pub input_schema: Value,
    /// The permission required to use this tool.
    pub required_permission: Permission,
}

/// An MCP tool call request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallRequest {
    /// The tool name.
    pub name: String,
    /// The tool arguments (JSON object).
    pub arguments: Value,
}

/// An MCP tool call response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallResponse {
    /// Whether the call succeeded.
    pub success: bool,
    /// The result (on success) or error message (on failure).
    pub result: Value,
    /// The error code (on failure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

/// A permission required to use a tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Read access (list, get, stats, health, config dump).
    Read,
    /// Write access (create, update, delete).
    Write,
    /// Admin access (purge cache, reload config).
    Admin,
}

/// An agent's identity and permissions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// The agent's name.
    pub name: String,
    /// The agent's permissions.
    pub permissions: Vec<Permission>,
}

impl AgentIdentity {
    /// Check if the agent has a permission.
    pub fn has_permission(&self, perm: Permission) -> bool {
        self.permissions.contains(&perm)
    }

    /// Create an agent with read-only permissions.
    pub fn read_only(name: &str) -> Self {
        Self {
            name: name.to_string(),
            permissions: vec![Permission::Read],
        }
    }

    /// Create an agent with read + write permissions.
    pub fn read_write(name: &str) -> Self {
        Self {
            name: name.to_string(),
            permissions: vec![Permission::Read, Permission::Write],
        }
    }

    /// Create an agent with all permissions.
    pub fn admin(name: &str) -> Self {
        Self {
            name: name.to_string(),
            permissions: vec![Permission::Read, Permission::Write, Permission::Admin],
        }
    }
}

// ---------------------------------------------------------------------------
// MCP server
// ---------------------------------------------------------------------------

/// The MCP server: holds tool definitions and executes tool calls
/// with RBAC checks.
pub struct McpServer {
    tools: HashMap<String, ToolDefinition>,
}

impl McpServer {
    /// Create a new MCP server with the standard admin tools.
    pub fn new() -> Self {
        let mut tools = HashMap::new();

        for tool in standard_tools() {
            tools.insert(tool.name.clone(), tool);
        }

        Self { tools }
    }

    /// List all available tools.
    pub fn list_tools(&self) -> Vec<&ToolDefinition> {
        self.tools.values().collect()
    }

    /// List tools available to an agent (filtered by permissions).
    pub fn list_tools_for(&self, agent: &AgentIdentity) -> Vec<&ToolDefinition> {
        self.tools
            .values()
            .filter(|t| agent.has_permission(t.required_permission))
            .collect()
    }

    /// Get a tool definition by name.
    pub fn get_tool(&self, name: &str) -> Option<&ToolDefinition> {
        self.tools.get(name)
    }

    /// Execute a tool call with RBAC check.
    ///
    /// This is the pure RBAC + dispatch step. The actual tool
    /// execution (calling the admin API) is done by the caller via
    /// the `ToolHandler` trait. This method checks permissions and
    /// returns the appropriate error if the agent is not authorized.
    pub fn execute(
        &self,
        request: &ToolCallRequest,
        agent: &AgentIdentity,
        handler: &dyn ToolHandler,
    ) -> ToolCallResponse {
        // Find the tool.
        let Some(tool) = self.tools.get(&request.name) else {
            return ToolCallResponse {
                success: false,
                result: Value::String(format!("unknown tool: {}", request.name)),
                error_code: Some("unknown_tool".to_string()),
            };
        };

        // Check permissions.
        if !agent.has_permission(tool.required_permission) {
            return ToolCallResponse {
                success: false,
                result: Value::String(format!(
                    "permission denied: tool '{}' requires {:?}, agent '{}' has {:?}",
                    tool.name, tool.required_permission, agent.name, agent.permissions
                )),
                error_code: Some("permission_denied".to_string()),
            };
        }

        // Validate arguments against the tool's input schema.
        if let Err(err) = validate_arguments(&tool.input_schema, &request.arguments) {
            return ToolCallResponse {
                success: false,
                result: Value::String(format!("invalid arguments: {err}")),
                error_code: Some("invalid_arguments".to_string()),
            };
        }

        // Execute the tool.
        handler.execute_tool(&request.name, &request.arguments)
    }

    /// The number of registered tools.
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

/// A tool handler: the caller implements this to actually execute
/// tools (calling the admin API, reading config, etc.).
pub trait ToolHandler {
    fn execute_tool(&self, name: &str, arguments: &Value) -> ToolCallResponse;
}

/// A simple tool handler for testing: returns canned responses.
pub struct MockToolHandler {
    responses: HashMap<String, Value>,
}

impl MockToolHandler {
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
        }
    }

    pub fn with_response(mut self, tool_name: &str, response: Value) -> Self {
        self.responses.insert(tool_name.to_string(), response);
        self
    }
}

impl Default for MockToolHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolHandler for MockToolHandler {
    fn execute_tool(&self, name: &str, _arguments: &Value) -> ToolCallResponse {
        if let Some(result) = self.responses.get(name) {
            ToolCallResponse {
                success: true,
                result: result.clone(),
                error_code: None,
            }
        } else {
            ToolCallResponse {
                success: true,
                result: Value::String(format!("mock response for {name}")),
                error_code: None,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Standard admin tools
// ---------------------------------------------------------------------------

fn standard_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "list_routes".to_string(),
            description: "List all routes in the current gateway config".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
            required_permission: Permission::Read,
        },
        ToolDefinition {
            name: "get_route".to_string(),
            description: "Get a single route by name".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The route name"}
                },
                "required": ["name"],
                "additionalProperties": false
            }),
            required_permission: Permission::Read,
        },
        ToolDefinition {
            name: "create_route".to_string(),
            description: "Create a new route".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "service": {"type": "string"},
                    "path": {"type": "string"},
                    "path_type": {"type": "string", "enum": ["exact", "prefix", "regex"]}
                },
                "required": ["name", "service", "path"],
                "additionalProperties": false
            }),
            required_permission: Permission::Write,
        },
        ToolDefinition {
            name: "update_route".to_string(),
            description: "Update an existing route".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "service": {"type": "string"},
                    "path": {"type": "string"}
                },
                "required": ["name"],
                "additionalProperties": false
            }),
            required_permission: Permission::Write,
        },
        ToolDefinition {
            name: "delete_route".to_string(),
            description: "Delete a route by name".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"}
                },
                "required": ["name"],
                "additionalProperties": false
            }),
            required_permission: Permission::Write,
        },
        ToolDefinition {
            name: "list_services".to_string(),
            description: "List all services in the current config".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
            required_permission: Permission::Read,
        },
        ToolDefinition {
            name: "get_stats".to_string(),
            description: "Get gateway stats (counters, histograms)".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
            required_permission: Permission::Read,
        },
        ToolDefinition {
            name: "get_health".to_string(),
            description: "Get gateway health status".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
            required_permission: Permission::Read,
        },
        ToolDefinition {
            name: "get_config".to_string(),
            description: "Dump the current gateway config as YAML".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
            required_permission: Permission::Read,
        },
        ToolDefinition {
            name: "purge_cache".to_string(),
            description: "Purge the cache for a route or all routes".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "route": {"type": "string", "description": "The route name (or 'all')"}
                },
                "required": ["route"],
                "additionalProperties": false
            }),
            required_permission: Permission::Admin,
        },
    ]
}

// ---------------------------------------------------------------------------
// Argument validation (simplified JSON Schema)
// ---------------------------------------------------------------------------

/// Validate arguments against a JSON Schema (simplified: checks
/// `type`, `required`, `properties`, `additionalProperties`).
fn validate_arguments(schema: &Value, args: &Value) -> Result<(), String> {
    let schema_obj = schema.as_object().ok_or("schema must be an object")?;

    // Check type.
    if let Some(schema_type) = schema_obj.get("type") {
        if schema_type == "object" {
            let args_obj = args.as_object().ok_or("arguments must be an object")?;

            // Check required fields.
            if let Some(required) = schema_obj.get("required").and_then(|r| r.as_array()) {
                for field in required {
                    let field_name = field
                        .as_str()
                        .ok_or("required field name must be a string")?;
                    if !args_obj.contains_key(field_name) {
                        return Err(format!("missing required field: {field_name}"));
                    }
                }
            }

            // Check additionalProperties.
            let additional_allowed = schema_obj
                .get("additionalProperties")
                .map(|v| v.as_bool().unwrap_or(true))
                .unwrap_or(true);

            if !additional_allowed {
                if let Some(properties) = schema_obj.get("properties").and_then(|p| p.as_object()) {
                    for key in args_obj.keys() {
                        if !properties.contains_key(key) {
                            return Err(format!("unknown field: {key}"));
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let handler = MockToolHandler::new()
            .with_response("create_route", serde_json::json!({"created": true}));

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
        let handler = MockToolHandler::new()
            .with_response("purge_cache", serde_json::json!({"purged": true}));

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
}
