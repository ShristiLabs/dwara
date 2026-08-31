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
