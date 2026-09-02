//! A2A (agent-to-agent) protocol support (DW-114).
//!
//! This module is SCAFFOLDED behind the `a2a` cargo feature. The A2A
//! protocol is an emerging standard for inter-agent communication; the
//! spec is NOT yet frozen, so the task lifecycle here is STUBBED: every
//! task-state transition returns an [`A2AStub`] error explaining that
//! the spec is not frozen. What IS implemented today:
//!
//! - The [`A2AAdapter`] struct implementing [`ProviderAdapter`]: it
//!   translates a canonical [`ChatRequest`] into an A2A task-submit
//!   JSON body ([`A2AAdapter::build_request`]) and parses an A2A task
//!   response back into the canonical [`ChatResponse`]
//!   ([`A2AAdapter::parse_response`]). Error and stream-event parsing
//!   are wired too (the SSE framing reuses [`crate::ai::sse`]).
//! - The [`AgentCard`] struct and [`AgentCardParser`]: parse the
//!   JSON-LD-ish Agent Card discovery doc (name, description, url,
//!   version, capabilities, authentication) from an inline JSON value
//!   or a file path.
//! - The [`TaskLifecycle`] enum: the task state machine
//!   (`Submitted`, `Working`, `Completed`, `Failed`, `Canceled`). The
//!   transitions are stubbed pending spec freeze.
//! - The [`A2ASession`] struct: reuses the MCP session-management
//!   patterns (session id, TTL, max-concurrent) for agent-to-agent
//!   task sessions.
//! - The [`handle_a2a_request`] function: routes an A2A call through
//!   the existing `dataplane::ai_proxy` path (the transport is the
//!   agent's named upstream, exactly like a regular provider).
//!
//! # Dependency direction
//!
//! `ai` depends on `config` only. The A2A adapter is a pure translator
//! (no HTTP client of its own), mirroring the OpenAI/Anthropic/Gemini
//! adapters and the MCP gateway. No new dependencies are introduced
//! (the scaffold is hand-rolled, the same locked M4 decision as MCP).
//!
//! # Feature gate
//!
//! The `a2a` cargo feature is flag-only (no new deps). When it is OFF,
//! the `ai.a2a` config block is accepted but inert: validation warns,
//! and [`CompiledA2a::compile`] returns `None` (no A2A providers are
//! wired into the alias table). When it is ON, each configured agent
//! appears as a provider of kind `a2a` in the model alias table.

use crate::ai::adapter::{AiError, ProviderAdapter, ProviderErrorBody, ProviderRequest};
use crate::ai::types::{
    ChatMessage, ChatRequest, ChatResponse, ChatRole, Choice, ContentPart, FinishReason,
    StreamDelta, StreamEvent, Usage,
};
use crate::config::ai::{A2aAgentCard, A2aConfig, AiProviderKind};
use crate::config::Gateway;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// The error returned by every stubbed task-lifecycle method. The A2A
/// task state machine is not implemented pending spec freeze; each
/// transition surfaces this error so callers fail loudly and
/// attributably rather than silently no-op'ing.
#[derive(Debug, Clone, PartialEq)]
pub struct A2AStub {
    /// The task-state transition that was attempted (e.g.
    /// `submit`, `get_status`, `cancel`).
    pub transition: String,
    /// Why it is stubbed (always the spec-not-frozen reason today).
    pub reason: String,
}

impl A2AStub {
    /// Build the standard stub error for a transition.
    pub fn new(transition: impl Into<String>) -> Self {
        A2AStub {
            transition: transition.into(),
            reason: "a2a task lifecycle is stubbed: the spec is not yet frozen \
                     (DW-114)"
                .to_string(),
        }
    }
}

impl std::fmt::Display for A2AStub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a2a stub ({}): {}", self.transition, self.reason)
    }
}

impl std::error::Error for A2AStub {}

/// The A2A task lifecycle state machine (DW-114). The states follow
/// the emerging A2A spec vocabulary; the transitions between them are
/// STUBBED (every transition returns [`A2AStub`]) pending spec freeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskLifecycle {
    /// A task has been submitted to the agent (the initial state).
    Submitted,
    /// The agent is processing the task.
    Working,
    /// The task completed successfully; the result is available.
    Completed,
    /// The task failed; the error is available.
    Failed,
    /// The task was canceled by the caller.
    Canceled,
}

impl TaskLifecycle {
    /// The lowercase wire name (the A2A spec spelling).
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskLifecycle::Submitted => "submitted",
            TaskLifecycle::Working => "working",
            TaskLifecycle::Completed => "completed",
            TaskLifecycle::Failed => "failed",
            TaskLifecycle::Canceled => "canceled",
        }
    }

    /// Parse a wire-name string into a state. Returns None for an
    /// unknown name (the spec is not frozen, so unknown states are
    /// tolerated rather than rejected).
    pub fn parse_state(s: &str) -> Option<Self> {
        match s {
            "submitted" => Some(TaskLifecycle::Submitted),
            "working" => Some(TaskLifecycle::Working),
            "completed" => Some(TaskLifecycle::Completed),
            "failed" => Some(TaskLifecycle::Failed),
            "canceled" => Some(TaskLifecycle::Canceled),
            _ => None,
        }
    }

    /// Submit a task (STUBBED). Returns the standard [`A2AStub`] error;
    /// the actual task-submit state transition waits for spec freeze.
    pub fn submit(&self) -> Result<TaskLifecycle, A2AStub> {
        Err(A2AStub::new("submit"))
    }

    /// Query a task's status (STUBBED). Returns the standard
    /// [`A2AStub`] error; the actual status-query state transition
    /// waits for spec freeze.
    pub fn get_status(&self) -> Result<TaskLifecycle, A2AStub> {
        Err(A2AStub::new("get_status"))
    }

    /// Cancel a task (STUBBED). Returns the standard [`A2AStub`] error;
    /// the actual cancel state transition waits for spec freeze.
    pub fn cancel(&self) -> Result<TaskLifecycle, A2AStub> {
        Err(A2AStub::new("cancel"))
    }
}

/// An Agent Card (DW-114): the JSON-LD-ish discovery doc an A2A agent
/// publishes to declare its identity, capabilities, and
/// authentication. Parsed from an inline JSON value or a file path by
/// [`AgentCardParser`].
#[derive(Debug, Clone, PartialEq)]
pub struct AgentCard {
    /// The agent's human-readable name.
    pub name: String,
    /// A short description of what the agent does.
    pub description: Option<String>,
    /// The agent's base URL (the A2A endpoint).
    pub url: String,
    /// The agent's version string.
    pub version: Option<String>,
    /// The agent's declared capabilities (a free-form JSON object;
    /// the spec is not frozen, so the shape is preserved verbatim).
    pub capabilities: Value,
    /// The agent's authentication declaration (a free-form JSON
    /// object; the spec is not frozen, so the shape is preserved
    /// verbatim). The gateway does not act on this today (the
    /// transport auth comes from the agent's upstream config).
    pub authentication: Value,
}

/// Parses Agent Card JSON (DW-114) from an inline JSON value or a
/// file path. The card shape is JSON-LD-ish: a top-level object with
/// `name`, `description`, `url`, `version`, `capabilities`, and
/// `authentication` fields. Unknown fields are tolerated (the spec is
/// not frozen). Required fields are `name` and `url`; missing either
/// is a parse error.
pub struct AgentCardParser;

impl AgentCardParser {
    /// Parse an Agent Card from an inline JSON value. Returns an
    /// error when the value is not an object or is missing a required
    /// field (`name`, `url`).
    pub fn parse_inline(value: &Value) -> Result<AgentCard, A2AStub> {
        let obj = value.as_object().ok_or_else(|| {
            A2AStub::new("agent_card_parse").into_parse_error("agent card is not a JSON object")
        })?;
        Self::parse_object(obj)
    }

    /// Parse an Agent Card from a file path. Reads the file and parses
    /// it as JSON, then delegates to [`parse_inline`]. Returns an
    /// error when the file cannot be read or is malformed.
    pub fn parse_path(path: &str) -> Result<AgentCard, A2AStub> {
        let bytes = std::fs::read(path).map_err(|e| {
            A2AStub::new("agent_card_parse")
                .into_parse_error(format!("could not read agent card file '{path}': {e}"))
        })?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
            A2AStub::new("agent_card_parse")
                .into_parse_error(format!("agent card file '{path}' is not valid JSON: {e}"))
        })?;
        Self::parse_inline(&value)
    }

    /// Parse a card source (inline-or-path) from the config. Inline
    /// takes precedence over path; when neither is set, returns an
    /// error (a card-less agent has no discovery doc).
    pub fn parse_source(card: Option<&A2aAgentCard>) -> Result<AgentCard, A2AStub> {
        let Some(card) = card else {
            return Err(A2AStub::new("agent_card_parse")
                .into_parse_error("agent has no card (set card.inline or card.path)"));
        };
        if let Some(inline) = &card.inline {
            return Self::parse_inline(inline);
        }
        if let Some(path) = &card.path {
            return Self::parse_path(path);
        }
        Err(A2AStub::new("agent_card_parse")
            .into_parse_error("agent card has neither inline nor path set"))
    }

    fn parse_object(obj: &Map<String, Value>) -> Result<AgentCard, A2AStub> {
        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                A2AStub::new("agent_card_parse")
                    .into_parse_error("agent card is missing the required 'name' field")
            })?
            .to_string();
        let url = obj
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                A2AStub::new("agent_card_parse")
                    .into_parse_error("agent card is missing the required 'url' field")
            })?
            .to_string();
        let description = obj
            .get("description")
            .and_then(Value::as_str)
            .map(String::from);
        let version = obj.get("version").and_then(Value::as_str).map(String::from);
        let capabilities = obj.get("capabilities").cloned().unwrap_or(Value::Null);
        let authentication = obj.get("authentication").cloned().unwrap_or(Value::Null);
        Ok(AgentCard {
            name,
            description,
            url,
            version,
            capabilities,
            authentication,
        })
    }
}

impl A2AStub {
    /// Attach a parse-detail message to a stub, producing a stub
    /// whose `reason` carries the detail (used by the card parser so
    /// the caller sees both the spec-not-frozen context and the
    /// concrete parse failure).
    fn into_parse_error(self, detail: impl Into<String>) -> A2AStub {
        A2AStub {
            transition: self.transition,
            reason: format!("{}: {}", self.reason, detail.into()),
        }
    }
}

/// The A2A provider adapter (DW-114). A pure translator, like the
/// OpenAI/Anthropic/Gemini adapters: it holds no state and opens no
/// connections. The transport is the agent's named upstream, driven
/// from `dataplane::ai_proxy`.
///
/// `build_request` translates a canonical [`ChatRequest`] into an A2A
/// task-submit JSON body: the conversation is folded into the task's
/// `message` field (the A2A spec models a task as a single message
/// exchange; multi-turn history is preserved verbatim under
/// `history`). `parse_response` parses an A2A task response back into
/// the canonical [`ChatResponse`].
pub struct A2AAdapter;

impl ProviderAdapter for A2AAdapter {
    fn kind(&self) -> AiProviderKind {
        AiProviderKind::A2a
    }

    fn build_request(
        &self,
        req: &ChatRequest,
        provider_model: &str,
    ) -> Result<ProviderRequest, AiError> {
        // Fold the canonical conversation into the A2A task-submit
        // shape. The latest user message becomes the task `message`;
        // prior messages are preserved under `history` (the A2A spec
        // is not frozen, so the shape is a reasonable projection that
        // round-trips through parse_response).
        let mut history: Vec<Value> = Vec::new();
        let mut message: Option<Value> = None;
        for (i, m) in req.messages.iter().enumerate() {
            let wire = message_to_a2a(m);
            if i + 1 == req.messages.len() {
                message = Some(wire);
            } else {
                history.push(wire);
            }
        }
        let mut body = Map::new();
        body.insert("jsonrpc".into(), json!("2.0"));
        body.insert("method".into(), json!("tasks/submit"));
        let mut params = Map::new();
        params.insert("model".into(), json!(provider_model));
        if let Some(msg) = message {
            params.insert("message".into(), msg);
        }
        if !history.is_empty() {
            params.insert("history".into(), Value::Array(history));
        }
        if let Some(t) = req.temperature {
            params.insert("temperature".into(), json!(t));
        }
        if let Some(p) = req.top_p {
            params.insert("top_p".into(), json!(p));
        }
        if let Some(m) = req.max_tokens {
            params.insert("max_tokens".into(), json!(m));
        }
        if let Some(stop) = &req.stop {
            params.insert("stop".into(), json!(stop));
        }
        if req.stream {
            params.insert("stream".into(), json!(true));
        }
        body.insert("params".into(), Value::Object(params));
        Ok(ProviderRequest {
            method: http::Method::POST,
            path: "/tasks/submit".to_string(),
            headers: vec![],
            body: Value::Object(body),
        })
    }

    fn parse_response(&self, body: &Value) -> Result<ChatResponse, AiError> {
        let obj = body
            .as_object()
            .ok_or_else(|| AiError::Translation("a2a response is not a JSON object".to_string()))?;
        // The A2A task response carries the result under
        // `result.message` (the JSON-RPC result envelope) or a bare
        // `message` (a non-envelope response). Tolerate both.
        let result = obj.get("result").and_then(Value::as_object).unwrap_or(obj);
        let message = result
            .get("message")
            .ok_or_else(|| AiError::Translation("a2a response has no message".to_string()))?;
        let content = parse_a2a_message(message)?;
        let id = obj.get("id").and_then(Value::as_str).map(String::from);
        let model = result
            .get("model")
            .and_then(Value::as_str)
            .map(String::from);
        let usage = result.get("usage").map(parse_usage);
        let finish_reason = result
            .get("state")
            .and_then(Value::as_str)
            .map(parse_finish_reason)
            .unwrap_or(FinishReason::Stop);
        Ok(ChatResponse {
            id,
            model,
            choices: vec![Choice {
                index: 0,
                message: content,
                finish_reason,
            }],
            usage,
        })
    }

    fn parse_error(&self, body: &Value) -> ProviderErrorBody {
        // A2A errors ride the JSON-RPC 2.0 error envelope:
        // {"error": {"code", "message", "data"}}.
        match body.get("error") {
            Some(Value::Object(e)) => ProviderErrorBody {
                message: e
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("a2a agent returned an error")
                    .to_string(),
                error_type: e.get("data").and_then(Value::as_str).map(String::from),
                code: e.get("code").map(|c| match c {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                }),
            },
            Some(Value::String(s)) => ProviderErrorBody {
                message: s.clone(),
                error_type: None,
                code: None,
            },
            _ => ProviderErrorBody {
                message: "a2a agent returned an error".to_string(),
                error_type: None,
                code: None,
            },
        }
    }

    fn parse_stream_event(&self, data: &Value) -> Result<Vec<StreamEvent>, AiError> {
        // A2A streaming events are SSE-ish (reusing the shared
        // `ai::sse` framer). Each event carries a `delta` with
        // content fragments and an optional terminal `state`.
        let obj = data.as_object().ok_or_else(|| {
            AiError::Translation("a2a stream event is not a JSON object".to_string())
        })?;
        let mut out = Vec::new();
        if let Some(delta) = obj.get("delta") {
            let mut sd = StreamDelta {
                index: 0,
                role: None,
                content: None,
                tool_calls: Vec::new(),
                finish_reason: None,
            };
            if let Some(role) = delta.get("role").and_then(Value::as_str) {
                sd.role = match role {
                    "assistant" => Some(ChatRole::Assistant),
                    _ => None,
                };
            }
            if let Some(text) = delta.get("content").and_then(Value::as_str) {
                sd.content = Some(text.to_string());
            }
            sd.finish_reason = obj
                .get("state")
                .and_then(Value::as_str)
                .map(parse_finish_reason);
            out.push(StreamEvent::Delta(sd));
        }
        if let Some(usage) = obj.get("usage").filter(|u| !u.is_null()) {
            out.push(StreamEvent::Usage(parse_usage(usage)));
        }
        Ok(out)
    }
}

/// Serialize a canonical message into the A2A wire shape (shared with
/// the build_request path).
fn message_to_a2a(m: &ChatMessage) -> Value {
    let mut obj = Map::new();
    obj.insert("role".into(), json!(m.role.as_str()));
    let text = m.text_content();
    if !text.is_empty() {
        obj.insert("content".into(), json!(text));
    } else if !m.content.is_empty() {
        // Multimodal: preserve the parts verbatim (images are not
        // expressible in the A2A text model today; the spec is not
        // frozen).
        let parts: Vec<Value> = m
            .content
            .iter()
            .map(|p| match p {
                ContentPart::Text { text } => json!({"type": "text", "text": text}),
                ContentPart::Image { url, .. } => json!({
                    "type": "image",
                    "image_url": url.clone().unwrap_or_default()
                }),
            })
            .collect();
        obj.insert("content".into(), Value::Array(parts));
    } else {
        obj.insert("content".into(), Value::Null);
    }
    if let Some(name) = &m.name {
        obj.insert("name".into(), json!(name));
    }
    Value::Object(obj)
}

/// Parse an A2A wire message into the canonical shape.
fn parse_a2a_message(v: &Value) -> Result<ChatMessage, AiError> {
    let obj = v
        .as_object()
        .ok_or_else(|| AiError::Translation("a2a message is not an object".to_string()))?;
    let role = match obj.get("role").and_then(Value::as_str) {
        Some("system") => ChatRole::System,
        Some("user") => ChatRole::User,
        Some("assistant") => ChatRole::Assistant,
        Some("tool") => ChatRole::Tool,
        _ => ChatRole::Assistant,
    };
    let mut content = Vec::new();
    match obj.get("content") {
        Some(Value::String(s)) => content.push(ContentPart::Text { text: s.clone() }),
        Some(Value::Array(parts)) => {
            for p in parts {
                match p.get("type").and_then(Value::as_str) {
                    Some("text") => content.push(ContentPart::Text {
                        text: p
                            .get("text")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    }),
                    Some("image") => content.push(ContentPart::Image {
                        url: p.get("image_url").and_then(Value::as_str).map(String::from),
                        media_type: None,
                        data_b64: None,
                    }),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    Ok(ChatMessage {
        role,
        content,
        name: obj.get("name").and_then(Value::as_str).map(String::from),
        tool_calls: Vec::new(),
        tool_call_id: None,
    })
}

/// Parse an A2A task state into a finish reason.
fn parse_finish_reason(s: &str) -> FinishReason {
    match s {
        "completed" => FinishReason::Stop,
        "failed" => FinishReason::Other("failed".to_string()),
        "canceled" => FinishReason::Other("canceled".to_string()),
        other => FinishReason::Other(other.to_string()),
    }
}

/// Parse an A2A usage object (provider-reported only).
fn parse_usage(v: &Value) -> Usage {
    Usage {
        prompt_tokens: v.get("prompt_tokens").and_then(Value::as_u64),
        completion_tokens: v.get("completion_tokens").and_then(Value::as_u64),
        total_tokens: v.get("total_tokens").and_then(Value::as_u64),
    }
}

// --- Session management (mirrors MCP) ------------------------------------

/// Default session TTL in seconds (1 hour), mirroring MCP. Used by
/// `CompiledA2a::compile` (feature-gated); `#[allow(dead_code)]` so the
/// default-feature build (feature off) stays warning-free.
#[allow(dead_code)]
const DEFAULT_TTL_SECS: u64 = 3600;

/// Default max concurrent sessions, mirroring MCP. Used by
/// `CompiledA2a::compile` (feature-gated); `#[allow(dead_code)]` so the
/// default-feature build (feature off) stays warning-free.
#[allow(dead_code)]
const DEFAULT_MAX_CONCURRENT: usize = 1000;

/// Per-process session-id counter (disambiguates coarse clocks and
/// same-nanosecond initializations), mirroring MCP.
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a 128-bit hex session id (mirrors MCP's
/// `generate_session_id`): sha256 over (wall-clock nanos, process
/// counter, agent name), truncated to 32 hex chars. Unique per
/// process; no `rand` dependency.
fn generate_session_id(agent: &str) -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let c = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(n.to_le_bytes());
    hasher.update(c.to_le_bytes());
    hasher.update(agent.as_bytes());
    let hash = hasher.finalize();
    let hex: String = hash.iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!("a2a-{hex}")
}

/// One A2A task session (DW-114), mirroring MCP's session model: a
/// session id, a TTL, and a max-concurrent cap. The session is a
/// correlation handle for an agent-to-agent task exchange; the actual
/// task state machine is stubbed pending spec freeze.
#[derive(Debug, Clone)]
pub struct A2ASession {
    /// The session id (a 128-bit hex handle, unique per process).
    pub id: String,
    /// The agent name this session is bound to.
    pub agent: String,
    /// Session TTL in seconds.
    pub ttl_secs: u64,
    /// Max concurrent sessions.
    pub max_concurrent: usize,
}

impl A2ASession {
    /// Create a new session for `agent`, using the configured session
    /// policy (or the defaults when none is set).
    pub fn new(agent: &str, ttl_secs: u64, max_concurrent: usize) -> Self {
        A2ASession {
            id: generate_session_id(agent),
            agent: agent.to_string(),
            ttl_secs,
            max_concurrent,
        }
    }

    /// The session id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Submit a task on this session (STUBBED). Returns the standard
    /// [`A2AStub`] error; the actual task-submit transition waits for
    /// spec freeze.
    pub fn submit_task(&self) -> Result<TaskLifecycle, A2AStub> {
        Err(A2AStub::new("submit_task"))
    }

    /// Query the task status on this session (STUBBED). Returns the
    /// standard [`A2AStub`] error.
    pub fn get_task_status(&self) -> Result<TaskLifecycle, A2AStub> {
        Err(A2AStub::new("get_task_status"))
    }

    /// Cancel the task on this session (STUBBED). Returns the standard
    /// [`A2AStub`] error.
    pub fn cancel_task(&self) -> Result<TaskLifecycle, A2AStub> {
        Err(A2AStub::new("cancel_task"))
    }
}

// --- Compiled A2A (built at AiRuntime compile time) ----------------------

/// One compiled A2A agent (DW-114): the resolved provider entry an
/// alias can route to. Built at `AiRuntime` compile time from the
/// `ai.a2a.agents[]` config; immutable once built.
#[derive(Debug, Clone)]
pub struct CompiledA2aAgent {
    /// The agent name (the provider name in the alias table).
    pub name: String,
    /// The agent's base URL.
    pub url: String,
    /// The parsed Agent Card (None when the agent has no card or the
    /// card failed to parse — the agent still compiles, the card is
    /// best-effort).
    pub card: Option<AgentCard>,
    /// The name of the upstream that carries the transport.
    pub upstream: String,
    /// Session TTL in seconds.
    pub sessions_ttl_secs: u64,
    /// Max concurrent sessions.
    pub sessions_max_concurrent: usize,
}

/// The compiled A2A surface (DW-114): the agent table and session
/// policy. Built at `AiRuntime` compile time from the `ai.a2a` config
/// block; immutable once built. None when the block is absent or the
/// `a2a` feature is off (the block is inert).
#[derive(Debug, Clone)]
pub struct CompiledA2a {
    /// The compiled agents, keyed by agent name.
    pub agents: BTreeMap<String, CompiledA2aAgent>,
    /// Session TTL in seconds.
    pub sessions_ttl_secs: u64,
    /// Max concurrent sessions.
    pub sessions_max_concurrent: usize,
}

impl CompiledA2a {
    /// Compile from the `ai.a2a` config block. Returns None when the
    /// block is absent, `enabled` is false, or the `a2a` feature is
    /// off (the block is inert in all those cases). Each agent's
    /// Agent Card is parsed best-effort: a parse failure logs a
    /// warning and the agent compiles without a card (the loud,
    /// attributable failure is the validation issue, not a compile
    /// abort).
    pub fn compile(config: Option<&A2aConfig>) -> Option<Self> {
        // Feature gate: when the `a2a` cargo feature is off, the
        // block is inert (no A2A providers are wired).
        #[cfg(not(feature = "a2a"))]
        {
            let _ = config;
            None
        }
        #[cfg(feature = "a2a")]
        {
            let cfg = config?;
            if !cfg.enabled {
                return None;
            }
            let sessions = cfg.sessions.as_ref();
            let sessions_ttl_secs = sessions
                .and_then(|s| s.ttl_secs)
                .unwrap_or(DEFAULT_TTL_SECS);
            let sessions_max_concurrent = sessions
                .and_then(|s| s.max_concurrent)
                .unwrap_or(DEFAULT_MAX_CONCURRENT);
            let mut agents = BTreeMap::new();
            for a in &cfg.agents {
                let card = match AgentCardParser::parse_source(a.card.as_ref()) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        tracing::warn!(
                            code = "a2a_agent_card_parse_failed",
                            agent = %a.name,
                            "a2a agent card could not be parsed; agent compiles \
                             without a card: {e}"
                        );
                        None
                    }
                };
                agents.insert(
                    a.name.clone(),
                    CompiledA2aAgent {
                        name: a.name.clone(),
                        url: a.url.clone(),
                        card,
                        upstream: a.upstream.clone(),
                        sessions_ttl_secs,
                        sessions_max_concurrent,
                    },
                );
            }
            Some(CompiledA2a {
                agents,
                sessions_ttl_secs,
                sessions_max_concurrent,
            })
        }
    }

    /// The compiled agent by name.
    pub fn agent(&self, name: &str) -> Option<&CompiledA2aAgent> {
        self.agents.get(name)
    }

    /// All agent names (introspection/tests).
    pub fn agent_names(&self) -> impl Iterator<Item = &str> {
        self.agents.keys().map(|s| s.as_str())
    }
}

/// Route an A2A call through the existing `dataplane::ai_proxy` path
/// (DW-114). The transport is the agent's named upstream, exactly like
/// a regular provider: the [`A2AAdapter`] builds the task-submit
/// request, `ai_proxy` places the call through the upstream, and the
/// response is parsed back to the canonical shape. This function is
/// the seam the dataplane calls for an A2A-routed alias; today it is
/// STUBBED (the task lifecycle is not implemented), returning an
/// [`A2AStub`] error so the caller fails loudly.
///
/// The actual wiring lands when the spec freezes; the scaffold keeps
/// the call-site shape stable so the dataplane path compiles
/// unchanged with or without the feature.
pub fn handle_a2a_request(
    _agent: &CompiledA2aAgent,
    _req: &ChatRequest,
) -> Result<ChatResponse, A2AStub> {
    Err(A2AStub::new("handle_a2a_request"))
}

/// Build the [`CompiledA2a`] from the gateway's `ai.a2a` block, for
/// the `AiRuntime` compile path. Returns None when the block is
/// absent or inert (feature off / disabled).
pub fn compile_a2a(gateway: &Gateway) -> Option<CompiledA2a> {
    let ai = gateway.ai.as_ref()?;
    CompiledA2a::compile(ai.a2a.as_ref())
}

/// The A2A agent entries that should appear as providers in the alias
/// table (DW-114). Each entry is `(name, upstream)` — the provider
/// name and the upstream that carries its transport. The `AiRuntime`
/// compile path inserts these into the provider pool with
/// `kind: a2a`. Returns an empty vec when the block is absent or
/// inert.
pub fn a2a_providers(gateway: &Gateway) -> Vec<(String, String)> {
    let Some(compiled) = compile_a2a(gateway) else {
        return Vec::new();
    };
    compiled
        .agents
        .values()
        .map(|a| (a.name.clone(), a.upstream.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // White-box: the A2A adapter's translation is private behavior
    // not exercised through a public caller (the gateway A2A path is
    // stubbed); these stay here with that justification and are
    // additionally replayed through the integration suite in
    // tests/a2a.rs.

    #[test]
    fn task_lifecycle_wire_names_round_trip() {
        for s in &[
            TaskLifecycle::Submitted,
            TaskLifecycle::Working,
            TaskLifecycle::Completed,
            TaskLifecycle::Failed,
            TaskLifecycle::Canceled,
        ] {
            assert_eq!(TaskLifecycle::parse_state(s.as_str()), Some(*s));
        }
        assert_eq!(TaskLifecycle::parse_state("unknown"), None);
    }

    #[test]
    fn task_lifecycle_transitions_are_stubbed() {
        let s = TaskLifecycle::Submitted;
        assert!(s.submit().is_err());
        assert!(s.get_status().is_err());
        assert!(s.cancel().is_err());
        let err = s.submit().unwrap_err();
        assert_eq!(err.transition, "submit");
        assert!(err.reason.contains("not yet frozen"));
    }

    #[test]
    fn session_task_methods_are_stubbed() {
        let s = A2ASession::new("my-agent", 3600, 1000);
        assert!(s.id().starts_with("a2a-"));
        assert!(s.submit_task().is_err());
        assert!(s.get_task_status().is_err());
        assert!(s.cancel_task().is_err());
    }

    #[test]
    fn handle_a2a_request_is_stubbed() {
        let agent = CompiledA2aAgent {
            name: "a".to_string(),
            url: "https://agent.example.com".to_string(),
            card: None,
            upstream: "u".to_string(),
            sessions_ttl_secs: 3600,
            sessions_max_concurrent: 1000,
        };
        let req = ChatRequest {
            model: "m".to_string(),
            messages: vec![ChatMessage::text(ChatRole::User, "hi")],
            tools: Vec::new(),
            tool_choice: None,
            temperature: None,
            top_p: None,
            max_tokens: None,
            stop: None,
            stream: false,
            stream_options_include_usage: false,
            other: BTreeMap::new(),
        };
        let err = handle_a2a_request(&agent, &req).unwrap_err();
        assert_eq!(err.transition, "handle_a2a_request");
    }
}
