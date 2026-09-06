//! A2A (agent-to-agent) protocol support (DW-114).
//!
//! This module implements the A2A protocol's task lifecycle state
//! machine against the A2A Protocol Specification draft (the task
//! state vocabulary: `submitted`, `working`, `completed`, `failed`,
//! `canceled`). The draft is not a formally stable standard; the
//! implemented contract is the task lifecycle state machine as
//! documented in the A2A Protocol Specification repository
//! (<https://github.com/a2aproject/A2A>) as of 2025-Q4. The state
//! vocabulary and the legal transitions are stable in the draft; the
//! wire format (JSON-RPC method names, envelope shapes) may evolve.
//!
//! # What is implemented
//!
//! - The [`TaskStateMachine`] struct: a validating state machine for
//!   A2A task lifecycle transitions. Legal transitions:
//!   - `Submitted -> Working` (the agent starts processing)
//!   - `Submitted -> Failed` (the agent rejects the task)
//!   - `Submitted -> Canceled` (the caller cancels before processing)
//!   - `Working -> Completed` (the agent finishes successfully)
//!   - `Working -> Failed` (the agent fails mid-processing)
//!   - `Working -> Canceled` (the caller cancels during processing)
//!   - `Completed`, `Failed`, `Canceled` are terminal (no transitions
//!     out). Illegal transitions return an [`A2AError`] naming the
//!     attempted and target states.
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
//! - The [`TaskLifecycle`] enum: the task state vocabulary
//!   (`Submitted`, `Working`, `Completed`, `Failed`, `Canceled`).
//! - The [`A2ASession`] struct: reuses the MCP session-management
//!   patterns (session id, TTL, max-concurrent) for agent-to-agent
//!   task sessions. Each session owns a [`TaskStateMachine`].
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

/// Error returned by A2A task lifecycle operations. Replaces the
/// former `A2AStub` (the spec is now sufficiently stable for the task
/// state machine; the wire format may still evolve). The [`A2AStub`]
/// type is kept as an alias for backward compatibility with the
/// `handle_a2a_request` function (which is about the network call,
/// not the state machine).
#[derive(Debug, Clone, PartialEq)]
pub enum A2AError {
    /// An illegal state transition was attempted (e.g. Completed ->
    /// Working). The `from` and `to` fields name the states.
    IllegalTransition {
        from: TaskLifecycle,
        to: TaskLifecycle,
    },
    /// A parse error (Agent Card JSON, response JSON, etc.).
    ParseError(String),
    /// The network call is not yet wired (the adapter intentionally
    /// does not own an HTTP client; the transport is the agent's
    /// upstream). This is the only remaining "stub" surface.
    NetworkNotWired(String),
}

impl std::fmt::Display for A2AError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            A2AError::IllegalTransition { from, to } => {
                write!(
                    f,
                    "a2a illegal task transition: {} -> {}",
                    from.as_str(),
                    to.as_str()
                )
            }
            A2AError::ParseError(m) => write!(f, "a2a parse error: {m}"),
            A2AError::NetworkNotWired(m) => write!(f, "a2a network not wired: {m}"),
        }
    }
}

impl std::error::Error for A2AError {}

/// The former stub error type, kept as a compatibility alias for the
/// `handle_a2a_request` function (which is about the network call, not
/// the state machine). New code should use [`A2AError`] directly.
#[derive(Debug, Clone, PartialEq)]
pub struct A2AStub {
    /// The operation that was attempted.
    pub transition: String,
    /// Why it is not wired.
    pub reason: String,
}

impl A2AStub {
    /// Build the standard stub error for a network-not-wired
    /// operation.
    pub fn new(transition: impl Into<String>) -> Self {
        A2AStub {
            transition: transition.into(),
            reason: "a2a network call is not wired (DW-114): the adapter does \
                     not own an HTTP client; the transport is the agent's \
                     upstream"
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

impl A2AStub {
    /// Attach a parse-detail message to a stub, producing a stub
    /// whose `reason` carries the detail (used by the card parser so
    /// the caller sees both the context and the concrete parse
    /// failure).
    fn into_parse_error(self, detail: impl Into<String>) -> A2AStub {
        A2AStub {
            transition: self.transition,
            reason: format!("{}: {}", self.reason, detail.into()),
        }
    }
}

/// The A2A task lifecycle state vocabulary (DW-114). The states follow
/// the A2A Protocol Specification draft: `submitted`, `working`,
/// `completed`, `failed`, `canceled`. The legal transitions between
/// them are enforced by [`TaskStateMachine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskLifecycle {
    /// A task has been submitted to the agent (the initial state).
    Submitted,
    /// The agent is processing the task.
    Working,
    /// The task completed successfully; the result is available.
    /// Terminal state.
    Completed,
    /// The task failed; the error is available. Terminal state.
    Failed,
    /// The task was canceled by the caller. Terminal state.
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

    /// Whether this state is terminal (no transitions out).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TaskLifecycle::Completed | TaskLifecycle::Failed | TaskLifecycle::Canceled
        )
    }

    /// Whether the transition `self -> target` is legal per the A2A
    /// task lifecycle state machine.
    pub fn can_transition_to(&self, target: TaskLifecycle) -> bool {
        matches!(
            (self, target),
            (TaskLifecycle::Submitted, TaskLifecycle::Working)
                | (TaskLifecycle::Submitted, TaskLifecycle::Failed)
                | (TaskLifecycle::Submitted, TaskLifecycle::Canceled)
                | (TaskLifecycle::Working, TaskLifecycle::Completed)
                | (TaskLifecycle::Working, TaskLifecycle::Failed)
                | (TaskLifecycle::Working, TaskLifecycle::Canceled)
        )
    }
}

/// A validating state machine for A2A task lifecycle transitions
/// (DW-114). Holds the current state; transition methods validate the
/// transition and return the new state, or an [`A2AError`] when the
/// transition is illegal.
///
/// The state machine is the in-process task tracker; it does NOT own
/// a network connection (the adapter intentionally does not own an
/// HTTP client — the transport is the agent's upstream, driven from
/// `dataplane::ai_proxy`). The state machine is updated by the
/// dataplane as it observes task responses and events.
#[derive(Debug, Clone)]
pub struct TaskStateMachine {
    state: TaskLifecycle,
}

impl TaskStateMachine {
    /// Create a new task in the `Submitted` state (the initial state).
    pub fn new() -> Self {
        TaskStateMachine {
            state: TaskLifecycle::Submitted,
        }
    }

    /// Create a state machine at a specific state (used when
    /// reconstructing a task from a persisted or observed state).
    pub fn from_state(state: TaskLifecycle) -> Self {
        TaskStateMachine { state }
    }

    /// The current state.
    pub fn state(&self) -> TaskLifecycle {
        self.state
    }

    /// Transition to `target`, returning the new state on success or
    /// an [`A2AError::IllegalTransition`] when the transition is not
    /// legal from the current state.
    pub fn transition_to(&mut self, target: TaskLifecycle) -> Result<TaskLifecycle, A2AError> {
        if self.state.can_transition_to(target) {
            self.state = target;
            Ok(self.state)
        } else {
            Err(A2AError::IllegalTransition {
                from: self.state,
                to: target,
            })
        }
    }

    /// Start processing the task (Submitted -> Working). Returns the
    /// new state or an error when the task is not in the Submitted
    /// state.
    pub fn start_work(&mut self) -> Result<TaskLifecycle, A2AError> {
        self.transition_to(TaskLifecycle::Working)
    }

    /// Mark the task as completed (Working -> Completed). Returns the
    /// new state or an error when the task is not in the Working
    /// state.
    pub fn complete(&mut self) -> Result<TaskLifecycle, A2AError> {
        self.transition_to(TaskLifecycle::Completed)
    }

    /// Mark the task as failed (Submitted|Working -> Failed). Returns
    /// the new state or an error when the task is in a terminal state.
    pub fn fail(&mut self) -> Result<TaskLifecycle, A2AError> {
        self.transition_to(TaskLifecycle::Failed)
    }

    /// Cancel the task (Submitted|Working -> Canceled). Returns the
    /// new state or an error when the task is in a terminal state.
    pub fn cancel(&mut self) -> Result<TaskLifecycle, A2AError> {
        self.transition_to(TaskLifecycle::Canceled)
    }

    /// Whether the task is in a terminal state (Completed, Failed, or
    /// Canceled — no further transitions are possible).
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

impl Default for TaskStateMachine {
    fn default() -> Self {
        Self::new()
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
/// correlation handle for an agent-to-agent task exchange and owns a
/// [`TaskStateMachine`] tracking the task's lifecycle state.
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
    /// The task lifecycle state machine for this session's task.
    pub task: TaskStateMachine,
}

impl A2ASession {
    /// Create a new session for `agent`, using the configured session
    /// policy (or the defaults when none is set). The task starts in
    /// the `Submitted` state.
    pub fn new(agent: &str, ttl_secs: u64, max_concurrent: usize) -> Self {
        A2ASession {
            id: generate_session_id(agent),
            agent: agent.to_string(),
            ttl_secs,
            max_concurrent,
            task: TaskStateMachine::new(),
        }
    }

    /// The session id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The current task lifecycle state.
    pub fn task_state(&self) -> TaskLifecycle {
        self.task.state()
    }

    /// Start processing the task (Submitted -> Working). Delegates to
    /// the session's [`TaskStateMachine`].
    pub fn start_work(&mut self) -> Result<TaskLifecycle, A2AError> {
        self.task.start_work()
    }

    /// Mark the task as completed (Working -> Completed).
    pub fn complete(&mut self) -> Result<TaskLifecycle, A2AError> {
        self.task.complete()
    }

    /// Mark the task as failed (Submitted|Working -> Failed).
    pub fn fail(&mut self) -> Result<TaskLifecycle, A2AError> {
        self.task.fail()
    }

    /// Cancel the task (Submitted|Working -> Canceled).
    pub fn cancel(&mut self) -> Result<TaskLifecycle, A2AError> {
        self.task.cancel()
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
/// the seam the dataplane calls for an A2A-routed alias; today it
/// returns an [`A2AStub`] error because the adapter intentionally
/// does not own an HTTP client (the transport is the agent's
/// upstream, driven from `dataplane::ai_proxy`). The task lifecycle
/// state machine itself is implemented (see [`TaskStateMachine`]);
/// this function is the network-call seam, not the state machine.
///
/// The scaffold keeps the call-site shape stable so the dataplane
/// path compiles unchanged with or without the feature.
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
    fn task_lifecycle_is_terminal() {
        assert!(!TaskLifecycle::Submitted.is_terminal());
        assert!(!TaskLifecycle::Working.is_terminal());
        assert!(TaskLifecycle::Completed.is_terminal());
        assert!(TaskLifecycle::Failed.is_terminal());
        assert!(TaskLifecycle::Canceled.is_terminal());
    }

    #[test]
    fn task_lifecycle_can_transition_to_legal() {
        assert!(TaskLifecycle::Submitted.can_transition_to(TaskLifecycle::Working));
        assert!(TaskLifecycle::Submitted.can_transition_to(TaskLifecycle::Failed));
        assert!(TaskLifecycle::Submitted.can_transition_to(TaskLifecycle::Canceled));
        assert!(TaskLifecycle::Working.can_transition_to(TaskLifecycle::Completed));
        assert!(TaskLifecycle::Working.can_transition_to(TaskLifecycle::Failed));
        assert!(TaskLifecycle::Working.can_transition_to(TaskLifecycle::Canceled));
    }

    #[test]
    fn task_lifecycle_cannot_transition_to_illegal() {
        // No transitions out of terminal states.
        for terminal in [
            TaskLifecycle::Completed,
            TaskLifecycle::Failed,
            TaskLifecycle::Canceled,
        ] {
            for target in [
                TaskLifecycle::Submitted,
                TaskLifecycle::Working,
                TaskLifecycle::Completed,
                TaskLifecycle::Failed,
                TaskLifecycle::Canceled,
            ] {
                assert!(
                    !terminal.can_transition_to(target),
                    "terminal {:?} should not transition to {:?}",
                    terminal,
                    target
                );
            }
        }
        // No Submitted -> Completed (must go through Working).
        assert!(!TaskLifecycle::Submitted.can_transition_to(TaskLifecycle::Completed));
        // No Working -> Submitted (no going back).
        assert!(!TaskLifecycle::Working.can_transition_to(TaskLifecycle::Submitted));
    }

    #[test]
    fn state_machine_happy_path_submitted_to_working_to_completed() {
        let mut sm = TaskStateMachine::new();
        assert_eq!(sm.state(), TaskLifecycle::Submitted);
        assert!(!sm.is_terminal());

        let s = sm.start_work().expect("submitted -> working");
        assert_eq!(s, TaskLifecycle::Working);
        assert_eq!(sm.state(), TaskLifecycle::Working);

        let s = sm.complete().expect("working -> completed");
        assert_eq!(s, TaskLifecycle::Completed);
        assert_eq!(sm.state(), TaskLifecycle::Completed);
        assert!(sm.is_terminal());
    }

    #[test]
    fn state_machine_fail_from_submitted() {
        let mut sm = TaskStateMachine::new();
        let s = sm.fail().expect("submitted -> failed");
        assert_eq!(s, TaskLifecycle::Failed);
        assert!(sm.is_terminal());
    }

    #[test]
    fn state_machine_fail_from_working() {
        let mut sm = TaskStateMachine::new();
        sm.start_work().expect("submitted -> working");
        let s = sm.fail().expect("working -> failed");
        assert_eq!(s, TaskLifecycle::Failed);
        assert!(sm.is_terminal());
    }

    #[test]
    fn state_machine_cancel_from_submitted() {
        let mut sm = TaskStateMachine::new();
        let s = sm.cancel().expect("submitted -> canceled");
        assert_eq!(s, TaskLifecycle::Canceled);
        assert!(sm.is_terminal());
    }

    #[test]
    fn state_machine_cancel_from_working() {
        let mut sm = TaskStateMachine::new();
        sm.start_work().expect("submitted -> working");
        let s = sm.cancel().expect("working -> canceled");
        assert_eq!(s, TaskLifecycle::Canceled);
        assert!(sm.is_terminal());
    }

    #[test]
    fn state_machine_rejects_completed_to_working() {
        let mut sm = TaskStateMachine::new();
        sm.start_work().expect("submitted -> working");
        sm.complete().expect("working -> completed");
        let err = sm.start_work().expect_err("completed is terminal");
        assert!(matches!(
            err,
            A2AError::IllegalTransition {
                from: TaskLifecycle::Completed,
                to: TaskLifecycle::Working,
            }
        ));
    }

    #[test]
    fn state_machine_rejects_failed_to_completed() {
        let mut sm = TaskStateMachine::new();
        sm.fail().expect("submitted -> failed");
        let err = sm.complete().expect_err("failed is terminal");
        assert!(matches!(
            err,
            A2AError::IllegalTransition {
                from: TaskLifecycle::Failed,
                to: TaskLifecycle::Completed,
            }
        ));
    }

    #[test]
    fn state_machine_rejects_canceled_to_working() {
        let mut sm = TaskStateMachine::new();
        sm.cancel().expect("submitted -> canceled");
        let err = sm.start_work().expect_err("canceled is terminal");
        assert!(matches!(
            err,
            A2AError::IllegalTransition {
                from: TaskLifecycle::Canceled,
                to: TaskLifecycle::Working,
            }
        ));
    }

    #[test]
    fn state_machine_rejects_submitted_to_completed() {
        let mut sm = TaskStateMachine::new();
        let err = sm.complete().expect_err("must go through working");
        assert!(matches!(
            err,
            A2AError::IllegalTransition {
                from: TaskLifecycle::Submitted,
                to: TaskLifecycle::Completed,
            }
        ));
    }

    #[test]
    fn state_machine_rejects_working_to_submitted() {
        let mut sm = TaskStateMachine::new();
        sm.start_work().expect("submitted -> working");
        let err = sm
            .transition_to(TaskLifecycle::Submitted)
            .expect_err("no going back");
        assert!(matches!(
            err,
            A2AError::IllegalTransition {
                from: TaskLifecycle::Working,
                to: TaskLifecycle::Submitted,
            }
        ));
    }

    #[test]
    fn state_machine_from_state() {
        let sm = TaskStateMachine::from_state(TaskLifecycle::Working);
        assert_eq!(sm.state(), TaskLifecycle::Working);
    }

    #[test]
    fn session_task_lifecycle() {
        let mut s = A2ASession::new("my-agent", 3600, 1000);
        assert!(s.id().starts_with("a2a-"));
        assert_eq!(s.task_state(), TaskLifecycle::Submitted);

        s.start_work().expect("submitted -> working");
        assert_eq!(s.task_state(), TaskLifecycle::Working);

        s.complete().expect("working -> completed");
        assert_eq!(s.task_state(), TaskLifecycle::Completed);
    }

    #[test]
    fn session_cancel_from_submitted() {
        let mut s = A2ASession::new("my-agent", 3600, 1000);
        s.cancel().expect("submitted -> canceled");
        assert_eq!(s.task_state(), TaskLifecycle::Canceled);
    }

    #[test]
    fn session_fail_from_working() {
        let mut s = A2ASession::new("my-agent", 3600, 1000);
        s.start_work().expect("submitted -> working");
        s.fail().expect("working -> failed");
        assert_eq!(s.task_state(), TaskLifecycle::Failed);
    }

    #[test]
    fn session_rejects_illegal_transition() {
        let mut s = A2ASession::new("my-agent", 3600, 1000);
        s.complete().expect_err("submitted -> completed is illegal");
        assert_eq!(s.task_state(), TaskLifecycle::Submitted);
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
