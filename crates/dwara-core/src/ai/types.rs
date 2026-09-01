//! Canonical chat-completion types (DW-075).
//!
//! One request/response vocabulary that every adapter translates to and
//! from. The canonical shape is a SUPERSET of the OpenAI
//! chat-completions surface (the facade dialect clients speak — see
//! [`crate::ai::openai_compat`]) carrying exactly the fields the three
//! shipped provider dialects can express; anything a client sends that
//! the canonical surface does not model is preserved verbatim in
//! [`ChatRequest::other`] and re-emitted only by the OpenAI adapter
//! (dialect-specific parameters cannot be translated honestly, so the
//! Anthropic/Gemini adapters DROP them — documented behavior, not
//! silent corruption).
//!
//! Token accounting is PROVIDER-REPORTED ONLY (locked M4 decision): the
//! gateway never estimates token counts itself. [`Usage`] fields are
//! optional because providers report subsets (Anthropic streams split
//! input/output tokens across different events).

use serde_json::Value;
use std::collections::BTreeMap;

/// The role of one chat message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatRole {
    System,
    User,
    Assistant,
    Tool,
}

impl ChatRole {
    /// The lowercase wire name shared by the OpenAI dialect and the
    /// canonical facade.
    pub fn as_str(&self) -> &'static str {
        match self {
            ChatRole::System => "system",
            ChatRole::User => "user",
            ChatRole::Assistant => "assistant",
            ChatRole::Tool => "tool",
        }
    }
}

/// One part of a message's content. Multimodal messages carry parts;
/// plain-text messages carry exactly one [`ContentPart::Text`].
#[derive(Debug, Clone, PartialEq)]
pub enum ContentPart {
    /// A text fragment.
    Text { text: String },
    /// An image. OpenAI clients send `url` (which may be a `data:`
    /// URI); Gemini uses inline base64 `data` + `media_type`. Both
    /// fields are carried so a `data:` URI decomposes for Gemini and
    /// base64 re-composes for OpenAI.
    Image {
        /// The URL form (OpenAI `image_url.url`); may be a `data:` URI.
        url: Option<String>,
        /// MIME type when known (Gemini `inline_data.mime_type`, or the
        /// decoded `data:` URI prefix).
        media_type: Option<String>,
        /// Base64 image bytes when known (Gemini `inline_data.data`, or
        /// the decoded `data:` URI payload).
        data_b64: Option<String>,
    },
}

impl ContentPart {
    /// The text of a Text part; None for images.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            ContentPart::Text { text } => Some(text),
            ContentPart::Image { .. } => None,
        }
    }

    /// An Image part from an OpenAI `image_url.url` value: when the URL
    /// is a `data:<mime>;base64,<payload>` URI it is DECOMPOSED (the
    /// media type and base64 payload fill the fields the Anthropic and
    /// Gemini translations need); a remote URL stays url-only (those
    /// dialects cannot fetch it — see the adapters' docs).
    pub fn image_from_openai_url(url: &str) -> ContentPart {
        if let Some((mime, data)) = split_data_uri(url) {
            ContentPart::Image {
                url: Some(url.to_string()),
                media_type: Some(mime),
                data_b64: Some(data),
            }
        } else {
            ContentPart::Image {
                url: Some(url.to_string()),
                media_type: None,
                data_b64: None,
            }
        }
    }
}

/// Split a `data:<mime>;base64,<payload>` URI into its parts. None for
/// anything else (remote URLs, malformed data URIs).
pub(crate) fn split_data_uri(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("data:")?;
    let (mime, payload) = rest.split_once(',')?;
    let mime = mime.strip_suffix(";base64")?.to_string();
    if mime.is_empty() || payload.is_empty() {
        return None;
    }
    Some((mime, payload.to_string()))
}

/// A tool call issued by the assistant. `arguments` is the JSON-encoded
/// arguments object as a STRING (the OpenAI convention); the Anthropic
/// and Gemini adapters parse/serialize around their native object
/// forms.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

impl ToolCall {
    /// Parse `arguments` as a JSON object; an empty or non-object value
    /// yields an empty map (the OpenAI spec allows the string "null"
    /// fragments mid-stream; non-object arguments are not expressible
    /// in the other dialects anyway).
    pub fn arguments_object(&self) -> BTreeMap<String, Value> {
        self.arguments
            .trim()
            .parse::<Value>()
            .ok()
            .and_then(|v| v.as_object().cloned())
            .map(|map| map.into_iter().collect::<BTreeMap<String, Value>>())
            .unwrap_or_default()
    }
}

/// One chat message in the canonical shape.
#[derive(Debug, Clone, PartialEq)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: Vec<ContentPart>,
    /// Optional participant name (OpenAI `name`).
    pub name: Option<String>,
    /// Tool calls issued by an assistant message.
    pub tool_calls: Vec<ToolCall>,
    /// For Tool-role messages: the call being answered.
    pub tool_call_id: Option<String>,
}

impl ChatMessage {
    /// A plain text message.
    pub fn text(role: ChatRole, text: impl Into<String>) -> Self {
        ChatMessage {
            role,
            content: vec![ContentPart::Text { text: text.into() }],
            name: None,
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }

    /// Concatenated text of all Text parts ("" when the message is
    /// image-only).
    pub fn text_content(&self) -> String {
        self.content
            .iter()
            .filter_map(|p| p.as_text())
            .collect::<Vec<_>>()
            .join("")
    }
}

/// A declared tool (function).
#[derive(Debug, Clone, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    pub description: Option<String>,
    /// The JSON-Schema parameters object (OpenAI `parameters`,
    /// Anthropic `input_schema`, Gemini `parameters`).
    pub parameters: Option<Value>,
}

/// The tool-selection policy.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolChoice {
    /// The model decides (OpenAI `auto`, Anthropic `auto`, Gemini
    /// `AUTO`).
    Auto,
    /// Tools are disabled.
    None,
    /// Some tool MUST be called (OpenAI `required`, Anthropic `any`,
    /// Gemini `ANY`).
    Any,
    /// A specific named tool must be called.
    Tool(String),
}

/// A canonical chat-completions request: what the facade parser
/// produces and every adapter consumes.
#[derive(Debug, Clone, PartialEq)]
pub struct ChatRequest {
    /// The model ALIAS as the client named it. Adapters receive the
    /// mapped `provider_model` separately; this field is only echoed
    /// back to the client.
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub tools: Vec<ToolSpec>,
    pub tool_choice: Option<ToolChoice>,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub max_tokens: Option<u64>,
    pub stop: Option<Vec<String>>,
    /// Whether the client asked for SSE streaming. DW-075 rejects
    /// streaming at the GATEWAY (400) until the zero-buffer pass-through
    /// lands (DW-077); adapters still translate delta shapes so the
    /// streaming pipeline composes later without adapter changes.
    pub stream: bool,
    /// OpenAI `stream_options.include_usage` (streaming only).
    pub stream_options_include_usage: bool,
    /// Dialect-specific parameters the canonical surface does not model
    /// (e.g. `response_format`, `seed`, `presence_penalty`). Carried
    /// verbatim; only the OpenAI adapter re-emits them.
    pub other: BTreeMap<String, Value>,
}

/// Provider-reported token usage (locked decision: provider-reported
/// only — the gateway never estimates).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

impl Usage {
    /// Fold a later usage report into this one (streaming providers
    /// report input tokens in an opening event and output tokens in a
    /// closing one; each side is filled in as it arrives).
    pub fn merge(&mut self, later: Usage) {
        if later.prompt_tokens.is_some() {
            self.prompt_tokens = later.prompt_tokens;
        }
        if later.completion_tokens.is_some() {
            self.completion_tokens = later.completion_tokens;
        }
        if later.total_tokens.is_some() {
            self.total_tokens = later.total_tokens;
        }
    }
}

/// Why generation stopped, normalized across dialects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishReason {
    Stop,
    Length,
    ToolCalls,
    ContentFilter,
    Other(String),
}

/// One completion choice.
#[derive(Debug, Clone, PartialEq)]
pub struct Choice {
    pub index: u64,
    pub message: ChatMessage,
    pub finish_reason: FinishReason,
}

/// A canonical non-streaming response: what every adapter's
/// `parse_response` produces and the facade serializes back to the
/// OpenAI shape.
#[derive(Debug, Clone, PartialEq)]
pub struct ChatResponse {
    /// The provider's response id, when it sends one.
    pub id: Option<String>,
    /// The model identifier the PROVIDER reported (may differ from the
    /// alias; the facade echoes the alias regardless).
    pub model: Option<String>,
    pub choices: Vec<Choice>,
    pub usage: Option<Usage>,
}

/// A tool call being streamed: argument fragments arrive across many
/// deltas and MUST be concatenated in order by the consumer (the
/// OpenAI convention; the Anthropic adapter maps its per-block
/// `input_json_delta` fragments onto this shape).
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCallDelta {
    /// The index of this call within the choice's call list.
    pub index: u64,
    pub id: Option<String>,
    pub name: Option<String>,
    /// An ARGUMENT FRAGMENT, not the whole string.
    pub arguments: String,
}

/// One streaming delta for one choice.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamDelta {
    pub index: u64,
    pub role: Option<ChatRole>,
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCallDelta>,
    pub finish_reason: Option<FinishReason>,
}

/// A canonical streaming event: what an adapter's stream parser
/// produces from one provider SSE data payload.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamEvent {
    /// A content/control delta.
    Delta(StreamDelta),
    /// A provider-reported usage update (mid-stream or terminal).
    Usage(Usage),
    /// The provider signalled completion of the stream.
    Done,
}
