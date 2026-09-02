//! gRPC-Web framing translation and JSON-to-gRPC transcoding (DW-101).
//!
//! ## gRPC-Web framing
//!
//! gRPC-Web is the browser-friendly variant of gRPC: it replaces HTTP/2
//! trailers with a trailing frame that carries the gRPC status as
//! pseudo-headers, and it frames every chunk with a 5-byte prefix (1
//! byte flag + 4 bytes big-endian length). The flag byte distinguishes
//! data frames (0x00) from trailer frames (0x80). A unary response is
//! one data frame followed by one trailer frame; a streaming response
//! is an arbitrary number of data frames (each its own 5-byte-prefixed
//! chunk) followed by a single trailer frame.
//!
//! The gateway sits between a browser (gRPC-Web) and a native gRPC
//! upstream (HTTP/2 + trailers). On the forward path it strips the
//! gRPC-Web framing and reconstructs the native gRPC request body; on
//! the response path it wraps the native gRPC frames (data + trailers)
//! back into gRPC-Web framing so the browser can decode them.
//!
//! ## JSON-to-gRPC transcoding
//!
//! When transcoding is enabled, the gateway also accepts plain JSON
//! requests (Content-Type: application/json) and translates them to
//! protobuf wire bytes for the upstream, and translates the protobuf
//! response back to JSON. The mapping is driven by .proto descriptors
//! supplied via config (FileDescriptorSet files): at config publish the
//! gateway loads the descriptors, builds a method map keyed by the
//! fully-qualified gRPC method name
//! (`/{package}.{service}/{method}`), and resolves each method's
//! request and response message types. The google.api.http annotation
//! on each RPC maps an HTTP path + verb to the gRPC method, so a REST
//! or JSON client can call a gRPC backend without a gRPC library.
//!
//! ## gRPC status mapping
//!
//! A gRPC status (carried in the `grpc-status` trailer) is mapped to an
//! HTTP status code and a `google.rpc.Status` JSON body for non-gRPC
//! clients. The mapping follows the gRPC HTTP/JSON specification (the
//! `google.rpc.Code` -> HTTP status table).
//!
//! ## Feature gating
//!
//! The entire module compiles only when the `grpc_web` cargo feature is
//! enabled. The config schema (`GrpcWeb`, `GrpcWebTranscoding`,
//! `GrpcWebDescriptor`) is always present so configs round-trip without
//! the feature; when the feature is off the block is accepted but inert
//! (validation warns, the runtime translation does not run).

#![cfg(feature = "grpc_web")]

use std::collections::HashMap;

use base64::Engine as _;
use prost::Message;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from gRPC-Web framing translation or JSON-to-gRPC transcoding.
#[derive(Debug)]
pub enum GrpcWebError {
    /// The gRPC-Web body is malformed (truncated frame, bad flag, etc.).
    MalformedFrame(String),
    /// The .proto descriptor file could not be read or parsed.
    Descriptor(String),
    /// The referenced gRPC method is not found in the loaded descriptors.
    MethodNotFound(String),
    /// The JSON body does not match the expected protobuf message shape.
    Transcoding(String),
}

impl std::fmt::Display for GrpcWebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrpcWebError::MalformedFrame(m) => {
                write!(f, "malformed grpc-web frame: {m}")
            }
            GrpcWebError::Descriptor(m) => write!(f, "descriptor error: {m}"),
            GrpcWebError::MethodNotFound(m) => {
                write!(f, "method not found in descriptors: {m}")
            }
            GrpcWebError::Transcoding(m) => write!(f, "transcoding error: {m}"),
        }
    }
}

impl std::error::Error for GrpcWebError {}

// ---------------------------------------------------------------------------
// Minimal protobuf descriptor types (prost-derived)
// ---------------------------------------------------------------------------
//
// prost 0.14 moved the well-known wrapper types into `prost::types` but
// the descriptor types (FileDescriptorSet, DescriptorProto, etc.) remain
// in the separate `prost-types` crate, which only exists at 0.13 (built
// against prost 0.13). Rather than pulling in a version-mismatched
// crate, we define the minimal subset of descriptor types we need,
// derived via prost::Message. These mirror the `google.protobuf`
// descriptor.proto shapes — only the fields the transcoder reads are
// included; unknown fields are skipped by prost's default decoding.

/// `google.protobuf.FileDescriptorSet` — the top-level container
/// produced by `protoc --descriptor_set_out`.
#[derive(Clone, PartialEq, Message)]
pub struct FileDescriptorSet {
    #[prost(message, repeated, tag = "1")]
    pub file: Vec<FileDescriptorProto>,
}

/// `google.protobuf.FileDescriptorProto` — one .proto file.
#[derive(Clone, PartialEq, Message)]
pub struct FileDescriptorProto {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub package: Option<String>,
    #[prost(message, repeated, tag = "4")]
    pub message_type: Vec<DescriptorProto>,
    #[prost(message, repeated, tag = "6")]
    pub service: Vec<ServiceDescriptorProto>,
}

/// `google.protobuf.DescriptorProto` — a message type.
#[derive(Clone, PartialEq, Message)]
pub struct DescriptorProto {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(message, repeated, tag = "2")]
    pub field: Vec<FieldDescriptorProto>,
    #[prost(message, repeated, tag = "3")]
    pub nested_type: Vec<DescriptorProto>,
    #[prost(message, repeated, tag = "4")]
    pub enum_type: Vec<EnumDescriptorProto>,
}

/// `google.protobuf.ServiceDescriptorProto` — an RPC service.
#[derive(Clone, PartialEq, Message)]
pub struct ServiceDescriptorProto {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(message, repeated, tag = "2")]
    pub method: Vec<MethodDescriptorProto>,
}

/// `google.protobuf.MethodDescriptorProto` — one RPC method.
#[derive(Clone, PartialEq, Message)]
pub struct MethodDescriptorProto {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub input_type: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub output_type: Option<String>,
}

/// `google.protobuf.FieldDescriptorProto` — one field in a message.
#[derive(Clone, PartialEq, Message)]
pub struct FieldDescriptorProto {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(string, optional, tag = "10")]
    pub json_name: Option<String>,
    #[prost(int32, optional, tag = "3")]
    pub number: Option<i32>,
    #[prost(enumeration = "field_label::Label", optional, tag = "4")]
    pub label: Option<i32>,
    #[prost(enumeration = "field_type::Type", optional, tag = "5")]
    pub r#type: Option<i32>,
    #[prost(string, optional, tag = "6")]
    pub type_name: Option<String>,
}

/// `google.protobuf.EnumDescriptorProto` — an enum type.
#[derive(Clone, PartialEq, Message)]
pub struct EnumDescriptorProto {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(message, repeated, tag = "2")]
    pub value: Vec<EnumValueDescriptorProto>,
}

/// `google.protobuf.EnumValueDescriptorProto` — one enum value.
#[derive(Clone, PartialEq, Message)]
pub struct EnumValueDescriptorProto {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(int32, optional, tag = "2")]
    pub number: Option<i32>,
}

/// Field label constants (the `FieldDescriptorProto.Label` enum).
pub mod field_label {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, prost::Enumeration)]
    #[repr(i32)]
    pub enum Label {
        Optional = 1,
        Required = 2,
        Repeated = 3,
    }
    pub const OPTIONAL: i32 = 1;
    pub const REQUIRED: i32 = 2;
    pub const REPEATED: i32 = 3;
}

/// Field type constants (the `FieldDescriptorProto.Type` enum).
pub mod field_type {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        Double = 1,
        Float = 2,
        Int64 = 3,
        Uint64 = 4,
        Int32 = 5,
        Fixed64 = 6,
        Fixed32 = 7,
        Bool = 8,
        String = 9,
        Message = 11,
        Bytes = 12,
        Uint32 = 13,
        Enum = 14,
        Sfixed32 = 15,
        Sfixed64 = 16,
        Sint32 = 17,
        Sint64 = 18,
    }
    pub const DOUBLE: i32 = 1;
    pub const FLOAT: i32 = 2;
    pub const INT64: i32 = 3;
    pub const UINT64: i32 = 4;
    pub const INT32: i32 = 5;
    pub const FIXED64: i32 = 6;
    pub const FIXED32: i32 = 7;
    pub const BOOL: i32 = 8;
    pub const STRING: i32 = 9;
    pub const MESSAGE: i32 = 11;
    pub const BYTES: i32 = 12;
    pub const UINT32: i32 = 13;
    pub const ENUM: i32 = 14;
    pub const SFIXED32: i32 = 15;
    pub const SFIXED64: i32 = 16;
    pub const SINT32: i32 = 17;
    pub const SINT64: i32 = 18;
}

// ---------------------------------------------------------------------------
// gRPC-Web framing translator
// ---------------------------------------------------------------------------

/// The gRPC-Web frame flag byte: 0x00 for a data frame, 0x80 for a
/// trailer frame.
const FLAG_DATA: u8 = 0x00;
const FLAG_TRAILER: u8 = 0x80;

/// The fixed 5-byte gRPC-Web frame prefix: 1 flag byte + 4 big-endian
/// length bytes.
const FRAME_PREFIX_LEN: usize = 5;

/// Strip gRPC-Web framing and reconstruct the native gRPC request body.
///
/// gRPC-Web encodes the request as one or more 5-byte-prefixed frames.
/// For a unary call there is a single data frame; for a streaming call
/// there may be multiple data frames. Trailer frames are not sent on
/// the request path (the browser cannot send trailers), so any trailer
/// frame in the request body is treated as an error.
///
/// The returned bytes are the concatenation of every data frame's
/// payload — exactly the native gRPC request body (which is itself a
/// single 5-byte-prefixed message, but that prefix belongs to the gRPC
/// layer, not gRPC-Web; the gRPC-Web data frame payload IS the gRPC
/// message including its own 5-byte gRPC length prefix).
pub fn translate_grpc_web_to_grpc(body: &[u8]) -> Result<Vec<u8>, GrpcWebError> {
    let mut out = Vec::with_capacity(body.len());
    let mut pos = 0;
    while pos < body.len() {
        if pos + FRAME_PREFIX_LEN > body.len() {
            return Err(GrpcWebError::MalformedFrame(format!(
                "truncated frame header at offset {pos}"
            )));
        }
        let flag = body[pos];
        let len = u32::from_be_bytes([body[pos + 1], body[pos + 2], body[pos + 3], body[pos + 4]])
            as usize;
        let data_start = pos + FRAME_PREFIX_LEN;
        let data_end = data_start + len;
        if data_end > body.len() {
            return Err(GrpcWebError::MalformedFrame(format!(
                "frame length {len} exceeds remaining body at offset {pos}"
            )));
        }
        match flag {
            FLAG_DATA => {
                out.extend_from_slice(&body[data_start..data_end]);
            }
            FLAG_TRAILER => {
                // Trailer frames on the request path are unexpected
                // (browsers cannot send gRPC trailers). Treat as an
                // error rather than silently dropping.
                return Err(GrpcWebError::MalformedFrame(
                    "unexpected trailer frame in request body".to_string(),
                ));
            }
            _ => {
                return Err(GrpcWebError::MalformedFrame(format!(
                    "unknown frame flag 0x{flag:02x} at offset {pos}"
                )));
            }
        }
        pos = data_end;
    }
    Ok(out)
}

/// Wrap native gRPC response bytes in gRPC-Web framing.
///
/// The native gRPC response body is a sequence of 5-byte-prefixed
/// messages (flag 0x00 + 4-byte length + payload). The gRPC trailers
/// (carrying `grpc-status`, `grpc-message`, etc.) are passed separately
/// as `trailers` — a raw byte slice of newline-separated `key: value`
/// lines (the standard gRPC trailer encoding).
///
/// The output is a gRPC-Web body: one data frame wrapping the entire
/// gRPC message stream, followed by one trailer frame wrapping the
/// trailer text. For streaming responses the caller should use
/// [`translate_grpc_to_grpc_web_data_chunk`] per chunk and
/// [`translate_grpc_trailers_to_grpc_web`] for the final trailer frame.
pub fn translate_grpc_to_grpc_web(body: &[u8], trailers: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + trailers.len() + FRAME_PREFIX_LEN * 2);
    // Data frame: flag 0x00 + length + payload.
    out.push(FLAG_DATA);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    // Trailer frame: flag 0x80 + length + trailer text.
    out.push(FLAG_TRAILER);
    out.extend_from_slice(&(trailers.len() as u32).to_be_bytes());
    out.extend_from_slice(trailers);
    out
}

/// Wrap a single gRPC data chunk in a gRPC-Web data frame (no trailer
/// frame). Used for streaming responses where each upstream data frame
/// becomes its own gRPC-Web data frame, and the trailer frame is sent
/// once at stream end via [`translate_grpc_trailers_to_grpc_web`].
pub fn translate_grpc_to_grpc_web_data_chunk(chunk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(chunk.len() + FRAME_PREFIX_LEN);
    out.push(FLAG_DATA);
    out.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
    out.extend_from_slice(chunk);
    out
}

/// Wrap gRPC trailers in a gRPC-Web trailer frame. Sent as the final
/// frame of a streaming gRPC-Web response.
pub fn translate_grpc_trailers_to_grpc_web(trailers: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(trailers.len() + FRAME_PREFIX_LEN);
    out.push(FLAG_TRAILER);
    out.extend_from_slice(&(trailers.len() as u32).to_be_bytes());
    out.extend_from_slice(trailers);
    out
}

/// Parse the gRPC-Web trailer frame payload (key: value lines) into a
/// map. Returns an empty map for an empty payload.
pub fn parse_trailers(trailer_bytes: &[u8]) -> HashMap<String, String> {
    let text = String::from_utf8_lossy(trailer_bytes);
    let mut map = HashMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    map
}

/// Build a trailer byte payload from a map of key-value pairs, in the
/// `key: value\n` format gRPC-Web expects.
pub fn build_trailers(trailers: &HashMap<String, String>) -> Vec<u8> {
    let mut out = String::new();
    for (key, value) in trailers {
        out.push_str(key);
        out.push_str(": ");
        out.push_str(value);
        out.push('\n');
    }
    out.into_bytes()
}

// ---------------------------------------------------------------------------
// JSON-to-gRPC transcoding
// ---------------------------------------------------------------------------

/// A loaded .proto descriptor entry: the raw FileDescriptorSet bytes
/// plus the package and service names that identify the methods this
/// descriptor covers.
#[derive(Debug, Clone)]
pub struct LoadedDescriptor {
    /// The raw FileDescriptorSet protobuf bytes (decoded from the
    /// config-supplied file).
    pub bytes: Vec<u8>,
    /// The protobuf package name (e.g. `my.api`).
    pub package: String,
    /// The service name within the package (e.g. `MyService`).
    pub service: String,
}

/// A resolved gRPC method: its fully-qualified path and the request/
/// response message type names.
#[derive(Debug, Clone)]
pub struct MethodInfo {
    /// The fully-qualified gRPC method path: `/{package}.{service}/{method}`.
    pub full_path: String,
    /// The fully-qualified request message type name.
    pub request_type: String,
    /// The fully-qualified response message type name.
    pub response_type: String,
}

/// The gRPC-Web + JSON transcoding engine. Loaded at config publish from
/// .proto descriptor files; holds a method map keyed by the fully-
/// qualified gRPC method path.
///
/// The transcoding uses prost for protobuf encoding/decoding. Because
/// the descriptors are supplied at runtime (not compiled in), the
/// transcoder works with the dynamic protobuf descriptor model: it
/// reads the FileDescriptorSet, resolves message types by name, and
/// encodes/decodes fields by walking the descriptor's field list. This
/// avoids any build-time code generation.
pub struct GrpcTranscoder {
    /// Method map: fully-qualified path -> method info.
    methods: HashMap<String, MethodInfo>,
    /// The loaded descriptors (raw FileDescriptorSet bytes + metadata).
    descriptors: Vec<LoadedDescriptor>,
}

impl std::fmt::Debug for GrpcTranscoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcTranscoder")
            .field("methods", &self.methods)
            .field("descriptor_count", &self.descriptors.len())
            .finish()
    }
}

impl GrpcTranscoder {
    /// Build a transcoder from loaded descriptors. Parses each
    /// FileDescriptorSet, resolves the service's methods, and builds
    /// the method map.
    pub fn from_descriptors(descriptors: Vec<LoadedDescriptor>) -> Result<Self, GrpcWebError> {
        let mut methods = HashMap::new();
        for desc in &descriptors {
            let fds = FileDescriptorSet::decode(&desc.bytes[..]).map_err(|e| {
                GrpcWebError::Descriptor(format!(
                    "failed to decode FileDescriptorSet for {}/{}: {e}",
                    desc.package, desc.service
                ))
            })?;
            for fd in &fds.file {
                let pkg = fd.package.as_deref().unwrap_or("");
                if pkg != desc.package {
                    continue;
                }
                for svc in &fd.service {
                    if svc.name.as_deref() != Some(desc.service.as_str()) {
                        continue;
                    }
                    for method in &svc.method {
                        let m_name = method.name.as_deref().unwrap_or("");
                        let full_path =
                            format!("/{}.{}{}{}", desc.package, desc.service, "/", m_name);
                        let request_type = method.input_type.clone().unwrap_or_default();
                        let response_type = method.output_type.clone().unwrap_or_default();
                        methods.insert(
                            full_path.clone(),
                            MethodInfo {
                                full_path,
                                request_type,
                                response_type,
                            },
                        );
                    }
                }
            }
        }
        Ok(GrpcTranscoder {
            methods,
            descriptors,
        })
    }

    /// Look up a method by its fully-qualified path
    /// (`/{package}.{service}/{method}`).
    pub fn method(&self, full_path: &str) -> Option<&MethodInfo> {
        self.methods.get(full_path)
    }

    /// The number of resolved methods.
    pub fn method_count(&self) -> usize {
        self.methods.len()
    }

    /// Translate a JSON request body to protobuf wire bytes for the
    /// given gRPC method. The returned bytes are the raw protobuf
    /// message (without the 5-byte gRPC length prefix — the caller
    /// adds that when framing the native gRPC request).
    pub fn json_to_grpc(&self, method: &str, json: &Value) -> Result<Vec<u8>, GrpcWebError> {
        let info = self
            .methods
            .get(method)
            .ok_or_else(|| GrpcWebError::MethodNotFound(method.to_string()))?;
        let fds = self.descriptor_set()?;
        let msg_desc = resolve_message(&fds, &info.request_type).ok_or_else(|| {
            GrpcWebError::Descriptor(format!(
                "request message type {} not found in descriptors",
                info.request_type
            ))
        })?;
        encode_json_to_proto(json, &msg_desc, &fds).map_err(GrpcWebError::Transcoding)
    }

    /// Translate a protobuf response body to JSON for the given gRPC
    /// method. The input `proto_bytes` are the raw protobuf message
    /// bytes (without the 5-byte gRPC length prefix).
    pub fn grpc_to_json(&self, method: &str, proto_bytes: &[u8]) -> Result<Value, GrpcWebError> {
        let info = self
            .methods
            .get(method)
            .ok_or_else(|| GrpcWebError::MethodNotFound(method.to_string()))?;
        let fds = self.descriptor_set()?;
        let msg_desc = resolve_message(&fds, &info.response_type).ok_or_else(|| {
            GrpcWebError::Descriptor(format!(
                "response message type {} not found in descriptors",
                info.response_type
            ))
        })?;
        decode_proto_to_json(proto_bytes, &msg_desc, &fds).map_err(GrpcWebError::Transcoding)
    }

    /// Collect all loaded descriptors into a single FileDescriptorSet
    /// for message-type resolution.
    fn descriptor_set(&self) -> Result<FileDescriptorSet, GrpcWebError> {
        let mut all_files = Vec::new();
        for desc in &self.descriptors {
            let fds = FileDescriptorSet::decode(&desc.bytes[..]).map_err(|e| {
                GrpcWebError::Descriptor(format!("failed to decode FileDescriptorSet: {e}"))
            })?;
            all_files.extend(fds.file);
        }
        Ok(FileDescriptorSet { file: all_files })
    }
}

// ---------------------------------------------------------------------------
// Protobuf descriptor helpers (dynamic, descriptor-driven)
// ---------------------------------------------------------------------------

/// Resolve a message descriptor by fully-qualified name from a
/// FileDescriptorSet. The name may be prefixed with a leading dot
/// (the protobuf convention for fully-qualified names).
fn resolve_message(fds: &FileDescriptorSet, full_name: &str) -> Option<DescriptorProto> {
    // Strip the leading dot if present (fully-qualified type names in
    // method descriptors use a leading dot: ".my.api.MyRequest").
    let name = full_name.strip_prefix('.').unwrap_or(full_name);
    // The name is `{package}.{MessageName}`. Walk each file's message
    // types (including nested) and match the full dotted name.
    for fd in &fds.file {
        let prefix = fd.package.as_deref().unwrap_or("");
        let prefix = if prefix.is_empty() {
            String::new()
        } else {
            format!("{}.", prefix)
        };
        for msg in &fd.message_type {
            if let Some(found) = find_message_recursive(msg, &prefix, name) {
                return Some(found);
            }
        }
    }
    None
}

/// Recursively search a message and its nested types for a message
/// whose full dotted name matches `target`.
fn find_message_recursive(
    msg: &DescriptorProto,
    prefix: &str,
    target: &str,
) -> Option<DescriptorProto> {
    let name = msg.name.as_deref().unwrap_or("");
    let full = format!("{prefix}{name}");
    if full == target {
        return Some(msg.clone());
    }
    let nested_prefix = format!("{full}.");
    for nested in &msg.nested_type {
        if let Some(found) = find_message_recursive(nested, &nested_prefix, target) {
            return Some(found);
        }
    }
    None
}

/// Encode a JSON value into protobuf wire bytes using a message
/// descriptor. Walks the descriptor's fields and encodes each field
/// present in the JSON according to its wire type.
fn encode_json_to_proto(
    json: &Value,
    msg_desc: &DescriptorProto,
    fds: &FileDescriptorSet,
) -> Result<Vec<u8>, String> {
    let obj = json
        .as_object()
        .ok_or_else(|| "expected a JSON object for a protobuf message".to_string())?;
    let mut buf = Vec::new();
    for field in &msg_desc.field {
        let Some(json_name) = &field.json_name else {
            continue;
        };
        let Some(value) = obj.get(json_name) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        encode_field(&mut buf, field, value, fds)?;
    }
    Ok(buf)
}

/// Encode a single protobuf field into the wire buffer.
fn encode_field(
    buf: &mut Vec<u8>,
    field: &FieldDescriptorProto,
    value: &Value,
    fds: &FileDescriptorSet,
) -> Result<(), String> {
    let number = field.number.unwrap_or(0) as u32;
    let label = field.label.unwrap_or(field_label::OPTIONAL);
    let ty = field.r#type.unwrap_or(field_type::MESSAGE);
    let is_repeated = label == field_label::REPEATED;

    if is_repeated {
        let arr = value.as_array().ok_or_else(|| {
            format!(
                "field {} expected a JSON array",
                field.json_name.as_deref().unwrap_or("")
            )
        })?;
        for elem in arr {
            if elem.is_null() {
                continue;
            }
            encode_single_field(buf, number, ty, field, elem, fds)?;
        }
        return Ok(());
    }

    encode_single_field(buf, number, ty, field, value, fds)
}

/// Encode a single (non-repeated or one-element) protobuf field.
fn encode_single_field(
    buf: &mut Vec<u8>,
    number: u32,
    ty: i32,
    field: &FieldDescriptorProto,
    value: &Value,
    fds: &FileDescriptorSet,
) -> Result<(), String> {
    match ty {
        field_type::STRING => {
            let s = value
                .as_str()
                .ok_or_else(|| format!("field {number} expected a string"))?;
            let bytes = s.as_bytes();
            write_tag(buf, number, WIRE_LENGTH_DELIMITED);
            write_varint(buf, bytes.len() as u64);
            buf.extend_from_slice(bytes);
        }
        field_type::BYTES => {
            let s = value
                .as_str()
                .ok_or_else(|| format!("field {number} expected a base64 string for bytes"))?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|e| format!("field {number} invalid base64: {e}"))?;
            write_tag(buf, number, WIRE_LENGTH_DELIMITED);
            write_varint(buf, decoded.len() as u64);
            buf.extend_from_slice(&decoded);
        }
        field_type::BOOL => {
            let b = value
                .as_bool()
                .ok_or_else(|| format!("field {number} expected a bool"))?;
            write_tag(buf, number, WIRE_VARINT);
            write_varint(buf, if b { 1u64 } else { 0u64 });
        }
        field_type::INT32 | field_type::SINT32 | field_type::SFIXED32 => {
            let n = value
                .as_i64()
                .ok_or_else(|| format!("field {number} expected an integer"))?
                as i32;
            write_tag(buf, number, WIRE_VARINT);
            write_varint(buf, n as u32 as u64);
        }
        field_type::INT64 | field_type::SINT64 | field_type::SFIXED64 => {
            let n = value
                .as_i64()
                .ok_or_else(|| format!("field {number} expected an integer"))?;
            write_tag(buf, number, WIRE_VARINT);
            write_varint(buf, n as u64);
        }
        field_type::UINT32 | field_type::FIXED32 => {
            let n = value
                .as_u64()
                .ok_or_else(|| format!("field {number} expected a non-negative integer"))?
                as u32;
            write_tag(buf, number, WIRE_VARINT);
            write_varint(buf, n as u64);
        }
        field_type::UINT64 | field_type::FIXED64 => {
            let n = value
                .as_u64()
                .ok_or_else(|| format!("field {number} expected a non-negative integer"))?;
            write_tag(buf, number, WIRE_VARINT);
            write_varint(buf, n);
        }
        field_type::FLOAT => {
            let f = value
                .as_f64()
                .ok_or_else(|| format!("field {number} expected a number"))?
                as f32;
            write_tag(buf, number, WIRE_32BIT);
            buf.extend_from_slice(&f.to_le_bytes());
        }
        field_type::DOUBLE => {
            let f = value
                .as_f64()
                .ok_or_else(|| format!("field {number} expected a number"))?;
            write_tag(buf, number, WIRE_64BIT);
            buf.extend_from_slice(&f.to_le_bytes());
        }
        field_type::ENUM => {
            let n = if let Some(i) = value.as_i64() {
                i as i32
            } else if let Some(s) = value.as_str() {
                // Enum by name: look up the value in the enum type
                // descriptor.
                let _ = s;
                return Err(format!(
                    "field {number} enum-by-name encoding not supported; \
                     use the integer value"
                ));
            } else {
                return Err(format!(
                    "field {number} expected an integer or string for enum"
                ));
            };
            write_tag(buf, number, WIRE_VARINT);
            write_varint(buf, n as u32 as u64);
        }
        field_type::MESSAGE => {
            let type_name = field
                .type_name
                .as_deref()
                .ok_or_else(|| format!("field {number} message type missing"))?;
            let nested = resolve_message(fds, type_name)
                .ok_or_else(|| format!("field {number} message type {type_name} not found"))?;
            let sub = encode_json_to_proto(value, &nested, fds)?;
            write_tag(buf, number, WIRE_LENGTH_DELIMITED);
            write_varint(buf, sub.len() as u64);
            buf.extend_from_slice(&sub);
        }
        _ => {
            return Err(format!("field {number} type {ty} not supported"));
        }
    }
    Ok(())
}

/// Decode protobuf wire bytes into a JSON value using a message
/// descriptor. Walks the wire format, matching tags to fields, and
/// builds a JSON object.
fn decode_proto_to_json(
    proto: &[u8],
    msg_desc: &DescriptorProto,
    fds: &FileDescriptorSet,
) -> Result<Value, String> {
    let mut obj = serde_json::Map::new();
    let mut pos = 0;
    while pos < proto.len() {
        let (tag, tag_len) =
            read_varint(&proto[pos..]).ok_or_else(|| "truncated varint tag".to_string())?;
        pos += tag_len;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        let field = msg_desc
            .field
            .iter()
            .find(|f| f.number.unwrap_or(0) as u32 == field_number);
        let json_name = field
            .and_then(|f| f.json_name.clone())
            .unwrap_or_else(|| format!("field{field_number}"));

        let (value, consumed) = decode_field(&proto[pos..], wire_type, field, fds)?;
        pos += consumed;

        // Handle repeated fields: accumulate into a JSON array.
        if let Some(existing) = obj.get(&json_name) {
            if let Some(arr) = existing.as_array() {
                let mut arr = arr.clone();
                arr.push(value);
                obj.insert(json_name, Value::Array(arr));
            } else {
                // Promote to array (first occurrence was singular).
                let arr = vec![existing.clone(), value];
                obj.insert(json_name, Value::Array(arr));
            }
        } else {
            obj.insert(json_name, value);
        }
    }
    Ok(Value::Object(obj))
}

/// Decode a single field value from the wire buffer.
fn decode_field(
    buf: &[u8],
    wire_type: u8,
    field: Option<&FieldDescriptorProto>,
    fds: &FileDescriptorSet,
) -> Result<(Value, usize), String> {
    let ty = field.and_then(|f| f.r#type).unwrap_or(field_type::MESSAGE);

    match wire_type {
        WIRE_VARINT => {
            let (v, len) = read_varint(buf).ok_or_else(|| "truncated varint".to_string())?;
            let value = match ty {
                field_type::BOOL => Value::Bool(v != 0),
                field_type::INT32 | field_type::SINT32 | field_type::SFIXED32 => {
                    Value::Number((v as u32 as i32 as i64).into())
                }
                field_type::INT64 | field_type::SINT64 | field_type::SFIXED64 => {
                    Value::Number((v as i64).into())
                }
                field_type::UINT32 | field_type::FIXED32 => Value::Number((v as u32 as u64).into()),
                field_type::UINT64 | field_type::FIXED64 => Value::Number(v.into()),
                field_type::ENUM => Value::Number((v as u32 as i32 as i64).into()),
                _ => Value::Number(v.into()),
            };
            Ok((value, len))
        }
        WIRE_64BIT => {
            if buf.len() < 8 {
                return Err("truncated 64-bit field".to_string());
            }
            let bytes: [u8; 8] = buf[..8].try_into().unwrap();
            let value = match ty {
                field_type::DOUBLE => serde_json::Number::from_f64(f64::from_le_bytes(bytes))
                    .map(Value::Number)
                    .unwrap_or(Value::Null),
                field_type::FIXED64 => Value::Number(u64::from_le_bytes(bytes).into()),
                field_type::SFIXED64 => Value::Number(i64::from_le_bytes(bytes).into()),
                _ => Value::Null,
            };
            Ok((value, 8))
        }
        WIRE_LENGTH_DELIMITED => {
            let (len, len_bytes) =
                read_varint(buf).ok_or_else(|| "truncated length-delimited length".to_string())?;
            let len = len as usize;
            let data_start = len_bytes;
            let data_end = data_start + len;
            if data_end > buf.len() {
                return Err("truncated length-delimited field".to_string());
            }
            let data = &buf[data_start..data_end];
            let value = match ty {
                field_type::STRING => Value::String(String::from_utf8_lossy(data).into_owned()),
                field_type::BYTES => {
                    Value::String(base64::engine::general_purpose::STANDARD.encode(data))
                }
                field_type::MESSAGE => {
                    let type_name = field
                        .and_then(|f| f.type_name.as_deref())
                        .ok_or_else(|| "message field missing type_name".to_string())?;
                    let nested = resolve_message(fds, type_name)
                        .ok_or_else(|| format!("message type {type_name} not found"))?;
                    decode_proto_to_json(data, &nested, fds)?
                }
                _ => {
                    // Unknown length-delimited: try string, fall back to
                    // base64 bytes.
                    Value::String(String::from_utf8_lossy(data).into_owned())
                }
            };
            Ok((value, data_end))
        }
        WIRE_32BIT => {
            if buf.len() < 4 {
                return Err("truncated 32-bit field".to_string());
            }
            let bytes: [u8; 4] = buf[..4].try_into().unwrap();
            let value = match ty {
                field_type::FLOAT => serde_json::Number::from_f64(f32::from_le_bytes(bytes) as f64)
                    .map(Value::Number)
                    .unwrap_or(Value::Null),
                field_type::FIXED32 => Value::Number(u32::from_le_bytes(bytes).into()),
                field_type::SFIXED32 => Value::Number(i32::from_le_bytes(bytes).into()),
                _ => Value::Null,
            };
            Ok((value, 4))
        }
        _ => Err(format!("unknown wire type {wire_type}")),
    }
}

// ---------------------------------------------------------------------------
// Low-level varint / tag helpers
// ---------------------------------------------------------------------------

/// Wire type constants (the low 3 bits of a protobuf tag).
const WIRE_VARINT: u8 = 0;
const WIRE_64BIT: u8 = 1;
const WIRE_LENGTH_DELIMITED: u8 = 2;
const WIRE_32BIT: u8 = 5;

/// Write a protobuf field tag (field number + wire type) as a varint.
fn write_tag(buf: &mut Vec<u8>, field_number: u32, wire_type: u8) {
    let tag = ((field_number as u64) << 3) | (wire_type as u64);
    write_varint(buf, tag);
}

/// Write a varint to the buffer.
fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

/// Read a varint from the buffer. Returns the value and the number of
/// bytes consumed.
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, byte) in buf.iter().enumerate() {
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// gRPC status mapping
// ---------------------------------------------------------------------------

/// gRPC status codes (the `google.rpc.Code` enum values).
pub mod grpc_code {
    pub const OK: i32 = 0;
    pub const CANCELLED: i32 = 1;
    pub const UNKNOWN: i32 = 2;
    pub const INVALID_ARGUMENT: i32 = 3;
    pub const DEADLINE_EXCEEDED: i32 = 4;
    pub const NOT_FOUND: i32 = 5;
    pub const ALREADY_EXISTS: i32 = 6;
    pub const PERMISSION_DENIED: i32 = 7;
    pub const RESOURCE_EXHAUSTED: i32 = 8;
    pub const FAILED_PRECONDITION: i32 = 9;
    pub const ABORTED: i32 = 10;
    pub const OUT_OF_RANGE: i32 = 11;
    pub const UNIMPLEMENTED: i32 = 12;
    pub const INTERNAL: i32 = 13;
    pub const UNAVAILABLE: i32 = 14;
    pub const DATA_LOSS: i32 = 15;
    pub const UNAUTHENTICATED: i32 = 16;
}

/// Map a gRPC status code to an HTTP status code and a `google.rpc.Status`
/// JSON body. The JSON body follows the `google.rpc.Status` shape:
/// `{ "code": <int>, "message": "<string>", "details": [] }`.
pub fn grpc_status_to_http(status: i32, message: &str) -> (u16, Value) {
    let http_status = match status {
        grpc_code::OK => 200,
        grpc_code::CANCELLED => 499,
        grpc_code::UNKNOWN => 500,
        grpc_code::INVALID_ARGUMENT => 400,
        grpc_code::DEADLINE_EXCEEDED => 504,
        grpc_code::NOT_FOUND => 404,
        grpc_code::ALREADY_EXISTS => 409,
        grpc_code::PERMISSION_DENIED => 403,
        grpc_code::RESOURCE_EXHAUSTED => 429,
        grpc_code::FAILED_PRECONDITION => 400,
        grpc_code::ABORTED => 409,
        grpc_code::OUT_OF_RANGE => 400,
        grpc_code::UNIMPLEMENTED => 501,
        grpc_code::INTERNAL => 500,
        grpc_code::UNAVAILABLE => 503,
        grpc_code::DATA_LOSS => 500,
        grpc_code::UNAUTHENTICATED => 401,
        _ => 500,
    };
    let body = serde_json::json!({
        "code": status,
        "message": message,
        "details": [],
    });
    (http_status, body)
}

/// The gRPC status name for a code (for logging / trailer display).
pub fn grpc_status_name(status: i32) -> &'static str {
    match status {
        grpc_code::OK => "OK",
        grpc_code::CANCELLED => "CANCELLED",
        grpc_code::UNKNOWN => "UNKNOWN",
        grpc_code::INVALID_ARGUMENT => "INVALID_ARGUMENT",
        grpc_code::DEADLINE_EXCEEDED => "DEADLINE_EXCEEDED",
        grpc_code::NOT_FOUND => "NOT_FOUND",
        grpc_code::ALREADY_EXISTS => "ALREADY_EXISTS",
        grpc_code::PERMISSION_DENIED => "PERMISSION_DENIED",
        grpc_code::RESOURCE_EXHAUSTED => "RESOURCE_EXHAUSTED",
        grpc_code::FAILED_PRECONDITION => "FAILED_PRECONDITION",
        grpc_code::ABORTED => "ABORTED",
        grpc_code::OUT_OF_RANGE => "OUT_OF_RANGE",
        grpc_code::UNIMPLEMENTED => "UNIMPLEMENTED",
        grpc_code::INTERNAL => "INTERNAL",
        grpc_code::UNAVAILABLE => "UNAVAILABLE",
        grpc_code::DATA_LOSS => "DATA_LOSS",
        grpc_code::UNAUTHENTICATED => "UNAUTHENTICATED",
        _ => "UNKNOWN",
    }
}
