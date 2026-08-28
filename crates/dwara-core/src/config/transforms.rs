//! Request/response transformation grammar (DW-028): the config shapes
//! for header/query manipulation and JSON-pointer body transforms, the
//! shared JSON-Pointer grammar validation and the runtime agree on, and
//! the security-header injection policy (feature analysis 4.12 and the
//! 5-Security "security header injection" row).
//!
//! This is config-contract grammar in the same sense as `net.rs` (the
//! IP/CIDR vocabulary) and `versioning.rs` (the HTTP-date and media-type
//! vocabularies): validation (`snapshot::validate`) and the runtime
//! (`dataplane::transforms`) must agree on ONE parsing of these strings,
//! so the grammar lives in `config`, the lowest consuming domain.
//!
//! ## The streaming contract (the issue's done-when)
//!
//! "Streaming is preserved unless a transform explicitly buffers." The
//! surface splits exactly along that line:
//!
//! - Header and query ops, and security headers, never touch a body:
//!   streaming responses (SSE, upgrades, chunked downloads) pass with
//!   zero buffering, exactly as before.
//! - A JSON body transform is the one EXPLICITLY BUFFERING transform:
//!   it opts the route in, applies only to JSON bodies (content-type
//!   gated), and buffers at most `max_bytes` — a hard cap enforced both
//!   against a declared `Content-Length` and against the live stream.
//!   Over-cap bodies fail CLOSED (413 request-side, 502 response-side),
//!   never "transform what fit" and never silently pass through: a
//!   skipped policy transform is a fail-open data leak in the masking
//!   direction (DW-029 builds on this machinery).
//!
//! ## Pointer semantics (why strict)
//!
//! A `set`/`remove` whose JSON Pointer does not resolve at runtime is an
//! ERROR, not a skip. Pointer misses are schema drift, and in the
//! redaction direction (remove the secret field) a silent miss is
//! exactly the leak the policy exists to prevent. Strictness costs
//! operators a 400/502 on drifted contracts; leniency would cost them
//! their data. The error names the offending pointer server-side only
//! (the client envelope carries a generic message).
//!
//! ## Security headers vs the decoration tail
//!
//! Security headers are an EDGE property of every response the route
//! emits — action responses and gateway short-circuits alike (a 401
//! without `X-Content-Type-Options: nosniff` is a real, if minor, gap;
//! contrast deprecation stamps, which announce API lifecycle and are
//! deliberately absent from short-circuits). They REPLACE any
//! upstream-sent values: the gateway is the source of truth for its
//! edge policy, the same rule as the deprecation and `X-RateLimit-*`
//! headers. They apply last in the response decoration tail, after
//! operator transforms: an operator who needs per-route-exception
//! behavior omits the field here and sets it via transforms.
//!
//! ## Response field masking (DW-029) — the security sharp edge
//!
//! [`Masking`] redacts JSON fields on the way OUT, per consumer group
//! (the mass-assignment/data-leak guard). It reuses the buffering and
//! pointer machinery above with ONE posture change: every gate that the
//! DW-028 body transform treats as pass-through (an already-encoded
//! body, a non-JSON content type) is, for masking, a REJECTION — the
//! gateway cannot prove fields absent from bytes it cannot parse, and a
//! skipped masking policy is exactly the leak the policy exists to
//! prevent. Over-cap, invalid JSON, and unresolved pointers fail the
//! same way (502), the strictness the pointer rules above already
//! argue for. Masking runs FIRST in the response decoration tail —
//! before the DW-028 body transform and before compression (DW-027) —
//! so no later stage can resurrect a redacted value: once the sentinel
//! replaces the secret, the original bytes exist nowhere in the
//! gateway.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Config shapes
// ---------------------------------------------------------------------------

/// Route-scoped request and response transforms (DW-028, feature
/// analysis 4.12). Absent (the default): the gateway forwards bytes and
/// headers untouched. Presence opts the route's traffic into the
/// declared manipulations — nothing here applies to any other route.
///
/// Semantics (frozen; enforcement lives in `dataplane::transforms`):
///
/// - REQUEST transforms run on the forward path only, after route
///   matching, the trusted-header injection (`X-Forwarded-*`,
///   `X-Consumer-*`), and the DW-010 path rewrite: they shape the
///   request the upstream receives. Route matching, limits, authn, and
///   rate limiting all evaluated the ORIGINAL request; reordering that
///   is a policy change this block cannot make.
/// - RESPONSE transforms run in the decoration tail, before compression
///   (so a body transform rewrites the bytes compression then encodes,
///   and a header transform's final `Content-Type` is what the
///   compression eligibility check sees).
/// - The one deliberately sharp edge: request header ops may remove or
///   rename the gateway-injected trust headers (`X-Consumer-*`,
///   `X-Forwarded-*`). The operator owns the upstream's contract; if
///   their upstream must not see consumer identity, removing it here is
///   the mechanism. Framing and hop-by-hop headers are NOT theirs to
///   touch (validation rejects those names).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Transforms {
    /// Manipulations applied to the forwarded request (headers, query,
    /// body).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestTransforms>,
    /// Manipulations applied to the route's action responses (headers,
    /// body).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseTransforms>,
}

/// Request-side transforms (DW-028).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestTransforms {
    /// Header manipulation on the forwarded request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HeaderOps>,
    /// Query-string manipulation on the forwarded request (the path is
    /// DW-010's `path_rewrite`; this block never touches it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<QueryOps>,
    /// Body transform (JSON) on the forwarded request — the explicitly
    /// buffering transform, size-capped. See [`BodyTransform`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<BodyTransform>,
}

/// Response-side transforms (DW-028), applied to the route's action
/// responses (proxy, redirect, respond) — not to gateway
/// short-circuits (limits, authn/authz, rate limits, maintenance,
/// sheds), which describe the request, not the upstream's output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseTransforms {
    /// Header manipulation on the route's responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HeaderOps>,
    /// Body transform (JSON) on the route's responses — the explicitly
    /// buffering transform, size-capped. See [`BodyTransform`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<BodyTransform>,
}

/// Header manipulation ops (DW-028). Applied in ONE deterministic
/// order regardless of YAML key order: `set` (replace all values of the
/// name with one value), then `add` (append one value, keeping any
/// existing values), then `rename` (move every value of `from` to
/// `to`), then `remove` (drop every value of the name) — so `remove`
/// can clean up what earlier ops placed, and `rename` sees both
/// upstream and just-set values. Maps iterate in sorted key order
/// (BTreeMap), making multi-entry application deterministic.
///
/// The block runs after hop-by-hop stripping on the request side and
/// before the gateway's own policy stamps on the response side;
/// framing and hop-by-hop header names are rejected by validation in
/// BOTH directions (see `dataplane::transforms` module docs for the
/// rationale).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeaderOps {
    /// Replace every value of the header name with this single value
    /// (an absent name is inserted).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set: BTreeMap<String, String>,
    /// Append one value to the header name, keeping any existing
    /// values (the way to build multi-value headers deterministically).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub add: BTreeMap<String, String>,
    /// Drop every value of these header names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
    /// Relabel every value of `from` onto `to` (existing `to` values
    /// are kept; the renamed values append after them). One entry per
    /// source name; a `from == to` entry is rejected by validation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rename: BTreeMap<String, String>,
}

/// Query-string manipulation ops (DW-028), applied to the forwarded
/// request's query. The original query is split into pairs WITHOUT
/// decoding (each pair's key and value stay byte-verbatim, so untouched
/// parameters — including their exact percent-encoding — survive); only
/// pairs a named op touches are re-encoded (new values are
/// percent-encoded by the gateway). Ops apply in the same deterministic
/// order as header ops: `set`, `add`, `rename`, `remove`.
///
/// `set` replaces EVERY pair of the key with one pair at the END of
/// the query (position cannot be preserved for a replaced key);
/// `rename` keeps position, re-labeling each matching pair in place;
/// `add` appends at the end; `remove` drops every matching pair.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryOps {
    /// Replace every pair of the key with this single pair (appended at
    /// the end of the result).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set: BTreeMap<String, String>,
    /// Append one pair at the end of the query.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub add: BTreeMap<String, String>,
    /// Drop every pair of these keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
    /// Re-label every pair of `from` with the new key, value verbatim,
    /// position preserved.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rename: BTreeMap<String, String>,
}

/// A body transform (DW-028). The `json` variant is the whole of v1:
/// any other body transform family (templating, XML) would be a new
/// variant here — the wrapper exists so adding one does not reshape
/// the config surface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BodyTransform {
    /// JSON-pointer operations on JSON bodies, size-capped. See
    /// [`JsonBodyTransform`].
    pub json: JsonBodyTransform,
}

/// JSON-pointer body transform (DW-028): RFC 6901 pointers against a
/// parsed JSON document, applied in listed order (each op sees the
/// previous op's result). THIS IS THE EXPLICITLY BUFFERING TRANSFORM —
/// the only place in the transforms surface that reads a body. Hard
/// rules, enforced by `dataplane::transforms`:
///
/// - Size cap: `max_bytes` bounds the buffered body both against a
///   declared `Content-Length` (rejected up front) and against the
///   live stream (aborted at the frame that crosses). Over-cap fails
///   CLOSED: 413 on the request side, 502 on the response side.
/// - Content-type gate: the transform applies only when the body's
///   media type is JSON (`application/json` or any
///   `application/<*+json>`), parameters ignored. Non-JSON and empty
///   bodies pass through untouched (streaming preserved; an empty body
///   has nothing to transform). A body already carrying
///   `Content-Encoding` passes through untouched: the transform does
///   not decode (the documented pass-through of the compression
///   policy, mirrored here).
/// - A JSON-typed body that fails to PARSE is a client/upstream
///   error, not a skip: 400 request-side, 502 response-side.
/// - A pointer that does not RESOLVE fails the transform (see the
///   module docs for why strictness is the safe default).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonBodyTransform {
    /// Maximum body size (bytes) this route will buffer to transform.
    /// Must be >= 1 (validation); there is deliberately no upper
    /// bound — the operator owns this route's memory budget, the same
    /// stance as `limits.max_body_bytes`.
    pub max_bytes: u64,
    /// Pointer operations, applied in order.
    pub ops: Vec<JsonOp>,
}

/// One JSON-pointer operation (DW-028). `set` writes any JSON value at
/// the pointer (creating the final key in an object parent that must
/// already exist; replacing an existing element in an array parent);
/// `remove` deletes the addressed value. The ROOT pointer (`""`) is
/// valid for `set` (whole-document replacement) and rejected for
/// `remove` by validation (a body with no document is not a state this
/// transform can produce).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum JsonOp {
    /// Write `value` at `path` (RFC 6901 pointer).
    Set {
        /// RFC 6901 JSON pointer (e.g. `/meta/via`, `/items/0/id`, ``
        /// for the whole document).
        path: String,
        /// Any JSON value to place at the pointer.
        value: serde_json::Value,
    },
    /// Delete the value at `path` (RFC 6901 pointer, not the root).
    Remove {
        /// RFC 6901 JSON pointer; the root (`""`) is rejected by
        /// validation.
        path: String,
    },
}

/// Security-header injection policy (DW-028, feature analysis
/// 5-Security "security header injection"). Each field that is present
/// injects (REPLACING any upstream-sent value — the gateway is the
/// source of truth at its edge) exactly one standard hardening header
/// on every response the route emits, including gateway
/// short-circuits (401/403/413/429/503, CORS preflights): unlike
/// deprecation stamps, these harden every byte the edge sends, and a
/// browser parsing an error page deserves the same guarantees as one
/// parsing a 200.
///
/// Not on responses with no route to consult: the framing 400 (the
/// pre-parse sniff rejects the request before any route exists) and
/// unrouted 404s.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityHeaders {
    /// Emit `Strict-Transport-Security: max-age=<secs>` (RFC 6797) on
    /// every response of the route. The presence of this field is the
    /// policy; 0 is rejected (max-age=0 is the spec's deletion signal,
    /// a state this policy cannot express — delete the field instead).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hsts_max_age_secs: Option<u64>,
    /// Append the `includeSubDomains` directive to the HSTS header
    /// (meaningful only with `hsts_max_age_secs`; rejected alone by
    /// validation).
    #[serde(default, skip_serializing_if = "is_false")]
    pub hsts_include_subdomains: bool,
    /// Append the `preload` directive to the HSTS header (the HSTS
    /// preload-list signal; meaningful only with `hsts_max_age_secs`
    /// and, per the preload list requirements, with
    /// `hsts_include_subdomains`; that combination is enforced by
    /// validation).
    #[serde(default, skip_serializing_if = "is_false")]
    pub hsts_preload: bool,
    /// Emit `X-Content-Type-Options: nosniff` (the MIME-sniffing
    /// off-switch; the only value the header has).
    #[serde(default, skip_serializing_if = "is_false")]
    pub nosniff: bool,
    /// Emit `Content-Security-Policy: <policy>` verbatim (the operator
    /// authors the policy; non-empty and header-representable,
    /// validation — a trailing newline or other control byte is
    /// rejected rather than silently not emitted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_security_policy: Option<String>,
    /// Emit `X-Frame-Options` (legacy but still load-bearing for older
    /// browsers). `ALLOW-FROM` is obsolete and deliberately absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_options: Option<FrameOptions>,
}

/// The `X-Frame-Options` value (DW-028).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FrameOptions {
    /// `DENY`: no framing at all.
    Deny,
    /// `SAMEORIGIN`: same-origin frames only.
    Sameorigin,
}

impl FrameOptions {
    /// The header value this option emits.
    pub fn header_value(self) -> &'static str {
        match self {
            FrameOptions::Deny => "DENY",
            FrameOptions::Sameorigin => "SAMEORIGIN",
        }
    }
}

/// Response field masking policy (DW-029, feature analysis 5-Security
/// "response field masking"): RFC 6901 pointers whose values are
/// replaced with the fixed [`MASKED_VALUE`] sentinel on the route's
/// responses, before any other body-handling stage. The
/// mass-assignment/data-leak guard: a field named here NEVER reaches
/// the client, whatever the upstream put in it.
///
/// Semantics (frozen; enforcement lives in `dataplane::transforms`):
///
/// - PRECEDENCE is the deny-anywhere-wins analog for a redaction
///   policy: the effective pointer set is the UNION of `fields` (the
///   floor, every consumer on the route) and every `groups` entry the
///   authenticated consumer belongs to. A group entry can only ADD
///   pointers — there is deliberately no mechanism by which a group is
///   EXEMPTED from the route floor (that would be a allow-anywhere
///   escape hatch on a security policy).
/// - The redacted value is the FIXED string [`MASKED_VALUE`], not
///   configurable: one sentinel everywhere, so clients and audit
///   tooling can rely on the exact shape.
/// - Masking is explicitly buffering under `max_bytes` and FAILS
///   CLOSED: a response that is content-encoded, not JSON, over the
///   cap, unparseable, or misses a configured pointer answers 502 —
///   never a passthrough of bytes the gateway could not prove clean
///   (see the module docs; the inverse of the DW-028 transform gates).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Masking {
    /// Maximum response body size (bytes) this route will buffer to
    /// mask. Must be >= 1 (validation); no upper bound, the same
    /// operator-owns-the-memory-budget stance as the DW-028 transform
    /// cap.
    pub max_bytes: u64,
    /// Pointers masked for EVERY consumer on this route (the floor).
    /// Each must parse as an RFC 6901 pointer and not be the root
    /// (validation); each must RESOLVE on every JSON response the
    /// route serves, or the response fails closed (schema drift, the
    /// same strictness as the DW-028 body transform).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// Extra pointers masked per consumer GROUP: group name -> pointers
    /// (unioned with `fields` for members of the group; consumers in
    /// no listed group get the floor alone). Validation checks the
    /// group names resolve against some config consumer's `groups`
    /// (the same store-only-group caveat as authorization group rules).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<String, Vec<String>>,
}

/// The value a masked field is replaced with (DW-029): the JSON string
/// `"***"` (the feature analysis row's `JSON paths -> ***`). FIXED, not
/// configurable — the sentinel is a fixed marker the client can rely
/// on (a value the gateway itself chose and documents) and identical
/// on every route, so nothing about a masked response depends on
/// per-route config a client cannot see. One ambiguity is inherent
/// and documented: source data that is literally `"***"` at a masked
/// position is indistinguishable from the sentinel — treat every
/// `"***"` at a configured pointer as masked (the operator docs carry
/// the same caveat). Operators who need a different shape on a
/// specific route combine masking with a DW-028 response transform
/// (which runs after masking and sees the sentinel).
pub const MASKED_VALUE: &str = "***";

/// Header names no REQUEST-side header op may touch (DW-028). Framing
/// (`content-length`, `transfer-encoding`) is rebuilt by the forward
/// pipeline from the actual body — an op that forced a disagreeing
/// value would be a request-smuggling primitive aimed at the upstream,
/// the exact class the pre-parse sniff exists to stop on the inbound
/// side. The rest is the hop-by-hop class (RFC 9110 section 7.6.1 plus
/// the legacy keep-alive/proxy spellings): the gateway strips and, for
/// upgrades, re-adds `connection`/`upgrade` itself. `host` is not the
/// operator's either — the gateway names the origin it dials (see
/// `UpstreamHandle::send_with_hash_key`).
pub fn is_forbidden_request_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
    )
}

/// Header names no RESPONSE-side header op may touch (DW-028): the
/// framing/hop-by-hop class plus `content-encoding`, which only the
/// compression pipeline may manage — an op that stripped it without
/// decoding would corrupt the body, and one that added it would
/// misdescribe bytes it did not encode.
pub fn is_forbidden_response_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "content-length"
            | "content-encoding"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
    )
}

fn is_false(b: &bool) -> bool {
    !*b
}

// ---------------------------------------------------------------------------
// JSON Pointer grammar (RFC 6901, the shared subset)
// ---------------------------------------------------------------------------

/// A parsed RFC 6901 JSON pointer (DW-028): the compiled form the
/// runtime applies and validation checks, so the two can never
/// disagree on what `/items/0` means. Built once at snapshot compile;
/// the raw config string never reaches the request path (the same
/// precompute contract as the CORS/compression/deprecation tables).
///
/// The grammar is RFC 6901 with the array-index discipline of RFC 6902
/// (`add`): a token of digits (no leading zeros, `0` alone allowed)
/// that fits `usize` addresses an array element; every other token is
/// an object key. A container decides which interpretation applies —
/// on an object the token `0` is the key `"0"`; on an array the token
/// `a` cannot resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonPointer {
    tokens: Vec<String>,
    /// Precomputed array-index form per token (`None`: the token is
    /// not index-shaped, or does not fit usize).
    indexes: Vec<Option<usize>>,
    /// `true` when the pointer is the whole document (`""`).
    root: bool,
}

impl JsonPointer {
    /// Parse an RFC 6901 pointer. `None` = malformed (does not start
    /// with `/` unless empty, or carries a `~` escape other than `~0`
    /// / `~1`).
    pub fn parse(raw: &str) -> Option<JsonPointer> {
        if raw.is_empty() {
            return Some(JsonPointer {
                tokens: Vec::new(),
                indexes: Vec::new(),
                root: true,
            });
        }
        if !raw.starts_with('/') {
            return None;
        }
        let mut tokens = Vec::new();
        let mut indexes = Vec::new();
        for raw_token in raw[1..].split('/') {
            // Unescape ~1 -> '/' then ~0 -> '~' (RFC 6901 order); any
            // other tilde sequence is malformed.
            let mut token = String::new();
            let mut chars = raw_token.chars();
            while let Some(c) = chars.next() {
                if c != '~' {
                    token.push(c);
                    continue;
                }
                match chars.next() {
                    Some('0') => token.push('~'),
                    Some('1') => token.push('/'),
                    _ => return None,
                }
            }
            indexes.push(parse_index(&token));
            tokens.push(token);
        }
        Some(JsonPointer {
            tokens,
            indexes,
            root: false,
        })
    }

    /// Is this the whole-document pointer (`""`)?
    pub fn is_root(&self) -> bool {
        self.root
    }

    /// The reference tokens, unescaped (diagnostics and tests).
    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }
}

/// Array-index form of one reference token: digits without leading
/// zeros (bare `0` allowed) fitting `usize`; anything else is not an
/// index. Tokens like `01` or `-` are object keys only.
fn parse_index(token: &str) -> Option<usize> {
    if token.is_empty() || token.len() > 1 && token.starts_with('0') {
        return None;
    }
    if !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    token.parse().ok()
}

/// Is `media_type` (the part before any `;`, already lowercased) a
/// JSON media type this gateway will body-transform (DW-028)? Exactly
/// the `application/json` type and the structured-syntax suffix family
/// `application/<*+json>` (an `application/vnd.acme+json` body IS a
/// JSON body); parameters are the caller's business (stripped before
/// this check). No other type family carries the `+json` suffix in
/// practice, and widening to `text/json`-style one-offs buys nothing.
pub fn is_json_media_type(media_type: &str) -> bool {
    let Some((ty, sub)) = media_type.split_once('/') else {
        return false;
    };
    ty == "application" && (sub == "json" || sub.ends_with("+json"))
}

// ---------------------------------------------------------------------------
// Compiled form (snapshot precompute)
// ---------------------------------------------------------------------------

/// Snapshot-compiled form of a [`JsonBodyTransform`] (DW-028): every
/// op's pointer parsed once at snapshot-compile time; the request path
/// applies tokens, never re-parsing config strings. Validation
/// guarantees every pointer parses, so compilation drops nothing on
/// any publishable config; a `None`-producing parse is skipped with
/// the same unreachable-skip contract as the CORS/compression
/// compilations.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledJsonTransform {
    max_bytes: u64,
    ops: Vec<CompiledJsonOp>,
}

/// One compiled op.
#[derive(Debug, Clone, PartialEq)]
pub enum CompiledJsonOp {
    /// Write `value` at `pointer`.
    Set {
        pointer: JsonPointer,
        value: serde_json::Value,
    },
    /// Delete at `pointer`.
    Remove { pointer: JsonPointer },
}

/// Why a compiled transform failed on a document (DW-028). The
/// offending pointer rides along for the server-side log; the client
/// envelope stays generic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonTransformError {
    /// The pointer's parent path does not exist (or is not a
    /// container), or the final token does not address an existing
    /// member for `remove` / array-`set`.
    Unresolved { path: String },
    /// `remove` at the root: there is no document left to serialize
    /// (validation rejects this; a generation-tear backstop).
    RemoveRoot,
}

impl std::fmt::Display for JsonTransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonTransformError::Unresolved { path } => {
                write!(f, "json pointer '{path}' does not resolve")
            }
            JsonTransformError::RemoveRoot => {
                write!(f, "json pointer removes the whole document")
            }
        }
    }
}

impl std::error::Error for JsonTransformError {}

impl CompiledJsonTransform {
    /// Compile a (validated) transform's op list.
    pub fn compile(cfg: &JsonBodyTransform) -> CompiledJsonTransform {
        let ops = cfg
            .ops
            .iter()
            .filter_map(|op| match op {
                JsonOp::Set { path, value } => {
                    JsonPointer::parse(path).map(|pointer| CompiledJsonOp::Set {
                        pointer,
                        value: value.clone(),
                    })
                }
                JsonOp::Remove { path } => {
                    JsonPointer::parse(path).map(|pointer| CompiledJsonOp::Remove { pointer })
                }
            })
            .collect();
        CompiledJsonTransform {
            max_bytes: cfg.max_bytes,
            ops,
        }
    }

    /// The buffering cap (bytes).
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Apply every op to `doc`, in order. Fails on the first
    /// unresolved pointer (see the module docs for the strictness
    /// rationale); the document is left as the ops up to the failure
    /// made it (the caller discards it on error).
    pub fn apply(&self, doc: &mut serde_json::Value) -> Result<(), JsonTransformError> {
        for op in &self.ops {
            match op {
                CompiledJsonOp::Set { pointer, value } => {
                    apply_set(pointer, value, doc)?;
                }
                CompiledJsonOp::Remove { pointer } => {
                    apply_remove(pointer, doc)?;
                }
            }
        }
        Ok(())
    }
}

/// Snapshot-compiled form of a [`Masking`] policy (DW-029): every
/// pointer parsed once at snapshot-compile time. The effective pointer
/// set is resolved per request (the floor plus the authenticated
/// consumer's groups — the union rule), which is why groups stay a map
/// here rather than being flattened at compile time.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledMasking {
    max_bytes: u64,
    /// The every-consumer floor (`fields`), parsed.
    base: Vec<JsonPointer>,
    /// Per-group additional pointers, parsed (`groups`).
    groups: BTreeMap<String, Vec<JsonPointer>>,
}

impl CompiledMasking {
    /// Compile a (validated) masking policy. Validation guarantees
    /// every pointer parses, so compilation drops nothing on any
    /// publishable config (the same unreachable-skip contract as
    /// [`CompiledJsonTransform::compile`]).
    pub fn compile(cfg: &Masking) -> CompiledMasking {
        let base = cfg
            .fields
            .iter()
            .filter_map(|p| JsonPointer::parse(p))
            .collect();
        let groups = cfg
            .groups
            .iter()
            .map(|(g, paths)| {
                (
                    g.clone(),
                    paths.iter().filter_map(|p| JsonPointer::parse(p)).collect(),
                )
            })
            .collect();
        CompiledMasking {
            max_bytes: cfg.max_bytes,
            base,
            groups,
        }
    }

    /// The buffering cap (bytes).
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Mask `doc` in place for a consumer in `consumer_groups`: every
    /// pointer in the floor plus every listed group the consumer
    /// belongs to is replaced with [`MASKED_VALUE`]. Returns how many
    /// DISTINCT pointers were applied (the audit count; a pointer
    /// listed in the floor and in one or more groups applies once).
    /// Fails on the first pointer that does not resolve — the
    /// strictness rule the DW-028 transform argues for, mandatory in
    /// the redaction direction: a silent miss is the leak.
    pub fn apply(
        &self,
        doc: &mut serde_json::Value,
        consumer_groups: &[String],
    ) -> Result<usize, JsonTransformError> {
        // Resolve the effective set first (floor, then each matching
        // group's extras, deduplicated): replacement is
        // pointer-independent, so only the FIRST FAILURE depends on
        // order — floor order, then the consumer's group-list order,
        // both deterministic config orders.
        let mut effective: Vec<&JsonPointer> = Vec::new();
        for pointer in &self.base {
            effective.push(pointer);
        }
        for group in consumer_groups {
            let Some(extra) = self.groups.get(group) else {
                continue;
            };
            for pointer in extra {
                if !effective.contains(&pointer) {
                    effective.push(pointer);
                }
            }
        }
        let count = effective.len();
        for pointer in effective {
            apply_mask_pointer(pointer, doc)?;
        }
        Ok(count)
    }
}

/// Replace the value AT `pointer` with [`MASKED_VALUE`] — only where
/// the pointer RESOLVES; a miss is [`JsonTransformError::Unresolved`]
/// (masking never inserts: a field that is not there to redact means
/// the response drifted from the contract the policy pinned).
fn apply_mask_pointer(
    pointer: &JsonPointer,
    doc: &mut serde_json::Value,
) -> Result<(), JsonTransformError> {
    // Validation rejects the root pointer for masking; keep the walker
    // total anyway (a generation-tear backstop, never a panic).
    if pointer.is_root() {
        *doc = serde_json::Value::String(MASKED_VALUE.to_string());
        return Ok(());
    }
    let tokens = pointer.tokens();
    let indexes = &pointer.indexes;
    let (last, parent_tokens) = tokens.split_last().expect("non-root has tokens");
    let (last_index, parent_indexes) = indexes.split_last().expect("indexes parallel tokens");
    let path = render(pointer);
    let parent = resolve_tokens(parent_tokens, parent_indexes, &path, doc)?;
    let sentinel = serde_json::Value::String(MASKED_VALUE.to_string());
    match parent {
        serde_json::Value::Object(map) => {
            if let Some(slot) = map.get_mut(last) {
                *slot = sentinel;
                Ok(())
            } else {
                Err(JsonTransformError::Unresolved { path })
            }
        }
        serde_json::Value::Array(items) => {
            let idx = last_index.ok_or(JsonTransformError::Unresolved { path: path.clone() })?;
            match items.get_mut(idx) {
                Some(slot) => {
                    *slot = sentinel;
                    Ok(())
                }
                None => Err(JsonTransformError::Unresolved { path: path.clone() }),
            }
        }
        _ => Err(JsonTransformError::Unresolved { path: path.clone() }),
    }
}

/// Resolve a token path to a mutable reference — the shared walker for
/// both ops. `indexes` runs parallel to `tokens` (the precomputed
/// array-index form); the two always come from one [`JsonPointer`] or
/// one of its proper prefixes, never mixed.
fn resolve_tokens<'a>(
    tokens: &[String],
    indexes: &[Option<usize>],
    path: &str,
    doc: &'a mut serde_json::Value,
) -> Result<&'a mut serde_json::Value, JsonTransformError> {
    let mut cur = doc;
    for (i, token) in tokens.iter().enumerate() {
        let index = indexes.get(i).copied().flatten();
        cur = match cur {
            serde_json::Value::Object(map) => {
                map.get_mut(token).ok_or(JsonTransformError::Unresolved {
                    path: path.to_string(),
                })?
            }
            serde_json::Value::Array(items) => {
                let idx = index.ok_or(JsonTransformError::Unresolved {
                    path: path.to_string(),
                })?;
                items.get_mut(idx).ok_or(JsonTransformError::Unresolved {
                    path: path.to_string(),
                })?
            }
            _ => {
                return Err(JsonTransformError::Unresolved {
                    path: path.to_string(),
                })
            }
        };
    }
    Ok(cur)
}

fn apply_set(
    pointer: &JsonPointer,
    value: &serde_json::Value,
    doc: &mut serde_json::Value,
) -> Result<(), JsonTransformError> {
    if pointer.is_root() {
        *doc = value.clone();
        return Ok(());
    }
    let tokens = pointer.tokens();
    let indexes = &pointer.indexes;
    let (last, parent_tokens) = tokens.split_last().expect("non-root has tokens");
    let (last_index, parent_indexes) = indexes.split_last().expect("indexes parallel tokens");
    let path = render(pointer);
    let parent = resolve_tokens(parent_tokens, parent_indexes, &path, doc)?;
    match parent {
        serde_json::Value::Object(map) => {
            map.insert(last.clone(), value.clone());
            Ok(())
        }
        serde_json::Value::Array(items) => {
            let idx = last_index.ok_or(JsonTransformError::Unresolved { path: path.clone() })?;
            let slot = items
                .get_mut(idx)
                .ok_or(JsonTransformError::Unresolved { path: path.clone() })?;
            *slot = value.clone();
            Ok(())
        }
        _ => Err(JsonTransformError::Unresolved { path: path.clone() }),
    }
}

fn apply_remove(
    pointer: &JsonPointer,
    doc: &mut serde_json::Value,
) -> Result<(), JsonTransformError> {
    if pointer.is_root() {
        return Err(JsonTransformError::RemoveRoot);
    }
    let tokens = pointer.tokens();
    let indexes = &pointer.indexes;
    let (last, parent_tokens) = tokens.split_last().expect("non-root has tokens");
    let (last_index, parent_indexes) = indexes.split_last().expect("indexes parallel tokens");
    let path = render(pointer);
    let parent = resolve_tokens(parent_tokens, parent_indexes, &path, doc)?;
    let existed = match parent {
        serde_json::Value::Object(map) => map.remove(last).is_some(),
        serde_json::Value::Array(items) => {
            let idx = last_index.ok_or(JsonTransformError::Unresolved { path: path.clone() })?;
            if idx < items.len() {
                items.remove(idx);
                true
            } else {
                false
            }
        }
        _ => false,
    };
    if existed {
        Ok(())
    } else {
        Err(JsonTransformError::Unresolved { path })
    }
}

/// Human-readable form of a pointer for error paths (the original
/// spelling is not retained; the canonical reconstruction is exact for
/// well-formed pointers modulo escape normalization).
fn render(pointer: &JsonPointer) -> String {
    if pointer.is_root() {
        return String::new();
    }
    let mut out = String::new();
    for token in pointer.tokens() {
        out.push('/');
        // Re-escape the two RFC 6901 escapes for a faithful spelling.
        for c in token.chars() {
            match c {
                '~' => out.push_str("~0"),
                '/' => out.push_str("~1"),
                _ => out.push(c),
            }
        }
    }
    out
}
