//! Request/response transforms and security-header injection (DW-028,
//! feature analysis 4.12 + the 5-Security header-injection row).
//!
//! ## The streaming split (the issue's done-when)
//!
//! "Streaming is preserved unless a transform explicitly buffers." The
//! implementation splits exactly there:
//!
//! - [`apply_header_ops`], [`apply_query_ops`], and
//!   [`apply_security_headers`] never touch a body. A route carrying
//!   only these forwards and streams byte-identically to a route with
//!   no transforms block at all.
//! - [`transform_request_body`] / [`transform_response_body`] are the
//!   ONE explicitly buffering path: they apply only when the route
//!   configured a JSON body transform AND the body declares itself
//!   JSON AND it is non-empty, and they buffer at most
//!   `max_bytes` — enforced against a declared `Content-Length` up
//!   front and against the live stream frame by frame. Over-cap fails
//!   CLOSED (413 request-side, 502 response-side): passing the body
//!   through untransformed would be fail-open in exactly the masking
//!   direction DW-029 builds on this machinery for.
//!
//! ## Where each piece runs (the documented order)
//!
//! Request side, inside the proxy action on the FORWARD path: DW-010
//! path rewrite, then [`apply_query_ops`] (the rewrite re-attaches the
//! original query verbatim, this block is the only thing that may
//! change it), then hop-by-hop stripping and the gateway's trusted
//! headers (`X-Forwarded-*`, `X-Consumer-*`), then [`apply_header_ops`]
//! — ops see the near-final forwarded request, which is also why they
//! MAY remove the trust headers (the operator owns the upstream's
//! contract; see `config::transforms`), and finally the body transform
//! BEFORE retry buffering, so a retried attempt replays the
//! TRANSFORMED bytes.
//!
//! Response side, in the decoration tail: FIELD MASKING first (DW-029,
//! [`mask_response_body`] — before anything else can so much as read
//! the body: once the sentinel replaces a secret, the original bytes
//! exist nowhere in the gateway, so no later stage — operator
//! transforms, the compression codec — can resurrect or re-emit them),
//! then the body transform (compression then encodes the transformed
//! bytes and its eligibility check sees the final content type), then
//! header ops, then the existing compression -> versioning -> CORS
//! stages, then [`apply_security_headers`] (last policy stamp before
//! rate headers), then rate headers.
//!
//! Response HEADER and BODY transforms apply to action responses only;
//! security headers apply to every route-matched response including
//! gateway short-circuits (see `config::transforms::SecurityHeaders`
//! for the asymmetry with deprecation stamps). MASKING applies to
//! PROXY action responses only: the leak surface it guards is the
//! upstream's output — gateway-authored bodies (redirect, respond) are
//! operator config bytes with no upstream data to redact, and bodiless
//! statuses (1xx/101/204/304) have nothing to leak; both pass.
//!
//! ## Masking's inverted gate posture (DW-029)
//!
//! The DW-028 body transform PASSES THROUGH what it cannot handle
//! (encoded or non-JSON bodies) — a convenience transform skipping
//! itself is harmless. Masking inverts every one of those gates into a
//! 502 REFUSAL: the gateway cannot prove the configured fields absent
//! from bytes it cannot parse, and for a redaction policy a skipped
//! pass IS the leak (the module docs of `config::transforms` carry the
//! full argument). A route that configures masking pins its proxied
//! responses to the contract "identity-encoded JSON within the cap,
//! with every configured pointer present" — an upstream that violates
//! it answers 502 with a generic envelope, and one `dwara::policy`
//! warn event names the refusal class server-side. Every successful
//! mask emits one `dwara::policy` info event (the audit trail the
//! issue's done-when asks for: route, consumer, count, request-id).
//!
//! ## Why header/query ops are lenient where JSON pointers are strict
//!
//! A header may legitimately be absent from a given request; renaming
//! or removing an absent header is a no-op, not an error. A JSON
//! pointer that does not resolve is a DATA-SHAPE violation against a
//! contract the operator pinned — and in the remove direction a
//! silent miss is the leak the policy exists to prevent. Leniency and
//! strictness each sit where their failure mode says they belong.
//!
//! ## Framing after a body transform
//!
//! Both body transforms rewrite `Content-Length` to the transformed
//! body's exact length (the buffered bytes ARE the body; any stale
//! declared length would misframe the hop). Framing headers are
//! meanwhile rejected from header ops by validation
//! (`config::transforms::is_forbidden_*_header`), so exactly one
//! component — this module — ever writes them.

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{
    HeaderMap, HeaderName, HeaderValue, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_SECURITY_POLICY,
    CONTENT_TYPE, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use hyper::{Response, Uri};

use crate::config::transforms as t;
use crate::config::transforms::{CompiledJsonTransform, HeaderOps, QueryOps, SecurityHeaders};

use crate::dataplane::proxy::ProxyBody;

// ---------------------------------------------------------------------------
// Header ops
// ---------------------------------------------------------------------------

/// Apply header manipulation ops in the frozen order (DW-028): `set`
/// (replace-all), `add` (append), `rename` (relabel every value), then
/// `remove` — see [`HeaderOps`] for the rationale. Every name/value
/// was validated representable at config publish; the `if let Ok`
/// skips are generation-tear backstops (never a panic, never a 500),
/// the same posture as the respond-action headers.
pub fn apply_header_ops(headers: &mut HeaderMap, ops: &HeaderOps) {
    for (name, value) in &ops.set {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(n, v);
        }
    }
    for (name, value) in &ops.add {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.append(n, v);
        }
    }
    // Rename: move EVERY value of `from` onto `to` (appending after any
    // values `to` already carries); an absent `from` is a no-op (a
    // header may simply not be present on this request).
    for (from, to) in &ops.rename {
        if let (Ok(f), Ok(to_n)) = (
            HeaderName::from_bytes(from.as_bytes()),
            HeaderName::from_bytes(to.as_bytes()),
        ) {
            let values: Vec<HeaderValue> = headers.get_all(&f).iter().cloned().collect();
            headers.remove(&f);
            for v in values {
                headers.append(&to_n, v);
            }
        }
    }
    for name in &ops.remove {
        if let Ok(n) = HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(&n);
        }
    }
}

// ---------------------------------------------------------------------------
// Query ops
// ---------------------------------------------------------------------------

/// Apply query manipulation ops to a request URI (DW-028). Returns the
/// rebuilt URI, or `None` when nothing changed (the caller keeps the
/// original — its bytes are already correct). Original pairs are
/// carried VERBATIM (no decode/re-encode round trip: a client's exact
/// percent-encoding spelling survives); only pairs a named op touches
/// are encoded, by the shared percent-encoder below.
///
/// Per-pair application order (deterministic, documented): a key named
/// by `remove` or owned by `set` is dropped from its original position
/// (`set` re-emits its pair at the end; `remove` just drops), then
/// `rename` re-labels surviving pairs in place (value bytes verbatim),
/// and `add` pairs append at the end (after `set`, both in sorted key
/// order). Key matching is on RAW bytes — neither the config key nor
/// the request key is percent-decoded first, so `set: {a: "1"}`
/// matches the literal `a=1`, never `%61=1`.
pub fn apply_query_ops(uri: &Uri, ops: &QueryOps) -> Option<Uri> {
    let mut emitted: Vec<String> = Vec::new();
    for (k, v) in ops.set.iter().chain(ops.add.iter()) {
        emitted.push(format!(
            "{}={}",
            encode_query_component(k),
            encode_query_component(v)
        ));
    }
    let Some(original) = uri.query() else {
        if emitted.is_empty() {
            return None;
        }
        // No query yet: set/add build one from scratch.
        return rebuild(uri, &emitted.join("&"));
    };

    let mut carried: Vec<String> = Vec::new();
    for raw_pair in original.split('&') {
        if raw_pair.is_empty() {
            continue; // a trailing/doubled '&' contributes nothing
        }
        let key = raw_pair.split('=').next().unwrap_or("");
        // Set-owned and removed keys do not carry (set re-emits at the
        // end; remove is gone for good).
        if ops.remove.iter().any(|r| r == key) || ops.set.contains_key(key) {
            continue;
        }
        let key_out = match ops.rename.get(key) {
            Some(to) => encode_query_component(to).into_owned(),
            None => key.to_string(),
        };
        let piece = match raw_pair.split_once('=') {
            Some((_, value)) => format!("{key_out}={value}"),
            None => key_out,
        };
        carried.push(piece);
    }
    let mut all = carried;
    all.extend(emitted);
    if all.is_empty() {
        // Everything removed, nothing emitted: the query disappears.
        return rebuild(uri, "");
    }
    let joined = all.join("&");
    if joined == original {
        return None;
    }
    rebuild(uri, &joined)
}

/// Percent-encode one query component for emission (DW-028): encode
/// every byte outside the RFC 3986 unreserved set and the query-safe
/// sub-delims, ALWAYS encoding the three structural bytes (`&`, `=`,
/// `#`) and space. Validation rejects control/non-ASCII input; the
/// encoder stays defensive for any byte.
fn encode_query_component(s: &str) -> std::borrow::Cow<'_, str> {
    fn safe(b: u8) -> bool {
        matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'.' | b'_' | b'~'
            | b'!' | b'$' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b':' | b'@' | b'/' | b'?')
    }
    if s.bytes().all(safe) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if safe(b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Rebuild `uri` with a new query (`""` = no query). `None` on an
/// unbuildable result — validation keeps ops' emissions in the safe
/// alphabet, so this is a never-fail backstop that keeps the ORIGINAL
/// URI rather than erroring the request.
fn rebuild(uri: &Uri, query: &str) -> Option<Uri> {
    let pq = if query.is_empty() {
        uri.path().to_string()
    } else {
        format!("{}?{}", uri.path(), query)
    };
    let Ok(pq) = pq.parse::<hyper::http::uri::PathAndQuery>() else {
        return None;
    };
    let mut parts = hyper::http::uri::Parts::from(uri.clone());
    parts.path_and_query = Some(pq);
    Uri::from_parts(parts).ok()
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

/// Stamp a route's security-header policy onto a response (DW-028).
/// Every present field REPLACES any upstream-sent value: the gateway
/// is the source of truth for its edge policy (the same rule as the
/// deprecation and `X-RateLimit-*` headers). Values are static or
/// validation-checked representable; the `if let Ok` skips are the
/// same generation-tear backstop posture as everywhere in the tail.
pub fn apply_security_headers(headers: &mut HeaderMap, sh: &SecurityHeaders) {
    if let Some(max_age) = sh.hsts_max_age_secs {
        let mut value = format!("max-age={max_age}");
        if sh.hsts_include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if sh.hsts_preload {
            value.push_str("; preload");
        }
        // A u64 with the two literal directives is always representable;
        // the parse keeps the shape honest.
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.insert(STRICT_TRANSPORT_SECURITY, v);
        }
    }
    if sh.nosniff {
        headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    }
    if let Some(csp) = &sh.content_security_policy {
        if let Ok(v) = HeaderValue::from_str(csp) {
            headers.insert(CONTENT_SECURITY_POLICY, v);
        }
    }
    if let Some(fo) = sh.frame_options {
        headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static(fo.header_value()));
    }
}

// ---------------------------------------------------------------------------
// Body transforms
// ---------------------------------------------------------------------------

/// The lowercase media type of a `Content-Type` header (parameters
/// stripped), when the header is present and textual.
pub fn media_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(&CONTENT_TYPE)?
        .to_str()
        .ok()
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .filter(|mt| !mt.is_empty())
}

/// Does this body's `Content-Type` make it a JSON body-transform
/// candidate (DW-028)? (`application/json` and the `application/
/// <*+json>` family, parameters ignored — see
/// `config::transforms::is_json_media_type`.)
pub fn is_json_body(headers: &HeaderMap) -> bool {
    media_type(headers).is_some_and(|mt| t::is_json_media_type(&mt))
}

/// Why a REQUEST body transform refused or failed (DW-028). The proxy
/// maps each arm to its client answer: `RouteLimit` keeps the route
/// limit's 413 envelope (the route's cap, not the transform's, bound
/// the body); `SignatureMismatch` keeps the HMAC family's 401 (the
/// client's own signature bound a digest the body did not match);
/// `TooLarge`/`InvalidJson`/`Unresolved` answer 413/400/400 in the
/// transform's own envelope.
#[derive(Debug)]
pub enum RequestBodyTransformError {
    /// The route's own streaming body limit aborted the read (the
    /// limit wrapper inside this body stack tripped mid-buffer).
    RouteLimit,
    /// The signed-body digest did not match (DW-036): the request's
    /// HMAC signature bound a different body.
    SignatureMismatch,
    /// The body exceeded the transform's `max_bytes`.
    TooLarge { cap: u64 },
    /// The body claims JSON but does not parse.
    InvalidJson,
    /// A pointer did not resolve (the strict-failure rule; see the
    /// module docs).
    Unresolved { path: String },
    /// The body stream errored while buffering (client abort, framing
    /// failure).
    Body(String),
}

/// The outcome of the request body-transform step (DW-028).
pub enum RequestBodyOutcome<B> {
    /// No transform applied: the ORIGINAL body streams on untouched —
    /// the streaming guarantee. (No policy, non-JSON or encoded
    /// content type, or a declared-empty body.)
    Original(B),
    /// Replacement bytes: the caller rewrites `Content-Length` and
    /// treats the body as replayable (retry attempts re-send these
    /// bytes, never the pre-transform stream).
    Replaced(Bytes),
    /// The transform failed; the caller maps the error to its
    /// 413/401/400 answer.
    Failed(RequestBodyTransformError),
}

/// The REQUEST body transform (DW-028): gate, buffer (capped), parse,
/// apply ops, serialize. Gates in order, cheapest first — no compiled
/// policy (the caller's `None` check), then here: non-JSON content
/// type (bodies of other types stream through untouched), an
/// already-encoded body (the transform does not decode), a declared
/// empty body (nothing to transform — bodiless methods pass), and a
/// declared length over the cap (413 without reading a byte). Only
/// then does anything buffer.
///
/// Reading the body here preserves every wrapper beneath it: the
/// route's limit counting guard and the HMAC digest fold still see
/// the ORIGINAL client bytes (the digest binds what the client
/// signed; the transform then shapes what the upstream receives —
/// enforcement and policy are separable by design).
pub async fn transform_request_body<B>(
    body: B,
    compiled: &CompiledJsonTransform,
    headers: &HeaderMap,
) -> RequestBodyOutcome<B>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if !is_json_body(headers) || headers.contains_key(&CONTENT_ENCODING) {
        return RequestBodyOutcome::Original(body);
    }
    let declared = body.size_hint().exact();
    if declared == Some(0) {
        return RequestBodyOutcome::Original(body);
    }
    let cap = compiled.max_bytes();
    if declared.is_some_and(|d| d > cap) {
        return RequestBodyOutcome::Failed(RequestBodyTransformError::TooLarge { cap });
    }
    let bytes = match buffer_capped(body, cap).await {
        Ok(bytes) => bytes,
        Err(e) => return RequestBodyOutcome::Failed(e),
    };
    if bytes.is_empty() {
        // An UNDECLARED empty stream (e.g. a bodiless method without
        // Content-Length): nothing to transform. The empty buffered
        // body is byte-identical to what arrived.
        return RequestBodyOutcome::Replaced(bytes);
    }
    match run_json_transform(&bytes, compiled) {
        Ok(out) => RequestBodyOutcome::Replaced(out),
        Err(e) => RequestBodyOutcome::Failed(e),
    }
}

/// Why a RESPONSE body transform failed (DW-028); every arm answers
/// 502 — the upstream violated the contract the transform pinned (the
/// client never sees upstream detail).
#[derive(Debug)]
pub enum ResponseBodyTransformError {
    /// Over the transform's `max_bytes` (declared or streamed).
    TooLarge { cap: u64 },
    /// Not valid JSON.
    InvalidJson,
    /// A pointer did not resolve.
    Unresolved { path: String },
    /// The upstream stream died mid-body while buffering.
    Upstream(String),
}

/// The RESPONSE body transform (DW-028), the decoration tail's first
/// stage: gate, buffer (capped), parse, apply ops, serialize. Gates:
/// informational/101/204/304 statuses (no body to shape), non-JSON
/// content type, and an already-encoded body all pass through
/// UNTOUCHED — SSE and streamed downloads on a transformed route keep
/// streaming, the core guarantee of this feature. A declared length
/// over the cap fails 502 without reading.
///
/// Two properties fall out of buffering before headers reach the
/// client: an upstream stream death mid-body answers a CLEAN 502
/// envelope instead of a torn stream, and upstream trailers are
/// dropped (they described the pre-transform body — forwarding a
/// stale checksum trailer alongside replaced bytes would be a lie).
pub async fn transform_response_body(
    resp: Response<ProxyBody>,
    compiled: &CompiledJsonTransform,
    rid: &str,
) -> Response<ProxyBody> {
    use hyper::body::Body as _;

    let status = resp.status();
    if status.is_informational()
        || status == hyper::StatusCode::SWITCHING_PROTOCOLS
        || status == hyper::StatusCode::NO_CONTENT
        || status == hyper::StatusCode::NOT_MODIFIED
    {
        return resp;
    }
    if !is_json_body(resp.headers()) || resp.headers().contains_key(&CONTENT_ENCODING) {
        return resp;
    }
    let cap = compiled.max_bytes();
    if resp.body().size_hint().exact().is_some_and(|d| d > cap) {
        return response_transform_failure(rid);
    }

    let (mut parts, body) = resp.into_parts();
    let bytes = match collect_capped(body, cap).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                code = "response_transform_failed",
                request_id = %rid,
                error = ?e,
                "upstream response failed the route's body transform"
            );
            return response_transform_failure(rid);
        }
    };
    // An empty JSON-typed body has nothing to transform; forwarding
    // the collected emptiness is byte-identical to passthrough.
    let out = if bytes.is_empty() {
        Ok(bytes)
    } else {
        run_json_transform(&bytes, compiled)
    };
    match out {
        Ok(out) => {
            if let Ok(v) = HeaderValue::from_str(&out.len().to_string()) {
                parts.headers.insert(CONTENT_LENGTH, v);
            }
            Response::from_parts(parts, ProxyBody::Full(Full::new(out)))
        }
        Err(e) => {
            tracing::warn!(
                code = "response_transform_failed",
                request_id = %rid,
                error = ?e,
                "upstream response failed the route's body transform"
            );
            response_transform_failure(rid)
        }
    }
}

/// Buffer a response body up to `cap` bytes (the shared DW-028/DW-029
/// response-side capped collector). Trailers are dropped: they
/// described the pre-transform body, and forwarding a stale checksum
/// trailer alongside replaced bytes would be a lie. Over-cap and
/// mid-body stream death surface as the two failure arms; both callers
/// answer 502 (buffering before headers reach the client is what makes
/// that a clean envelope instead of a torn stream).
async fn collect_capped<B>(body: B, cap: u64) -> Result<Bytes, ResponseBodyTransformError>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    use http_body_util::BodyExt as _;
    let mut body = std::pin::pin!(body);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match body.as_mut().frame().await {
            Some(Ok(frame)) => {
                let Ok(data) = frame.into_data() else {
                    continue; // trailer: dropped (see the doc comment)
                };
                if buf.len() as u64 + data.len() as u64 > cap {
                    return Err(ResponseBodyTransformError::TooLarge { cap });
                }
                buf.extend_from_slice(&data);
            }
            Some(Err(e)) => {
                return Err(ResponseBodyTransformError::Upstream(e.to_string()));
            }
            None => return Ok(Bytes::from(buf)),
        }
    }
}

/// The 502 for a failed response transform: generic message (no
/// upstream internals leak), uniform JSON envelope.
fn response_transform_failure(rid: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(hyper::StatusCode::BAD_GATEWAY)
        .header(CONTENT_TYPE, "application/json")
        .body(ProxyBody::Full(Full::new(
            crate::observability::envelope_body(
                "response_transform_failed",
                "upstream response failed the route's transform policy",
                rid,
            ),
        )))
        .expect("static 502 response is valid")
}

// ---------------------------------------------------------------------------
// Response field masking (DW-029)
// ---------------------------------------------------------------------------

/// Why masking refused a response (DW-029). Every arm answers the same
/// 502 envelope; the distinction exists for the server-side
/// `dwara::policy` warn event (which refusal class fired).
#[derive(Debug)]
enum MaskRefusal {
    /// The upstream sent a content-encoded body: the gateway does not
    /// decode, and cannot prove anything about bytes it cannot read.
    Encoded,
    /// The body is not JSON-media-typed: pointers cannot apply to it,
    /// so its contents cannot be proven clean.
    NotJson,
    /// Over the masking cap (declared or streamed).
    TooLarge { cap: u64 },
    /// JSON-typed but unparseable.
    InvalidJson,
    /// A configured pointer did not resolve (schema drift; the strict
    /// miss-is-the-leak rule).
    Unresolved { path: String },
    /// The upstream stream died mid-body while buffering.
    Upstream(String),
}

impl std::fmt::Display for MaskRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MaskRefusal::Encoded => {
                write!(f, "response is content-encoded; masking cannot read it")
            }
            MaskRefusal::NotJson => {
                write!(
                    f,
                    "response is not JSON; masking cannot prove fields absent"
                )
            }
            MaskRefusal::TooLarge { cap } => {
                write!(f, "response exceeds the masking cap of {cap} bytes")
            }
            MaskRefusal::InvalidJson => write!(f, "response claims JSON but does not parse"),
            MaskRefusal::Unresolved { path } => {
                write!(f, "masking pointer '{path}' does not resolve")
            }
            MaskRefusal::Upstream(e) => write!(f, "upstream stream failed mid-body: {e}"),
        }
    }
}

/// The RESPONSE field masking pass (DW-029), the decoration tail's
/// first stage and the security floor of the response path. Gates, in
/// order — every one of them FAILS CLOSED (the inverted posture; see
/// the module docs): bodiless statuses pass (nothing to leak), then a
/// content-encoded body, a non-JSON content type, a declared length
/// over the cap, an over-cap or dying stream, unparseable JSON, and a
/// pointer miss each answer 502 with a generic envelope plus one
/// `dwara::policy` warn event naming the refusal class server-side.
/// The gateway's OWN compression (DW-027) runs later in the tail, so
/// it can never trip the encoding gate — only upstream-pre-encoded
/// responses do.
///
/// On success every effective pointer (route floor plus the consumer's
/// groups — the union rule, `config::transforms::Masking`) is replaced
/// with the fixed sentinel, `Content-Length` is rewritten, and one
/// `dwara::policy` info event records route, consumer, masked count,
/// and request-id: the audit trail the issue's done-when requires.
pub async fn mask_response_body(
    resp: Response<ProxyBody>,
    compiled: &crate::config::transforms::CompiledMasking,
    consumer_groups: &[String],
    route: &str,
    consumer: Option<&str>,
    rid: &str,
) -> Response<ProxyBody> {
    use hyper::body::Body as _;

    let status = resp.status();
    if status.is_informational()
        || status == hyper::StatusCode::SWITCHING_PROTOCOLS
        || status == hyper::StatusCode::NO_CONTENT
        || status == hyper::StatusCode::NOT_MODIFIED
    {
        return resp;
    }
    if resp.headers().contains_key(&CONTENT_ENCODING) {
        return masking_refusal(rid, route, consumer, &MaskRefusal::Encoded);
    }
    if !is_json_body(resp.headers()) {
        return masking_refusal(rid, route, consumer, &MaskRefusal::NotJson);
    }
    let cap = compiled.max_bytes();
    if resp.body().size_hint().exact().is_some_and(|d| d > cap) {
        return masking_refusal(rid, route, consumer, &MaskRefusal::TooLarge { cap });
    }
    let (mut parts, body) = resp.into_parts();
    let bytes = match collect_capped(body, cap).await {
        Ok(bytes) => bytes,
        Err(e) => {
            let refusal = match e {
                ResponseBodyTransformError::TooLarge { cap } => MaskRefusal::TooLarge { cap },
                // collect_capped cannot produce the parse/pointer arms;
                // the debug-formatted fallback keeps the match total with
                // no unreachable panic on the request path (server-side
                // log only, like every refusal reason).
                other => MaskRefusal::Upstream(format!("{other:?}")),
            };
            return masking_refusal(rid, route, consumer, &refusal);
        }
    };
    // An empty body has nothing to mask — byte-identical passthrough
    // (a proxied HEAD lands here, among others).
    if bytes.is_empty() {
        if let Ok(v) = HeaderValue::from_str("0") {
            parts.headers.insert(CONTENT_LENGTH, v);
        }
        return Response::from_parts(parts, ProxyBody::Full(Full::new(bytes)));
    }
    let mut doc: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(doc) => doc,
        Err(_) => return masking_refusal(rid, route, consumer, &MaskRefusal::InvalidJson),
    };
    let masked = match compiled.apply(&mut doc, consumer_groups) {
        Ok(masked) => masked,
        Err(t::JsonTransformError::Unresolved { path }) => {
            return masking_refusal(rid, route, consumer, &MaskRefusal::Unresolved { path })
        }
        // Validation rejects the root pointer for masking; this arm is
        // the same generation-tear backstop mapping the request-side
        // transform uses (RemoveRoot -> empty-path Unresolved).
        Err(t::JsonTransformError::RemoveRoot) => {
            return masking_refusal(
                rid,
                route,
                consumer,
                &MaskRefusal::Unresolved {
                    path: String::new(),
                },
            )
        }
    };
    let out = match serde_json::to_vec(&doc) {
        Ok(out) => Bytes::from(out),
        Err(_) => return masking_refusal(rid, route, consumer, &MaskRefusal::InvalidJson),
    };
    tracing::info!(
        target: "dwara::policy",
        code = "response_masked",
        route = route,
        consumer = consumer.unwrap_or("anonymous"),
        masked = masked,
        request_id = rid,
        "masked response fields (DW-029 audit trail)"
    );
    if let Ok(v) = HeaderValue::from_str(&out.len().to_string()) {
        parts.headers.insert(CONTENT_LENGTH, v);
    }
    Response::from_parts(parts, ProxyBody::Full(Full::new(out)))
}

/// The fail-closed 502 for a response masking refused: generic client
/// message (no pointer paths, no upstream detail), uniform JSON
/// envelope, and the server-side `dwara::policy` warn event that names
/// the refusal class — the correlation key is the request-id.
fn masking_refusal(
    rid: &str,
    route: &str,
    consumer: Option<&str>,
    refusal: &MaskRefusal,
) -> Response<ProxyBody> {
    tracing::warn!(
        target: "dwara::policy",
        code = "response_mask_failed",
        route = route,
        consumer = consumer.unwrap_or("anonymous"),
        request_id = rid,
        reason = %refusal,
        "response refused by the route's masking policy (fail-closed)"
    );
    Response::builder()
        .status(hyper::StatusCode::BAD_GATEWAY)
        .header(CONTENT_TYPE, "application/json")
        .body(ProxyBody::Full(Full::new(
            crate::observability::envelope_body(
                "response_mask_failed",
                "response failed the route's masking policy",
                rid,
            ),
        )))
        .expect("static 502 response is valid")
}

/// Buffer a body up to `cap` bytes (the DW-028 transform cap).
/// Distinguishes the two marker errors the gateway's own body
/// wrappers produce (route limit, signature digest) from a generic
/// body failure, so the caller answers with the right status family.
async fn buffer_capped<B>(body: B, cap: u64) -> Result<Bytes, RequestBodyTransformError>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    use http_body_util::BodyExt as _;
    let mut body = Box::pin(body);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                let Ok(data) = frame.into_data() else {
                    continue; // trailers are not body bytes
                };
                if buf.len() as u64 + data.len() as u64 > cap {
                    return Err(RequestBodyTransformError::TooLarge { cap });
                }
                buf.extend_from_slice(&data);
            }
            Some(Err(e)) => {
                let boxed: Box<dyn std::error::Error + Send + Sync> = e.into();
                return Err(classify_body_error(boxed));
            }
            None => return Ok(Bytes::from(buf)),
        }
    }
}

/// Map a body-wrapper error to its transform failure class: the route
/// limit's marker keeps the limit's 413, the signature digest marker
/// keeps the HMAC family's 401, everything else is a generic body
/// failure. Same marker types (and the same walking rationale) as
/// `proxy::request_limit_exceeded` / `proxy::signature_body_mismatch`.
fn classify_body_error(e: Box<dyn std::error::Error + Send + Sync>) -> RequestBodyTransformError {
    use crate::dataplane::hardening::{LimitedBodyError, SignatureBodyError};
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e.as_ref());
    while let Some(s) = src {
        if let Some(limit) = s.downcast_ref::<LimitedBodyError>() {
            match limit {
                LimitedBodyError::OverLimit { .. } => return RequestBodyTransformError::RouteLimit,
                LimitedBodyError::Inner(inner) => {
                    if inner
                        .downcast_ref::<SignatureBodyError>()
                        .is_some_and(|se| matches!(se, SignatureBodyError::DigestMismatch))
                    {
                        return RequestBodyTransformError::SignatureMismatch;
                    }
                }
            }
        }
        if s.downcast_ref::<SignatureBodyError>()
            .is_some_and(|se| matches!(se, SignatureBodyError::DigestMismatch))
        {
            return RequestBodyTransformError::SignatureMismatch;
        }
        src = s.source();
    }
    RequestBodyTransformError::Body(e.to_string())
}

/// Parse, apply ops, serialize (shared by both body transforms). The
/// request side reuses the error enum; the response side maps the same
/// failure set to its 502 family.
fn run_json_transform(
    bytes: &Bytes,
    compiled: &CompiledJsonTransform,
) -> Result<Bytes, RequestBodyTransformError> {
    let mut doc: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| RequestBodyTransformError::InvalidJson)?;
    compiled.apply(&mut doc).map_err(|e| match e {
        t::JsonTransformError::Unresolved { path } => {
            RequestBodyTransformError::Unresolved { path }
        }
        t::JsonTransformError::RemoveRoot => RequestBodyTransformError::Unresolved {
            path: String::new(),
        },
    })?;
    serde_json::to_vec(&doc)
        .map(Bytes::from)
        .map_err(|_| RequestBodyTransformError::InvalidJson)
}
