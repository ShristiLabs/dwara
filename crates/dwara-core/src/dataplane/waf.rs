//! WAF-lite heuristic filtering (DW-051).
//!
//! A lightweight, pattern-matching web application filter that inspects
//! the request path, query string, selected headers, and body (when JSON
//! or form-urlencoded) for common SQL-injection, XSS, and path-traversal
//! signatures. This is NOT a full WAF — it is a first-line traffic filter
//! that rejects obvious attack signatures before authentication or rate
//! limiting.
//!
//! ## Request-path position
//!
//! The WAF check runs AFTER the route method allowlist and BEFORE the
//! route limits (DW-027): a content filter that should reject malicious
//! requests before any resource is spent on auth or rate limiting. It
//! inspects the ORIGINAL request (before path rewrite / transforms).
//!
//! ## Inspection targets
//!
//! - **Path**: the original request URI path (after routing match, before
//!   rewrite).
//! - **Query string**: the raw query string.
//! - **Headers**: User-Agent, Referer, Cookie, X-Forwarded-For.
//! - **Body**: when the content type is `application/json` or
//!   `application/x-www-form-urlencoded`, up to `max_body_inspect_bytes`.
//!
//! ## Match result
//!
//! A [`WafMatch`] carries the filter category, the pattern that matched,
//! the inspection target, and a truncated value preview (max 64 chars —
//! never the full payload, which could be huge or sensitive). In
//! `dry_run` mode the match is logged and the request continues; otherwise
//! a 403 `waf_blocked` error envelope is returned.

use std::pin::Pin;

use bytes::Bytes;
use http_body_util::BodyExt as _;
use http_body_util::Full;
use hyper::body::Body;
use regex::Regex;

use crate::config::RouteWaf;

/// The filter category a matched pattern belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafFilter {
    Sqli,
    Xss,
    PathTraversal,
}

impl WafFilter {
    pub fn as_str(&self) -> &'static str {
        match self {
            WafFilter::Sqli => "sqli",
            WafFilter::Xss => "xss",
            WafFilter::PathTraversal => "path_traversal",
        }
    }
}

/// The inspection target where a match was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafTarget {
    Path,
    Query,
    Header,
    Body,
}

impl WafTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            WafTarget::Path => "path",
            WafTarget::Query => "query",
            WafTarget::Header => "header",
            WafTarget::Body => "body",
        }
    }
}

/// A WAF match result: the filter, pattern, target, and a truncated
/// value preview for logging. The preview is capped at 64 chars and
/// never carries the full payload (which could be huge or sensitive).
#[derive(Debug, Clone)]
pub struct WafMatch {
    pub filter: WafFilter,
    pub pattern: String,
    pub target: WafTarget,
    pub value_preview: String,
}

/// Truncate a value to 64 chars for safe logging.
fn truncate_preview(s: &str) -> String {
    const MAX_PREVIEW: usize = 64;
    if s.len() <= MAX_PREVIEW {
        s.to_string()
    } else {
        // Walk char boundaries so we never split a multi-byte char.
        let mut end = MAX_PREVIEW;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

/// Built-in SQLi signatures (case-insensitive).
const SQLI_PATTERNS: &[&str] = &[
    r"(?i)union\s+select",
    r"(?i)\bor\s+1\s*=\s*1\b",
    r"(?i)'\s*;\s*drop\s+table",
    r"(?i)'\s*;\s*delete\s+from",
    r"(?i)'\s*;\s*insert\s+into",
    r"(?i)'\s*;\s*update\s+set",
    r"(?i)--\s*$",
    r"(?i)--\s",
    r"(?i)xp_cmdshell",
    r"(?i)0x[0-9a-f]{8,}\b",
    r"(?i)'\s*or\s*'",
    r"(?i)'\s*and\s*'",
    r"(?i);\s*select\s+",
    r"(?i)\bexec\s*\(",
    r"(?i)\bwaitfor\s+delay\b",
    r"(?i)\bsleep\s*\(",
    r"(?i)\bbenchmark\s*\(",
    r"(?i)\bload_file\s*\(",
    r"(?i)\binto\s+outfile\b",
    r"(?i)\bgroup\s+by\s+\d+",
    r"(?i)'\s*=\s*'",
];

/// Built-in XSS signatures (case-insensitive).
const XSS_PATTERNS: &[&str] = &[
    r"(?i)<script",
    r"(?i)javascript:",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)onclick\s*=",
    r"(?i)onmouseover\s*=",
    r"(?i)<iframe",
    r"(?i)<object",
    r"(?i)<embed",
    r"(?i)document\.cookie",
    r"(?i)eval\s*\(",
    r"(?i)alert\s*\(",
    r"(?i)<img[^>]+src\s*=",
    r"(?i)<svg[^>]+onload",
    r"(?i)String\.fromCharCode",
    r"(?i)\\x3cscript",
    r"(?i)&lt;script",
    r"(?i)<body[^>]+onload",
    r"(?i)expression\s*\(",
];

/// Built-in path-traversal signatures.
const PATH_TRAVERSAL_PATTERNS: &[&str] = &[
    r"\.\./",
    r"\.\.\\",
    r"(?i)%2e%2e%2f",
    r"(?i)%2e%2e/",
    r"(?i)%2e%2e%5c",
    r"\.\.%2f",
    r"(?i)\.\.//",
    r"(?i)\.\.\\",
    r"(?i)\.\.;/",
    r"%00",
    r"(?i)%252e%252e%252f",
    r"(?i)/etc/passwd",
    r"(?i)/etc/shadow",
    r"(?i)c:\\windows\\",
    r"(?i)\\windows\\win\.ini",
    r"(?i)/proc/self/",
];

/// Compile the built-in patterns for a filter category into regexes.
fn builtin_patterns(filter: WafFilter) -> &'static [&'static str] {
    match filter {
        WafFilter::Sqli => SQLI_PATTERNS,
        WafFilter::Xss => XSS_PATTERNS,
        WafFilter::PathTraversal => PATH_TRAVERSAL_PATTERNS,
    }
}

/// A compiled WAF generation: the regex sets for each enabled filter
/// category, plus any custom patterns. Built once per config generation
/// and reused across requests.
pub struct WafGeneration {
    filters: Vec<WafFilterEntry>,
    max_body_inspect_bytes: u64,
    dry_run: bool,
}

struct WafFilterEntry {
    filter: WafFilter,
    patterns: Vec<Regex>,
}

impl WafGeneration {
    /// Build a WAF generation from the route config. Returns `None` when
    /// the WAF is disabled (no inspection should run).
    pub fn from_config(waf: &RouteWaf) -> Option<Self> {
        if !waf.enabled {
            return None;
        }
        // Resolve the filter set: an empty list defaults to all three.
        let filter_names: Vec<WafFilter> = if waf.filters.is_empty() {
            vec![WafFilter::Sqli, WafFilter::Xss, WafFilter::PathTraversal]
        } else {
            waf.filters
                .iter()
                .filter_map(|f| match f.as_str() {
                    "sqli" => Some(WafFilter::Sqli),
                    "xss" => Some(WafFilter::Xss),
                    "path_traversal" => Some(WafFilter::PathTraversal),
                    _ => None,
                })
                .collect()
        };
        let mut entries = Vec::with_capacity(filter_names.len());
        for filter in filter_names {
            let mut patterns: Vec<Regex> = builtin_patterns(filter)
                .iter()
                .map(|p| Regex::new(p).expect("built-in WAF pattern compiles"))
                .collect();
            // Custom patterns are appended to every enabled filter
            // category (they are additional signatures the operator
            // chose to add).
            for custom in &waf.custom_patterns {
                if let Ok(re) = Regex::new(custom) {
                    patterns.push(re);
                }
            }
            entries.push(WafFilterEntry { filter, patterns });
        }
        Some(WafGeneration {
            filters: entries,
            max_body_inspect_bytes: waf.max_body_inspect_bytes,
            dry_run: waf.dry_run,
        })
    }

    /// Whether this WAF generation is in dry-run (audit-log-only) mode.
    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// The configured body inspection byte cap (0 = no body inspection).
    pub fn max_body_inspect_bytes(&self) -> u64 {
        self.max_body_inspect_bytes
    }

    /// Inspect a single string value against all enabled filter patterns.
    /// Returns the first match (if any). The `target` and `value` are
    /// used to populate the [`WafMatch`].
    fn inspect_value(&self, target: WafTarget, value: &str) -> Option<WafMatch> {
        for entry in &self.filters {
            for pat in &entry.patterns {
                if pat.is_match(value) {
                    return Some(WafMatch {
                        filter: entry.filter,
                        pattern: pat.as_str().to_string(),
                        target,
                        value_preview: truncate_preview(value),
                    });
                }
            }
        }
        None
    }

    /// Inspect the request head: path, query string, and selected
    /// headers. Returns the first match (if any). Synchronous — no body
    /// access.
    pub fn inspect_head(
        &self,
        path: &str,
        query: Option<&str>,
        headers: &hyper::HeaderMap,
    ) -> Option<WafMatch> {
        // Path (the ORIGINAL request path, before rewrite).
        if let Some(m) = self.inspect_value(WafTarget::Path, path) {
            return Some(m);
        }
        // Query string (raw).
        if let Some(q) = query {
            if let Some(m) = self.inspect_value(WafTarget::Query, q) {
                return Some(m);
            }
        }
        // Selected headers: User-Agent, Referer, Cookie, X-Forwarded-For.
        for name in &["user-agent", "referer", "cookie", "x-forwarded-for"] {
            if let Some(val) = headers.get(*name).and_then(|v| v.to_str().ok()) {
                if let Some(m) = self.inspect_value(WafTarget::Header, val) {
                    return Some(m);
                }
            }
        }
        None
    }

    /// Inspect a buffered body slice. Returns the first match (if any).
    pub fn inspect_body_slice(&self, body: &[u8]) -> Option<WafMatch> {
        // The body is inspected as UTF-8 lossy — patterns match on the
        // decoded text, not raw bytes (the common case for JSON and
        // form-urlencoded bodies).
        let text = String::from_utf8_lossy(body);
        self.inspect_value(WafTarget::Body, &text)
    }
}

/// The headers that signal a body worth inspecting: JSON or
/// form-urlencoded content types.
pub fn should_inspect_body(headers: &hyper::HeaderMap) -> bool {
    if let Some(ct) = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        let ct = ct.to_ascii_lowercase();
        ct.starts_with("application/json")
            || ct.starts_with("application/x-www-form-urlencoded")
            || ct.starts_with("text/plain")
    } else {
        false
    }
}

/// The outcome of body inspection: either a match was found (and the
/// body is reconstructed for forwarding), or no match was found. The
/// reconstructed body is a concrete type so the caller can continue
/// the request path regardless of the original body's type.
pub struct BodyInspectionResult {
    /// The reconstructed body for forwarding (buffered prefix + any
    /// remaining stream). When the body fit within the inspection cap,
    /// this is the full body as `Full<Bytes>`. When the body exceeded
    /// the cap, this is the buffered prefix followed by the remaining
    /// stream via [`WafBody`].
    pub body: WafBody,
    /// The match found during inspection, if any.
    pub match_found: Option<WafMatch>,
}

/// A body that replays buffered bytes (inspected by the WAF) then
/// streams the remaining original body. When the entire body fit within
/// the inspection cap, `rest` is `None` and the body is fully buffered.
pub enum WafBody {
    /// Fully buffered body (fit within the inspection cap).
    Full(Full<Bytes>),
    /// Partially buffered: the inspected prefix followed by the
    /// remaining stream.
    Partial {
        prefix: Bytes,
        rest: Pin<
            Box<dyn Body<Data = Bytes, Error = Box<dyn std::error::Error + Send + Sync>> + Send>,
        >,
    },
}

impl WafBody {
    /// Create a fully-buffered WAF body.
    pub fn full(bytes: Bytes) -> Self {
        WafBody::Full(Full::new(bytes))
    }
}

impl Body for WafBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match this {
            WafBody::Full(b) => Pin::new(b).poll_frame(cx).map_err(|e| match e {}),
            WafBody::Partial { prefix, rest } => {
                if !prefix.is_empty() {
                    let chunk = prefix.clone();
                    *prefix = Bytes::new();
                    return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(chunk))));
                }
                rest.as_mut().poll_frame(cx)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            WafBody::Full(b) => b.is_end_stream(),
            WafBody::Partial { prefix, rest } => prefix.is_empty() && rest.is_end_stream(),
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self {
            WafBody::Full(b) => b.size_hint(),
            WafBody::Partial { prefix, rest } => {
                let mut hint = rest.size_hint();
                if let Some(exact) = hint.exact() {
                    hint.set_exact(exact + prefix.len() as u64);
                }
                hint
            }
        }
    }
}

/// Inspect the request body for WAF signatures. Buffers up to
/// `max_body_inspect_bytes` from the body, runs the pattern match on
/// the buffered slice, and returns the reconstructed body for
/// forwarding. When the body exceeds the cap, only the prefix is
/// inspected (a malicious payload beyond the cap is not caught — the
/// trade-off for a bounded inspection cost).
pub async fn inspect_body<B>(body: B, gen: &WafGeneration) -> BodyInspectionResult
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let cap = gen.max_body_inspect_bytes();
    let mut body = Box::pin(body);
    let mut buf: Vec<u8> = Vec::new();
    let mut exceeded_cap = false;

    loop {
        if cap > 0 && buf.len() as u64 >= cap {
            exceeded_cap = true;
            break;
        }
        match body.frame().await {
            Some(Ok(frame)) => {
                let Ok(data) = frame.into_data() else {
                    continue; // trailer frame: dropped
                };
                if cap > 0 && buf.len() as u64 + data.len() as u64 > cap {
                    // Only buffer up to the cap; the rest stays in the
                    // stream. We take the portion that fits and leave
                    // the remainder in the body.
                    let remaining = cap as usize - buf.len();
                    buf.extend_from_slice(&data[..remaining]);
                    // Re-wrap the unconsumed portion + the rest of the
                    // body into a chain. Since we already consumed this
                    // frame, we need to prepend the unconsumed bytes.
                    let unconsumed = data.slice(remaining..);
                    let rest_body = PrefixedBody {
                        prefix: Some(unconsumed),
                        rest: body,
                    };
                    let match_found = gen.inspect_body_slice(&buf);
                    let body_out = WafBody::Partial {
                        prefix: Bytes::from(buf),
                        rest: Box::pin(rest_body),
                    };
                    return BodyInspectionResult {
                        body: body_out,
                        match_found,
                    };
                }
                buf.extend_from_slice(&data);
            }
            Some(Err(_)) => {
                // Body error: stop inspecting, forward what we have.
                break;
            }
            None => break,
        }
    }

    let match_found = gen.inspect_body_slice(&buf);
    let buffered = Bytes::from(buf);

    let body_out = if exceeded_cap {
        // The body had more data; `body` still holds the remaining
        // stream. We need to forward buffered prefix + rest. The error
        // type is mapped to BoxError for type-erasure.
        WafBody::Partial {
            prefix: buffered,
            rest: Box::pin(body.map_err(|e| e.into())),
        }
    } else {
        // The whole body fit within the cap (or the body ended).
        WafBody::Full(Full::new(buffered))
    };

    BodyInspectionResult {
        body: body_out,
        match_found,
    }
}

/// A body wrapper that yields an optional buffered prefix followed by
/// the remaining stream. Used when the WAF inspection cap is reached
/// mid-frame: the unconsumed portion of the breaking frame is prepended
/// to the rest of the body.
struct PrefixedBody<B: Body> {
    prefix: Option<Bytes>,
    rest: Pin<Box<B>>,
}

impl<B> Body for PrefixedBody<B>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(prefix) = this.prefix.take() {
            if !prefix.is_empty() {
                return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(prefix))));
            }
        }
        this.rest.as_mut().poll_frame(cx).map_err(|e| e.into())
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.as_ref().is_none_or(|p| p.is_empty()) && self.rest.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        let mut hint = self.rest.size_hint();
        if let Some(prefix) = &self.prefix {
            if let Some(exact) = hint.exact() {
                hint.set_exact(exact + prefix.len() as u64);
            }
        }
        hint
    }
}
