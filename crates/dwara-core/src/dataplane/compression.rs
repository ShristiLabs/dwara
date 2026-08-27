//! Route-scoped response compression (DW-027, feature analysis 4.13).
//!
//! One [`Compression`] policy per route drives two steps:
//!
//! - **Negotiation** ([`negotiate`]): the first algorithm of the
//!   policy's preference order the request's `Accept-Encoding` accepts
//!   wins. `q=0` codings are treated as refusal; `*` accepts any. No
//!   acceptable overlap means no compression (identity is always
//!   permitted; the gateway never answers 406 over compression).
//! - **Encoding** ([`wrap_response`]): the response body is wrapped in
//!   [`CompressedBody`], which compresses CHUNK-BY-CHUNK — every data
//!   frame is written through the codec and flushed, and whatever the
//!   codec produced is forwarded as the next frame. The gateway never
//!   buffers a whole body to compress it; the only buffering is the
//!   codec's own bounded working set plus the not-yet-emitted output of
//!   the current chunk. Per-chunk flushing costs a little ratio and
//!   buys streaming correctness: a slow/trickling upstream (SSE)
//!   reaches the client per chunk instead of at end-of-stream.
//!   Content types that must not be delayed (e.g. `text/event-stream`)
//!   are the operator's call via `excluded_content_types`.
//!
//! Response eligibility (see [`decide`]): never a 1xx/204/304, never a
//! 101 upgrade, never a body that already carries `Content-Encoding`,
//! never a zero length, never below `min_size` when the size is known
//! (declared `Content-Length` or the exact size of the gateway's own
//! header-less bodies; unknown-length streams are always candidates).
//! `Content-Length` is dropped on compression (the encoded
//! length differs; framing switches to chunked/streamed), and
//! `Content-Encoding: <token>` plus `Vary: Accept-Encoding` (merged into
//! any existing `Vary`) are set. `Vary` is ALSO added to responses that
//! were candidates but skipped (too small, wrong content type, no
//! acceptable coding) so shared caches key them correctly alongside
//! their compressed siblings — the proxy handles that half.
//!
//! The three codecs are Write-based streaming encoders (flate2 gzip,
//! brotli, zstd) all draining into one shared output sink the wrapper reads
//! compressed bytes back out of; each carries the per-algorithm level
//! clamp (gzip 0-9, brotli 0-11, zstd 0-22; defaults 6/5/3 — zstd 3 and
//! brotli 5 sit at the fast end of their useful range, the right bias
//! for a per-route default on a hot proxy path).

use std::collections::BTreeSet;
use std::io::Write as _;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::Frame;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Response, StatusCode};

use crate::config::{CompiledContentTypeFilter, Compression, CompressionAlgorithm};
use crate::dataplane::hardening::merge_vary;
use crate::dataplane::proxy::{ProxyBody, ProxyBodyError};

/// Shared output sink the codecs write into and [`CompressedBody`]
/// drains compressed bytes out of. The handle is cheap to clone (the
/// encoder holds one, the wrapper another); `Arc<Mutex<Vec<u8>>>` keeps
/// the wrapper `Send` while the encoder owns its clone writing into it.
type Sink = Arc<Mutex<Vec<u8>>>;

/// The `io::Write` view of a [`Sink`] the encoders hold.
#[derive(Clone)]
struct SinkWriter(Sink);

impl std::io::Write for SinkWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn drain(sink: &Sink) -> Vec<u8> {
    std::mem::take(&mut *sink.lock().unwrap_or_else(|p| p.into_inner()))
}

/// The negotiated coding for one response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionPlan {
    pub algorithm: CompressionAlgorithm,
    /// Effective level AFTER the per-algorithm clamp.
    pub level: u8,
}

/// Per-algorithm default level (see the module docs for the rationale).
fn default_level(algorithm: CompressionAlgorithm) -> u8 {
    match algorithm {
        CompressionAlgorithm::Gzip => 6,
        CompressionAlgorithm::Brotli => 5,
        CompressionAlgorithm::Zstd => 3,
    }
}

/// Per-algorithm maximum level (validation bounds the field to 0-22;
/// the clamp happens here so a single config level works across
/// algorithms with different ranges).
fn max_level(algorithm: CompressionAlgorithm) -> u8 {
    match algorithm {
        CompressionAlgorithm::Gzip => 9,
        CompressionAlgorithm::Brotli => 11,
        CompressionAlgorithm::Zstd => 22,
    }
}

/// Which codings an `Accept-Encoding` value accepts (DW-027). `*`
/// accepts everything; `q=0` excludes a coding; anything not listed is
/// not accepted (identity is always fine and is what "no compression"
/// answers with). Header absent = nothing but identity.
struct AcceptedEncodings {
    any: bool,
    codings: BTreeSet<String>,
}

fn accepted_encodings(accept: Option<&str>) -> AcceptedEncodings {
    let mut out = AcceptedEncodings {
        any: false,
        codings: BTreeSet::new(),
    };
    let Some(accept) = accept else {
        return out;
    };
    for entry in accept.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (token, params) = match entry.split_once(';') {
            Some((t, p)) => (t.trim(), p),
            None => (entry, ""),
        };
        // q=0 (or 0.0...) is an explicit refusal; any other q (or none)
        // accepts. Parameters other than q are ignored per RFC 9110.
        let refused = params
            .split(';')
            .map(|p| p.trim())
            .find_map(|p| p.strip_prefix("q=").map(|q| q.trim().to_lowercase()))
            .and_then(|q| q.parse::<f32>().ok())
            .is_some_and(|q| q == 0.0);
        if refused {
            continue;
        }
        let token = token.to_lowercase();
        if token == "*" {
            out.any = true;
        } else {
            out.codings.insert(token);
        }
    }
    out
}

/// Negotiate the coding for one response (DW-027): the first policy
/// algorithm the request accepts wins; `None` = serve identity.
pub fn negotiate(policy: &Compression, accept: Option<&str>) -> Option<CompressionPlan> {
    let accepted = accepted_encodings(accept);
    let requested = policy.level.unwrap_or(0);
    policy
        .algorithms
        .iter()
        .copied()
        .find(|a| accepted.any || accepted.codings.contains(a.encoding_token()))
        .map(|algorithm| CompressionPlan {
            algorithm,
            level: if policy.level.is_some() {
                requested.min(max_level(algorithm))
            } else {
                default_level(algorithm)
            },
        })
}

/// The response's `Content-Type` reduced to its lowercase media type
/// (parameters stripped) for prefix matching. Absent or non-UTF-8
/// collapses to the empty string, which the compiled filter treats as
/// "no type signal" — compressible under an empty include list, never
/// matching a specific prefix (the same reading the header-based check
/// had).
fn media_type(headers: &HeaderMap) -> String {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_lowercase()
}

/// Decide whether THIS response gets compressed under the policy
/// (DW-027): status, existing encoding, known size, content type, and
/// negotiation all have to line up. `None` = pass through (the caller
/// still adds `Vary: Accept-Encoding` for cache correctness).
///
/// `types` is the policy's snapshot-compiled content-type filter (see
/// [`crate::snapshot::RouteTable::compression_types`]); `body_size` is
/// the response body's exact size when known (`size_hint().exact()` —
/// exact for the gateway's fully-buffered bodies) so `min_size` gates
/// bodies that carry no `Content-Length` header too (respond-action
/// and redirect bodies). `None` = length unknown (streaming).
pub fn decide(
    policy: &Compression,
    types: &CompiledContentTypeFilter,
    status: StatusCode,
    headers: &HeaderMap,
    body_size: Option<u64>,
    accept_encoding: Option<&str>,
) -> Option<CompressionPlan> {
    // 1xx carry no body; 204/304 are body-less by definition. 101 is a
    // protocol switch (the body becomes the tunneled connection).
    if status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || status == StatusCode::SWITCHING_PROTOCOLS
    {
        return None;
    }
    // Already-encoded bodies pass through untouched (double-compressing
    // a jpeg grows it and corrupts content negotiation).
    if headers.contains_key(hyper::header::CONTENT_ENCODING) {
        return None;
    }
    // Size gate: `min_size` applies whenever the size is KNOWN — the
    // declared `Content-Length`, or the exact size hint for bodies that
    // carry no header (the gateway's own respond/redirect bodies; a
    // ~23-byte gzip container around an empty 302 helps nobody). A
    // present-but-unparsable length is untrustworthy: do not compress.
    let known_size = match headers.get(hyper::header::CONTENT_LENGTH) {
        Some(len) => Some(len.to_str().ok()?.trim().parse::<u64>().ok()?),
        None => body_size,
    };
    if known_size.is_some_and(|len| len == 0 || len < policy.min_size) {
        return None;
    }
    if !types.allows(&media_type(headers)) {
        return None;
    }
    negotiate(policy, accept_encoding)
}

/// Apply a plan to a response (DW-027): header rewrite + body wrap.
/// `Content-Length` is removed (the encoded length differs); the
/// encoding token and `Vary: Accept-Encoding` are set.
pub fn wrap_response(resp: Response<ProxyBody>, plan: &CompressionPlan) -> Response<ProxyBody> {
    let (mut parts, body) = resp.into_parts();
    parts.headers.remove(hyper::header::CONTENT_LENGTH);
    if let Ok(v) = HeaderValue::from_str(plan.algorithm.encoding_token()) {
        parts.headers.insert(hyper::header::CONTENT_ENCODING, v);
    }
    merge_vary(&mut parts.headers, "Accept-Encoding");
    Response::from_parts(
        parts,
        ProxyBody::Compressed(Box::new(CompressedBody::new(body, *plan))),
    )
}

/// One of the three Write-based streaming codecs (DW-027). `write_chunk`
/// pushes input through the codec with a flush (a sync-flush point for
/// gzip/brotli, a block flush for zstd) so output is drainable per
/// chunk; `finish` completes the stream (gzip trailer, brotli final
/// block, zstd frame end).
enum Encoder {
    Gzip(flate2::write::GzEncoder<SinkWriter>),
    Brotli(Box<brotli::CompressorWriter<SinkWriter>>),
    Zstd(zstd::Encoder<'static, SinkWriter>),
}

impl Encoder {
    fn new(plan: &CompressionPlan, sink: SinkWriter) -> Self {
        match plan.algorithm {
            CompressionAlgorithm::Gzip => Encoder::Gzip(flate2::write::GzEncoder::new(
                sink,
                flate2::Compression::new(plan.level as u32),
            )),
            CompressionAlgorithm::Brotli => Encoder::Brotli(Box::new(
                brotli::CompressorWriter::new(sink, 4096, plan.level as u32, 22),
            )),
            CompressionAlgorithm::Zstd => Encoder::Zstd(
                zstd::Encoder::new(sink, plan.level as i32)
                    .expect("zstd level is clamped to the valid range at construction"),
            ),
        }
    }

    fn write_chunk(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Encoder::Gzip(e) => {
                e.write_all(data)?;
                e.flush()
            }
            Encoder::Brotli(e) => {
                e.write_all(data)?;
                e.flush()
            }
            Encoder::Zstd(e) => {
                e.write_all(data)?;
                e.flush()
            }
        }
    }

    /// Complete the stream; final bytes land in the sink. The brotli
    /// `into_inner` swallows codec errors (the sink is a Vec — its IO
    /// cannot fail; a codec-side failure is unreachable in practice and
    /// would surface as a truncated stream either way).
    fn finish(self) {
        match self {
            Encoder::Gzip(e) => {
                let _ = e.finish();
            }
            Encoder::Brotli(e) => {
                let _ = e.into_inner();
            }
            Encoder::Zstd(e) => {
                let _ = e.finish();
            }
        }
    }
}

/// Compressing wrapper over a [`ProxyBody`] (DW-027). Streams: every
/// inner data frame goes through the codec and comes back as (at most)
/// one emitted frame of pending output; the codec is finished when the
/// inner stream ends, and any trailing headers observed on the inner
/// stream are re-emitted AFTER the compressed bytes (trailers ride
/// after the body; compression does not touch them).
pub struct CompressedBody {
    inner: Pin<Box<ProxyBody>>,
    encoder: Option<Box<Encoder>>,
    sink: Sink,
    /// Compressed bytes not yet emitted to the client.
    pending: Vec<u8>,
    /// Trailers seen on the inner stream, deferred until the compressed
    /// bytes have been emitted.
    trailer: Option<HeaderMap>,
    inner_done: bool,
    finished: bool,
}

impl CompressedBody {
    fn new(inner: ProxyBody, plan: CompressionPlan) -> Self {
        let sink: Sink = Arc::new(Mutex::new(Vec::new()));
        CompressedBody {
            inner: Box::pin(inner),
            encoder: Some(Box::new(Encoder::new(&plan, SinkWriter(Arc::clone(&sink))))),
            sink,
            pending: Vec::new(),
            trailer: None,
            inner_done: false,
            finished: false,
        }
    }
}

impl hyper::body::Body for CompressedBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, ProxyBodyError>>> {
        let this = self.get_mut();
        loop {
            if !this.pending.is_empty() {
                let chunk = std::mem::take(&mut this.pending);
                return Poll::Ready(Some(Ok(Frame::data(Bytes::from(chunk)))));
            }
            if this.inner_done {
                // Finish the codec BEFORE any trailers frame: the final
                // gzip/brotli/zstd tail bytes must drain as DATA frames
                // ahead of the trailers (h2 upstreams deliver trailers;
                // data-after-trailers is a framing violation that tears
                // the stream). The pending-drain at the top of the loop
                // emits those bytes; the trailers frame goes out only
                // once finished AND fully drained.
                if !this.finished {
                    if let Some(encoder) = this.encoder.take() {
                        encoder.finish();
                    }
                    this.pending = drain(&this.sink);
                    this.finished = true;
                    continue;
                }
                if let Some(trailer) = this.trailer.take() {
                    return Poll::Ready(Some(Ok(Frame::trailers(trailer))));
                }
                return Poll::Ready(None);
            }
            match this.inner.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        if let Some(encoder) = this.encoder.as_deref_mut() {
                            if let Err(e) = encoder.write_chunk(data) {
                                return Poll::Ready(Some(Err(ProxyBodyError::Io(e))));
                            }
                        }
                        this.pending = drain(&this.sink);
                    } else if let Ok(trailer) = frame.into_trailers() {
                        this.trailer = Some(trailer);
                        this.inner_done = true;
                    }
                    // Other frame kinds (none exist on this path today)
                    // are dropped; the compressed stream is the body.
                    continue;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    this.inner_done = true;
                    continue;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner_done && self.finished && self.pending.is_empty() && self.trailer.is_none()
    }
}

impl std::fmt::Debug for CompressedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompressedBody")
            .field("inner_done", &self.inner_done)
            .field("finished", &self.finished)
            .field("pending_bytes", &self.pending.len())
            .finish_non_exhaustive()
    }
}
