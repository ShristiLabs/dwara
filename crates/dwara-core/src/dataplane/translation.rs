//! Protocol translation framework (DW-100).
//!
//! The gateway can sit between clients and upstreams that speak different
//! protocols and translate the request and response bodies on the fly.
//! This module defines the shared, protocol-agnostic seam every
//! translator implements: the [`ProtocolTranslator`] trait, the
//! [`TranslatedRequest`] / [`TranslatedResponse`] carrying the converted
//! bytes, the [`TranslationError`] enum, and a [`TranslationRegistry`]
//! that maps content-type pairs to translators.
//!
//! ## Translators
//!
//! Three translators ship behind two cargo features:
//!
//! - **REST <-> gRPC** (DW-101, shared): the gRPC-Web transcoding engine
//!   in [`super::grpc_web`] already translates JSON <-> protobuf; this
//!   feature reuses it through the shared trait. Compiled under
//!   `protocol_translation` (which implies `grpc_web`).
//! - **REST <-> GraphQL** ([`super::translation_graphql`]): translates a
//!   REST JSON body to a GraphQL query using a config-supplied query
//!   template, and a GraphQL response back to a REST JSON body. Compiled
//!   under `protocol_translation`.
//! - **SOAP/XML** ([`super::translation_soap`]): translates SOAP XML
//!   envelopes to REST JSON and back, using a minimal hand-rolled XML
//!   parser (no external XML crate, to avoid deny.toml review and binary
//!   size). Compiled under the separate `soap` feature.
//!
//! ## Why a shared trait
//!
//! Every translator does the same two things on a route: convert the
//! inbound request body to the upstream's wire format, and convert the
//! upstream's response body back to the client's wire format. Factoring
//! that into one trait lets the dataplane dispatch by content-type pair
//! through a single registry, and lets a new translator (e.g. a future
//! Thrift or AMQP bridge) plug in without touching the request path.
//!
//! ## Feature gating
//!
//! This module compiles only when the `protocol_translation` cargo
//! feature is enabled. The config schema (`Translation`,
//! `TranslationKind`, `GraphqlTranslation`, `SoapTranslation`) is always
//! present so configs round-trip without the feature; when the feature
//! is off the block is accepted but inert (validation warns, the runtime
//! translation does not run). The SOAP translator is further gated
//! behind the `soap` feature for binary size.

#![cfg(feature = "protocol_translation")]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::Frame;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};

// ---------------------------------------------------------------------------
// Body type
// ---------------------------------------------------------------------------

/// A complete, buffered body used by the translation seam.
///
/// The [`ProtocolTranslator`] trait is synchronous: a translator reads
/// the inbound body and writes the converted body in one pass, with no
/// streaming. This type wraps a [`Bytes`] buffer and implements
/// [`hyper::body::Body`] so a translated body can be handed to the rest
/// of the dataplane (which speaks the `Body` trait). The bytes are
/// exposed synchronously via [`as_bytes`] / [`into_bytes`] so the
/// translators do not need to await a body collection.
///
/// [`as_bytes`]: TranslationBody::as_bytes
/// [`into_bytes`]: TranslationBody::into_bytes
#[derive(Debug, Clone, Default)]
pub struct TranslationBody(Bytes);

impl TranslationBody {
    /// Wrap a buffer into a translation body.
    pub fn new(bytes: Bytes) -> Self {
        TranslationBody(bytes)
    }

    /// An empty body.
    pub fn empty() -> Self {
        TranslationBody(Bytes::new())
    }

    /// The buffered bytes, borrowed.
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// The buffered bytes, owned.
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl hyper::body::Body for TranslationBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.0.is_empty() {
            return Poll::Ready(None);
        }
        // Yield the entire buffer in one frame and drain it so the next
        // poll reports end-of-stream. A translator body is fully
        // buffered, so one frame is the correct framing.
        let chunk = std::mem::take(&mut this.0);
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_empty()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        let mut hint = hyper::body::SizeHint::new();
        hint.set_exact(self.0.len() as u64);
        hint
    }
}

// ---------------------------------------------------------------------------
// Translated request / response
// ---------------------------------------------------------------------------

/// The converted request to send upstream: the method, path, headers,
/// and body the translator produced from the inbound request.
#[derive(Debug, Clone)]
pub struct TranslatedRequest {
    /// The HTTP method to send upstream (a GraphQL upstream expects POST;
    /// a gRPC upstream expects POST; a SOAP upstream expects POST).
    pub method: Method,
    /// The path to send upstream (the translator may rewrite it, e.g. a
    /// REST-to-GraphQL translator points every request at `/graphql`).
    pub path: String,
    /// The headers to send upstream. The translator sets the
    /// `Content-Type` to [`ProtocolTranslator::content_type_out`]; the
    /// caller merges these with the route's forwarded headers.
    pub headers: HeaderMap,
    /// The converted body bytes.
    pub body: Bytes,
}

/// The converted response to send the client: the status, headers, and
/// body the translator produced from the upstream response.
#[derive(Debug, Clone)]
pub struct TranslatedResponse {
    /// The HTTP status to send the client.
    pub status: StatusCode,
    /// The headers to send the client. The translator sets the
    /// `Content-Type` to [`ProtocolTranslator::content_type_in`].
    pub headers: HeaderMap,
    /// The converted body bytes.
    pub body: Bytes,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from protocol translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranslationError {
    /// The inbound body could not be parsed (malformed JSON, malformed
    /// XML, a SOAP envelope without a Body, etc.).
    InvalidBody(String),
    /// The referenced schema/template/descriptor was not found (e.g. a
    /// GraphQL translation without a query template, or a gRPC method
    /// not in the loaded descriptors).
    SchemaNotFound(String),
    /// The translation itself failed (a template variable the request
    /// body did not supply, an XML element the converter could not map,
    /// etc.).
    TranslationFailed(String),
}

impl std::fmt::Display for TranslationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TranslationError::InvalidBody(m) => {
                write!(f, "invalid body for translation: {m}")
            }
            TranslationError::SchemaNotFound(m) => {
                write!(f, "schema not found for translation: {m}")
            }
            TranslationError::TranslationFailed(m) => {
                write!(f, "translation failed: {m}")
            }
        }
    }
}

impl std::error::Error for TranslationError {}

// ---------------------------------------------------------------------------
// ProtocolTranslator trait
// ---------------------------------------------------------------------------

/// Translate a request/response pair between two wire protocols.
///
/// A translator is constructed at config publish from a route's
/// `translation` block and held by the request path for the duration of
/// one request. [`translate_request`] converts the inbound request body
/// to the upstream's wire format; [`translate_response`] converts the
/// upstream's response body back to the client's wire format.
/// [`content_type_in`] is the media type the client sends (and expects
/// back); [`content_type_out`] is the media type the upstream expects
/// (and sends back).
///
/// The trait is synchronous and operates on fully-buffered bodies
/// ([`TranslationBody`]): protocol translation is an explicitly buffering
/// step (the same posture as the DW-028 body transform and the DW-061
/// aggregation plugin), never a tax on the zero-buffering proxy path.
/// A route that configures translation opts its requests into the
/// buffer-and-convert path; a route without the block streams untouched.
///
/// [`translate_request`]: ProtocolTranslator::translate_request
/// [`translate_response`]: ProtocolTranslator::translate_response
/// [`content_type_in`]: ProtocolTranslator::content_type_in
/// [`content_type_out`]: ProtocolTranslator::content_type_out
pub trait ProtocolTranslator: Send + Sync {
    /// Convert the inbound request to the upstream's wire format. The
    /// translator reads `req`'s body (via [`TranslationBody::as_bytes`])
    /// and returns the converted method, path, headers, and body to
    /// send upstream.
    fn translate_request(
        &self,
        req: &Request<TranslationBody>,
    ) -> Result<TranslatedRequest, TranslationError>;

    /// Convert the upstream response to the client's wire format. The
    /// translator reads `resp`'s body and returns the converted status,
    /// headers, and body to send the client.
    fn translate_response(
        &self,
        resp: &Response<TranslationBody>,
    ) -> Result<TranslatedResponse, TranslationError>;

    /// The media type the CLIENT sends and expects back (e.g.
    /// `application/json` for a REST client, `text/xml` for a SOAP
    /// client).
    fn content_type_in(&self) -> &str;

    /// The media type the UPSTREAM expects and sends back (e.g.
    /// `application/graphql` for a GraphQL upstream, `application/xml`
    /// for a SOAP upstream, `application/grpc` for a gRPC upstream).
    fn content_type_out(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// A registry of protocol translators keyed by the (in, out) content-type
/// pair. Built at config publish; held behind an `Arc` by the request
/// path. A route's `translation.kind` resolves to one entry here.
#[derive(Clone, Default)]
pub struct TranslationRegistry {
    /// `(content_type_in, content_type_out)` -> translator.
    entries: HashMap<(String, String), Arc<dyn ProtocolTranslator>>,
}

impl std::fmt::Debug for TranslationRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The trait object is not Debug, so report the registered
        // content-type pairs instead of the translators themselves.
        f.debug_struct("TranslationRegistry")
            .field("pairs", &self.entries.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl TranslationRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        TranslationRegistry {
            entries: HashMap::new(),
        }
    }

    /// Register a translator for a content-type pair. The pair is
    /// normalized to lowercase (media types are case-insensitive).
    pub fn register(
        &mut self,
        content_type_in: &str,
        content_type_out: &str,
        translator: Arc<dyn ProtocolTranslator>,
    ) {
        let key = (
            content_type_in.to_ascii_lowercase(),
            content_type_out.to_ascii_lowercase(),
        );
        self.entries.insert(key, translator);
    }

    /// Look up the translator for a content-type pair. Matching is
    /// case-insensitive on both media types.
    pub fn get(
        &self,
        content_type_in: &str,
        content_type_out: &str,
    ) -> Option<Arc<dyn ProtocolTranslator>> {
        let key = (
            content_type_in.to_ascii_lowercase(),
            content_type_out.to_ascii_lowercase(),
        );
        self.entries.get(&key).cloned()
    }

    /// The number of registered translators.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
