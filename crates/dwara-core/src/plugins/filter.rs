//! The native filter trait and its shared outcome/response types (DW-119).
//!
//! [`NativeFilter`] is a dyn-compatible trait mirroring the proxy-wasm
//! host's phase contract. A compiled-in Rust filter implements it and
//! registers a factory with [`super::NativeRegistry`]; the unified
//! [`super::PluginChain`] dispatches to it at the phases the filter's
//! config declares, exactly as it dispatches to a WASM plugin instance.
//!
//! [`LocalResponse`] lives here (in the `plugins` domain) because it is
//! the shared short-circuit shape both native filters and WASM plugins
//! produce. The `wasm` host re-exports its own [`wasm::host::LocalResponse`]
//! (defined before this domain existed); the two are structurally
//! identical and converted at the dispatch boundary by the `wasm`
//! adapter. Keeping the canonical type in the lower `plugins` domain
//! avoids an upward dependency from `plugins` to `wasm`.

use std::fmt;

/// A local response short-circuiting the request pipeline.
///
/// Produced by a native filter via [`FilterOutcome::LocalResponse`] or
/// by a WASM plugin via `proxy_send_http_response`. The proxy returns
/// this response immediately, skipping all subsequent phases and the
/// upstream. Structurally identical to `wasm::host::LocalResponse`; the
/// `wasm` adapter converts between the two at the dispatch boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalResponse {
    /// HTTP status code (e.g. 403, 200).
    pub status: u16,
    /// Response headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// The outcome of a native filter phase callback.
///
/// Mirrors `wasm::runner::PhaseOutcome` so a native filter and a WASM
/// plugin are interchangeable in the unified chain:
///
/// - [`FilterOutcome::Continue`] -- proceed to the next plugin/phase.
///   The (possibly modified) headers/body are threaded through.
/// - [`FilterOutcome::LocalResponse`] -- short-circuit with a local
///   response; the proxy returns it immediately.
/// - [`FilterOutcome::Error`] -- the filter failed (the proxy returns a
///   500, mirroring a WASM trap). The message is logged and never
///   leaked to the client.
#[derive(Clone, Debug)]
pub enum FilterOutcome {
    /// Continue processing. The headers/body passed in (possibly
    /// modified by the filter) are returned to the chain.
    Continue {
        /// The (possibly modified) headers (request_headers /
        /// response_headers phases) or empty for body phases.
        headers: Vec<(String, String)>,
        /// The (possibly modified) body (request_body / response_body
        /// phases) or empty for header phases.
        body: Vec<u8>,
    },
    /// Short-circuit with a local response.
    LocalResponse(LocalResponse),
    /// The filter errored. The proxy returns a 500 (mirroring a WASM
    /// trap); the message is logged, never sent to the client.
    Error(String),
}

/// A compile-in native filter (DW-119).
///
/// A dyn-compatible trait mirroring the proxy-wasm host's phase
/// callbacks. Each method receives the current headers/body by value
/// and returns a [`FilterOutcome`]. The methods are synchronous,
/// matching the WASM runner's synchronous phase methods -- the proxy
/// calls them synchronously per phase. A filter that does not hook a
/// phase returns [`FilterOutcome::Continue`] with the input unchanged.
///
/// Implementations are registered by name via
/// [`super::NativeRegistry::register`] with a
/// [`super::NativeFilterFactory`]; config selects a native filter with
/// `native: <name>` on a [`crate::config::PluginConfig`].
pub trait NativeFilter: Send + Sync {
    /// `request_headers` phase -- after route resolution, before authn.
    /// Receives the request headers; returns the outcome and the
    /// (possibly modified) headers.
    fn on_request_headers(&mut self, headers: Vec<(String, String)>) -> FilterOutcome {
        FilterOutcome::Continue {
            headers,
            body: Vec::new(),
        }
    }

    /// `request_body` phase -- after authn/authz/rate-limit, before
    /// upstream. Receives the request body; returns the outcome and the
    /// (possibly modified) body.
    fn on_request_body(&mut self, body: Vec<u8>) -> FilterOutcome {
        FilterOutcome::Continue {
            headers: Vec::new(),
            body,
        }
    }

    /// `response_headers` phase -- after the upstream responds, before
    /// masking. Receives the response headers; returns the outcome and
    /// the (possibly modified) headers.
    fn on_response_headers(&mut self, headers: Vec<(String, String)>) -> FilterOutcome {
        FilterOutcome::Continue {
            headers,
            body: Vec::new(),
        }
    }

    /// `response_body` phase -- after masking, before compression.
    /// Receives the response body; returns the outcome and the
    /// (possibly modified) body.
    fn on_response_body(&mut self, body: Vec<u8>) -> FilterOutcome {
        FilterOutcome::Continue {
            headers: Vec::new(),
            body,
        }
    }
}

impl fmt::Debug for dyn NativeFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeFilter")
    }
}
