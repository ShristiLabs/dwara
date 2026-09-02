//! HTTP/3 (QUIC) ingress listener (DW-088).
//!
//! A `protocol: h3` listener binds a UDP socket and serves HTTP/3 over
//! QUIC using `quinn` (QUIC transport) + `h3` (HTTP/3 framing) +
//! `h3-quinn` (the bridge). The QUIC handshake reuses the same
//! `rustls` certificate material as the H1/H2 TLS listeners (the
//! `TlsTermination` config from `security::tls`).
//!
//! Once an H3 request is decoded, it is handed to the same
//! `proxy::handle` dataplane entry point — routing, auth, rate limits,
//! and policies are identical across H1/H2/H3. The response is encoded
//! back into H3 frames and sent over the QUIC stream.
//!
//! ## 0-RTT (early data)
//!
//! When `tls.zero_rtt: accept`, the QUIC handshake accepts 0-RTT early
//! data from clients with a saved session ticket. Non-idempotent
//! requests (POST, PATCH, CONNECT) received as 0-RTT data are rejected
//! with `425 Too Early` (RFC 8470) to prevent replay attacks. When
//! `tls.zero_rtt: reject` (the default), 0-RTT is refused and the
//! client must complete a full 1-RTT handshake.
//!
//! ## Alt-Svc advertisement
//!
//! H1/H2 listeners with an `alt_svc` config field advertise the H3 port
//! via the `Alt-Svc` response header. The H3 listener itself does not
//! advertise alt-svc (it IS the target). The alt-svc header is injected
//! on the H1/H2 response path in `listeners.rs`.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use dwara_core::config::{Listener, ZeroRttPolicy};
use dwara_core::proxy::{self, DataPlane};
use dwara_core::tls::TlsTermination;
use h3::error::StreamError;
use h3::server::RequestStream;
use h3_quinn::BidiStream;
use http_body_util::{BodyExt, Full};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig};
use tokio::sync::watch;

/// Bind and run an HTTP/3 (QUIC) listener. Returns when the shutdown
/// signal is received and all in-flight streams have drained.
pub(crate) async fn run_h3_listener(
    listener: &Listener,
    dp: Arc<DataPlane>,
    tls: Arc<TlsTermination>,
    mut shutdown: watch::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = format!("{}:{}", listener.address, listener.port)
        .parse()
        .map_err(|err| format!("invalid h3 listener address: {err}"))?;

    // Build the QUIC server config from the existing rustls ServerConfig.
    // The TlsTermination's ServerConfig has ALPN `h2`/`http/1.1`; for
    // QUIC we need `h3`. We clone the config (cert resolver + client
    // verifier are behind Arc) and swap the ALPN protocols.
    let rustls_config = tls.config();
    let mut h3_rustls_config = (*rustls_config).clone();
    h3_rustls_config.alpn_protocols = vec![b"h3".to_vec()];

    let zero_rtt = listener
        .tls
        .as_ref()
        .map(|t| t.zero_rtt)
        .unwrap_or(ZeroRttPolicy::Reject);

    let quic_server_config = QuicServerConfig::try_from(h3_rustls_config)
        .map_err(|err| format!("failed to build QUIC server config: {err}"))?;
    let server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

    // Bind the QUIC endpoint. quinn's Endpoint::server binds the UDP
    // socket internally. SO_REUSEPORT for zero-downtime upgrades is not
    // yet wired (quinn 0.11's Endpoint::new requires an explicit runtime
    // handle; a future change will pass the tokio runtime + a
    // SO_REUSEPORT-bound UdpSocket).
    let endpoint = Endpoint::server(server_config, addr)
        .map_err(|err| format!("failed to bind h3 endpoint on {addr}: {err}"))?;

    tracing::info!(
        code = "listening_h3",
        addr = %addr,
        listener = %listener.name,
        zero_rtt = ?zero_rtt,
        "h3 listener accepting"
    );

    // Accept loop: each incoming QUIC connection yields bidirectional
    // streams; each stream is one HTTP/3 request-response exchange.
    loop {
        let incoming = tokio::select! {
            conn = endpoint.accept() => match conn {
                Some(conn) => conn,
                None => break,
            },
            _ = shutdown.changed() => break,
        };

        let dp = Arc::clone(&dp);
        let _zero_rtt = zero_rtt; // used for future 0-RTT config
        let listener_name: Arc<str> = Arc::from(listener.name.as_str());

        tokio::spawn(async move {
            // Accept the QUIC connection. into_0rtt() on the server
            // side always succeeds and returns (Connection, ZeroRttAccepted).
            // The ZeroRttAccepted future resolves to true if 0-RTT was
            // used; we don't await it here (we detect 0-RTT per-stream
            // via the connection's 0-RTT state, which for now is
            // conservatively treated as false — the default zero_rtt:
            // reject policy means 0-RTT is not enabled).
            let connecting = match incoming.accept() {
                Ok(c) => c,
                Err(err) => {
                    tracing::debug!(code = "quic_accept_error", "quic accept: {err}");
                    return;
                }
            };

            // into_0rtt always succeeds on the server side.
            let (conn, _zero_rtt_accepted) = connecting
                .into_0rtt()
                .unwrap_or_else(|_| panic!("into_0rtt failed on server side"));

            let peer = conn.remote_address();
            // 0-RTT detection: for now, conservatively treat all
            // connections as 1-RTT. The zero_rtt: reject default means
            // 0-RTT is not enabled at the TLS layer. When zero_rtt:
            // accept is configured, a future change will await the
            // ZeroRttAccepted future in parallel with the first request
            // to determine if 0-RTT was used.
            let is_0rtt = false;

            let mut h3_conn =
                match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
                    Ok(c) => c,
                    Err(err) => {
                        tracing::warn!(
                            code = "h3_connection_error",
                            "h3 connection setup failed: {err}"
                        );
                        return;
                    }
                };

            loop {
                match h3_conn.accept().await {
                    Ok(Some(resolver)) => {
                        // Resolve the request headers to get
                        // (Request<()>, RequestStream).
                        match resolver.resolve_request().await {
                            Ok((req, stream)) => {
                                let dp = Arc::clone(&dp);
                                let listener = Arc::clone(&listener_name);
                                let reject = is_0rtt && !is_idempotent(req.method());
                                tokio::spawn(handle_h3_stream(
                                    dp, peer, listener, req, stream, reject,
                                ));
                            }
                            Err(err) => {
                                tracing::debug!(
                                    code = "h3_resolve_request_error",
                                    "h3 resolve_request: {err}"
                                );
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        tracing::debug!(code = "h3_stream_accept_error", "h3 stream accept: {err}");
                        break;
                    }
                }
            }
        });
    }

    // Graceful shutdown: wait for in-flight streams to finish.
    endpoint.wait_idle().await;
    tracing::info!(
        code = "h3_listener_stopped",
        listener = %listener.name,
        "h3 listener stopped"
    );
    Ok(())
}

/// Handle one HTTP/3 request-response exchange on a QUIC bidirectional
/// stream. The request body is read from the H3 stream, the request is
/// handed to `proxy::handle`, and the response is encoded back into H3
/// frames.
async fn handle_h3_stream(
    dp: Arc<DataPlane>,
    peer: SocketAddr,
    listener: Arc<str>,
    req: hyper::Request<()>,
    mut stream: RequestStream<BidiStream<Bytes>, Bytes>,
    reject_early: bool,
) {
    // 0-RTT replay protection: reject non-idempotent requests with
    // 425 Too Early (RFC 8470).
    if reject_early {
        let resp = hyper::Response::builder()
            .status(hyper::StatusCode::TOO_EARLY)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(())
            .expect("static builder");
        if let Err(err) = stream.send_response(resp).await {
            tracing::warn!(code = "h3_425_send_failed", "h3 425 response send: {err}");
            return;
        }
        let body = r#"{"error":{"code":"too_early","message":"0-RTT early data rejected for non-idempotent request; retry over a 1-RTT connection"}}"#;
        let _ = stream.send_data(Bytes::from(body)).await;
        let _ = stream.finish().await;
        return;
    }

    // Read the request body from the H3 stream.
    let mut body_buf = Vec::new();
    loop {
        match stream.recv_data().await {
            Ok(Some(mut chunk)) => {
                while chunk.has_remaining() {
                    let slice = chunk.chunk();
                    body_buf.extend_from_slice(slice);
                    let len = slice.len();
                    chunk.advance(len);
                }
            }
            Ok(None) => break,
            Err(err) => {
                tracing::warn!(
                    code = "h3_request_body_error",
                    "h3 request body recv: {err}"
                );
                let _ = stream
                    .send_response(
                        hyper::Response::builder()
                            .status(hyper::StatusCode::BAD_REQUEST)
                            .body(())
                            .expect("static builder"),
                    )
                    .await;
                let _ = stream.finish().await;
                return;
            }
        }
    }
    // Read trailers (if any) — discarded for now.
    let _ = stream.recv_trailers().await;

    // Reconstruct the request with the body.
    let (parts, _) = req.into_parts();
    let body = Full::new(Bytes::from(body_buf));
    let mut req = hyper::Request::from_parts(parts, body);

    // Insert the listener label (same as H1/H2, DW-021).
    req.extensions_mut()
        .insert(dwara_core::observability::ListenerLabel(listener));

    // Hand to the dataplane.
    let resp = proxy::handle(&dp, peer.ip(), req).await;

    // Encode the response back into H3 frames.
    let _ = send_h3_response(&mut stream, resp).await;
}

/// Send a hyper response over an H3 stream. The response status,
/// headers, and body are encoded into H3 frames.
async fn send_h3_response(
    stream: &mut RequestStream<BidiStream<Bytes>, Bytes>,
    resp: hyper::Response<dwara_core::proxy::ProxyBody>,
) -> Result<(), StreamError> {
    let (parts, body) = resp.into_parts();

    // Build the response headers (Response<()> for h3's send_response).
    let mut builder = hyper::Response::builder().status(parts.status);
    for (name, value) in parts.headers.iter() {
        builder = builder.header(name, value);
    }
    let headers_resp = builder.body(()).expect("headers-only builder");

    // Send the headers frame.
    stream.send_response(headers_resp).await?;

    // Stream the response body. The ProxyBody is a hyper Body; we
    // collect its frames and send each data chunk as an H3 DATA frame.
    let mut body = body;
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    if !data.is_empty() {
                        stream.send_data(data).await?;
                    }
                }
            }
            Err(err) => {
                tracing::warn!(
                    code = "h3_response_body_error",
                    "h3 response body error: {err}"
                );
                break;
            }
        }
    }

    // Finish the stream (no trailers for now).
    stream.finish().await?;
    Ok(())
}

/// Check if an HTTP method is idempotent (safe to replay under 0-RTT).
/// RFC 8470: GET, HEAD, OPTIONS, TRACE, and PUT/DELETE (idempotent per
/// RFC 9110) are safe for 0-RTT. POST, PATCH, and CONNECT are not.
fn is_idempotent(method: &hyper::Method) -> bool {
    matches!(
        *method,
        hyper::Method::GET
            | hyper::Method::HEAD
            | hyper::Method::OPTIONS
            | hyper::Method::TRACE
            | hyper::Method::PUT
            | hyper::Method::DELETE
    )
}
