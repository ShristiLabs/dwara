//! Unit tests for `dataplane::hardening` (relocated from src).

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::BodyExt as _;
use http_body_util::Full;
use hyper::body::Body;
use hyper::body::Bytes;
use hyper::body::Frame as BodyFrame;

use dwara_core::dataplane::hardening::*;

/// Minimal channel-driven body: `next_frame` pulls from a shared queue
/// the test fills on its own schedule (the stream stays Pending until a
/// frame is pushed), which is exactly what a slow client looks like.
struct SlowBody {
    frames: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
}

impl Body for SlowBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<BodyFrame<Bytes>, Infallible>>> {
        self.get_mut()
            .frames
            .poll_recv(cx)
            .map(|maybe: Option<Bytes>| {
                maybe.map(|b| Ok::<_, Infallible>(BodyFrame::data(Bytes::from(b.to_vec()))))
            })
    }
}

#[test]
fn defaults_match_documented_table() {
    let h = HttpHardening::default();
    assert_eq!(h.http1_max_headers, 100);
    assert_eq!(h.http1_max_buf_size, 64 * 1024);
    assert_eq!(h.http1_header_read_timeout, Duration::from_secs(10));
    assert_eq!(h.h2_max_concurrent_streams, 128);
    assert_eq!(h.h2_initial_stream_window, 1024 * 1024);
    assert_eq!(h.h2_initial_connection_window, 4 * 1024 * 1024);
    assert_eq!(h.h2_max_send_buf_size, 1024 * 1024);
    assert_eq!(h.request_body_gap, Some(Duration::from_secs(30)));
}

#[tokio::test]
async fn body_gap_timeout_fires_between_frames() {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
    let hardening = HttpHardening {
        request_body_gap: Some(Duration::from_millis(100)),
        ..HttpHardening::default()
    };
    let body = hardening.wrap_request_body(SlowBody { frames: rx });
    tx.send(Bytes::from(&b"first"[..])).unwrap();
    let mut body = std::pin::pin!(body);
    let first = body
        .frame()
        .await
        .expect("first frame arrives")
        .expect("first frame is ok");
    assert_eq!(&first.data_ref().unwrap()[..], b"first");
    // No second frame: the gap timeout must fire.
    let started = std::time::Instant::now();
    let err = body
        .frame()
        .await
        .expect("stream ends")
        .expect_err("times out");
    match err {
        InboundBodyError::Timeout { after } => {
            assert_eq!(after, Duration::from_millis(100))
        }
        other => panic!("expected Timeout, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "fired within the bound, took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn steadily_trickling_body_never_times_out() {
    // A body that keeps producing frames every 30 ms must survive a
    // 200 ms GAP timeout: the knob bounds stalls, not totals.
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
    let filler = std::thread::spawn(move || {
        for _ in 0..10 {
            std::thread::sleep(Duration::from_millis(30));
            if tx.send(Bytes::new()).is_err() {
                return;
            }
        }
    });
    let hardening = HttpHardening {
        request_body_gap: Some(Duration::from_millis(200)),
        ..HttpHardening::default()
    };
    let body = hardening.wrap_request_body(SlowBody { frames: rx });
    let collected = body.collect().await;
    assert!(
        collected.is_ok(),
        "trickling body must not trip the gap timeout"
    );
    filler.join().expect("filler thread");
}

#[tokio::test]
async fn disabled_gap_is_a_passthrough() {
    let hardening = HttpHardening {
        request_body_gap: None,
        ..HttpHardening::default()
    };
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
    let body = hardening.wrap_request_body(SlowBody { frames: rx });
    drop(tx); // sender gone: stream ENDS (no timeout error to invent)
    let mut body = std::pin::pin!(body);
    assert!(body.frame().await.is_none(), "clean end of stream");
}

#[tokio::test]
async fn wrapped_body_passes_frames_and_size_hint_through() {
    let hardening = HttpHardening::default();
    let body = hardening.wrap_request_body(Full::new(Bytes::from_static(b"hello")));
    let bytes = body.collect().await.expect("collects").to_bytes();
    assert_eq!(&bytes[..], b"hello");
}

#[test]
fn merge_vary_folds_all_existing_vary_lines() {
    // RFC 9110 permits multiple Vary field lines; merging a token must
    // fold EVERY line into one value, not read the first and drop the
    // rest (which would corrupt cache keys).
    let mut headers = hyper::HeaderMap::new();
    headers.append(
        hyper::header::VARY,
        hyper::header::HeaderValue::from_static("Accept-Language"),
    );
    headers.append(
        hyper::header::VARY,
        hyper::header::HeaderValue::from_static("Cookie"),
    );
    merge_vary(&mut headers, "Accept-Encoding");
    let lines: Vec<&str> = headers
        .get_all(hyper::header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert_eq!(lines, ["Accept-Language, Cookie, Accept-Encoding"]);
}

#[test]
fn merge_vary_appends_to_a_single_line_and_creates_when_absent() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        hyper::header::VARY,
        hyper::header::HeaderValue::from_static("Origin"),
    );
    merge_vary(&mut headers, "Accept-Encoding");
    assert_eq!(
        headers.get(hyper::header::VARY).unwrap(),
        "Origin, Accept-Encoding"
    );

    let mut headers = hyper::HeaderMap::new();
    merge_vary(&mut headers, "Accept-Encoding");
    assert_eq!(headers.get(hyper::header::VARY).unwrap(), "Accept-Encoding");
}

#[test]
fn merge_vary_leaves_lines_untouched_when_token_already_present() {
    // The token anywhere across the folded lines (case-insensitive)
    // means no rewrite at all: the existing lines stay as they are.
    let mut headers = hyper::HeaderMap::new();
    headers.append(
        hyper::header::VARY,
        hyper::header::HeaderValue::from_static("Origin"),
    );
    headers.append(
        hyper::header::VARY,
        hyper::header::HeaderValue::from_static("accept-encoding"),
    );
    merge_vary(&mut headers, "Accept-Encoding");
    let lines: Vec<&str> = headers
        .get_all(hyper::header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert_eq!(lines, ["Origin", "accept-encoding"]);
}
