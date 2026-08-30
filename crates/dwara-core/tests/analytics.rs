//! End-to-end tests for the embedded analytics record path (DW-043):
//! a real dataplane serving real requests, a real analytics store
//! attached the way dwara-bin attaches it, and assertions against the
//! RAW table after a clean writer shutdown — the rollup math itself is
//! pinned exactly in `tests/unit/analytics_store.rs` (driving SQLite
//! directly is deterministic; driving it through the async writer is
//! only slower).

mod support;

use std::sync::Arc;

use support::{body_of, gateway_yaml, h1_client, spawn_backend, spawn_gateway, uri};

use dwara_core::analytics::{EmbeddedAnalytics, DEFAULT_RETENTION_MS};

fn ok() -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    hyper::Response::builder()
        .status(200)
        .body(http_body_util::Full::new(bytes::Bytes::from("ok")))
        .unwrap()
}

#[tokio::test]
async fn completion_path_records_raw_rows_with_custom_dims() {
    let (backend_port, _hits) = spawn_backend(
        |_n, _method, _path, _body| ok(),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("analytics.db");
    let db_path = db.to_str().unwrap().to_string();
    // The support harness spawns its own listener, so the config
    // carries no listeners — the analytics block is what this test
    // needs from the config.
    let gateway_extra = format!(
        "analytics:\n\
         \x20 path: {db_path}\n\
         \x20 dimensions:\n\
         \x20   - name: plan\n\
         \x20     header: x-plan\n"
    );
    let yaml = gateway_yaml(&gateway_extra, backend_port, None, "");
    let dp = support::dataplane_from(&yaml);
    let store = EmbeddedAnalytics::open(&db_path, DEFAULT_RETENTION_MS, 50).unwrap();
    dp.set_analytics(Arc::clone(&store));
    let port = spawn_gateway(dp).await;
    let client = h1_client();

    // One request WITH the dimension header, one WITHOUT.
    let with_dim = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri(port, "/api/one"))
        .header("x-plan", "pro")
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap();
    let a = client.request(with_dim).await.unwrap();
    assert!(a.status().is_success());
    let _ = body_of(a).await;
    let without_dim = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri(port, "/api/two"))
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap();
    let b = client.request(without_dim).await.unwrap();
    assert!(b.status().is_success());
    let _ = body_of(b).await;

    // Clean shutdown drain (the dwara-bin shape): drop the watch
    // sender, workers drain + final-flush + stop.
    let (tx, rx) = tokio::sync::watch::channel(());
    let handles = store.spawn_workers(rx);
    drop(tx);
    for h in handles {
        tokio::time::timeout(std::time::Duration::from_secs(5), h)
            .await
            .expect("workers stop promptly")
            .expect("worker ok");
    }

    let rows: Vec<(String, String, String, i64, String)> = store
        .query(|c| {
            let mut stmt =
                c.prepare("SELECT route, consumer, method, status, dims FROM raw ORDER BY id")?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                })?
                .collect::<Result<_, _>>()?;
            Ok(rows)
        })
        .unwrap();
    assert_eq!(rows.len(), 2, "exactly one raw row per request: {rows:?}");
    assert_eq!(rows[0].0, "all", "matched route name recorded");
    assert_eq!(rows[0].1, "anonymous", "unauthenticated consumer default");
    assert_eq!(rows[0].2, "GET");
    assert_eq!(rows[0].3, 200);
    assert_eq!(rows[0].4, r#"{"plan":"pro"}"#, "custom dim captured");
    assert_eq!(rows[1].4, "{}", "no header, no dims");
}

#[tokio::test]
async fn unattached_store_means_no_recording() {
    // The no-analytics default: the completion path takes the ArcSwap
    // empty branch and records nothing (the config has no block; the
    // dataplane never had a store attached).
    let (backend_port, _hits) = spawn_backend(
        |_n, _method, _path, _body| ok(),
        std::time::Duration::from_millis(0),
    )
    .await;
    let yaml = gateway_yaml("", backend_port, None, "");
    let dp = support::dataplane_from(&yaml);
    let port = spawn_gateway(dp).await;
    let client = h1_client();
    let resp = client.get(uri(port, "/api/x")).await.unwrap();
    assert!(resp.status().is_success());
    let _ = body_of(resp).await;
    // No store, no file, nothing to assert against beyond "the request
    // succeeded" — the empty-branch behavior is compile-time visible
    // and covered by the dataplane's zero-cost no-op path.
}
