//! SEC-11 (#214): concurrency tests for the signed URL nonce cache.
//!
//! Verifies that the per-verifier nonce cache correctly detects
//! replays under concurrent access: multiple threads calling verify
//! with the same nonce must result in exactly one acceptance and
//! the rest rejected as replays.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dwara_core::security::signed_url::{SignedUrlConfig, SignedUrlVerifier};

#[test]
fn nonce_cache_concurrent_replay_detection() {
    let config = SignedUrlConfig {
        enabled: true,
        secret: Some("test-secret".to_string()),
        ttl_seconds: 300,
        query_param: "sig".to_string(),
        require_nonce: true,
        nonce_param: "nonce".to_string(),
        bind_client_ip: false,
    };
    let verifier = Arc::new(SignedUrlVerifier::from_config(&config).unwrap());

    // Mint a valid signed URL with a fixed nonce.
    let expires = now_secs() + 300;
    let query = verifier
        .sign("GET", "/path", expires, "", Some("unique-nonce-1"))
        .unwrap();

    // Spawn 8 threads all verifying the same signed URL (same nonce).
    let accepted = Arc::new(AtomicUsize::new(0));
    let rejected = Arc::new(AtomicUsize::new(0));
    let now = now_secs();

    let mut handles = Vec::new();
    for _ in 0..8 {
        let v = Arc::clone(&verifier);
        let q = query.clone();
        let acc = Arc::clone(&accepted);
        let rej = Arc::clone(&rejected);
        handles.push(std::thread::spawn(move || {
            let result = v.verify("GET", "/path", &q, now, "");
            match result {
                dwara_core::security::signed_url::SignedUrlResult::Valid => {
                    acc.fetch_add(1, Ordering::SeqCst);
                }
                dwara_core::security::signed_url::SignedUrlResult::NonceError => {
                    rej.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // Exactly one thread should have its nonce accepted; the rest
    // should be rejected as replays.
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "exactly one nonce acceptance under concurrency"
    );
    assert_eq!(
        rejected.load(Ordering::SeqCst),
        7,
        "7 nonce replays rejected under concurrency"
    );
}

#[test]
fn nonce_cache_distinct_nonces_all_accepted() {
    let config = SignedUrlConfig {
        enabled: true,
        secret: Some("test-secret".to_string()),
        ttl_seconds: 300,
        query_param: "sig".to_string(),
        require_nonce: true,
        nonce_param: "nonce".to_string(),
        bind_client_ip: false,
    };
    let verifier = Arc::new(SignedUrlVerifier::from_config(&config).unwrap());
    let expires = now_secs() + 300;
    let now = now_secs();

    // Each thread uses a distinct nonce — all should be accepted.
    let accepted = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for i in 0..8 {
        let v = Arc::clone(&verifier);
        let acc = Arc::clone(&accepted);
        handles.push(std::thread::spawn(move || {
            let nonce = format!("distinct-nonce-{i}");
            let query = v.sign("GET", "/path", expires, "", Some(&nonce)).unwrap();
            let result = v.verify("GET", "/path", &query, now, "");
            if result == dwara_core::security::signed_url::SignedUrlResult::Valid {
                acc.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        8,
        "all 8 distinct nonces accepted"
    );
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
