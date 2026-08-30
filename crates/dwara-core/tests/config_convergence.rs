//! Integration tests for config convergence (DW-054, ent feature only).
//!
//! These tests use an in-memory [`MemoryBackend`] implementing
//! [`ConfigConvergenceBackend`] so they are fully deterministic and
//! require no running Redis. A real-Redis smoke test is gated on the
//! `REDIS_URL` env var (skipped when unset) -- see
//! [`redis_smoke_test_when_redis_available`].
//!
//! The four scenarios from the story:
//!
//! 1. Two instances share a backend; A publishes a new config; B
//!    detects and converges within the poll interval (<1s with
//!    `poll_interval_ms = 100`).
//! 2. Drift detection -- two instances with different configs; drift
//!    is reported (the drift metric flips to 1).
//! 3. Fail-open when the backend is unreachable (continue serving the
//!    local config).
//! 4. Instance removal on shutdown (the backend no longer lists the
//!    instance).

#![cfg(feature = "ent")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use dwara_core::config::parse_gateway;
use dwara_core::dataplane::convergence::ConvergenceCoordinator;
use dwara_core::extensions::config_convergence::{
    ConfigConvergenceBackend, ConvergenceError, InstanceGeneration,
};
use dwara_core::observability::Observability;
use dwara_core::snapshot::ConfigState;
use tokio::sync::watch;

/// A minimal valid gateway YAML with one route. `route_name` and
/// `port` vary the content hash so two generations differ.
fn gateway_yaml(route_name: &str, port: u16) -> String {
    // NOTE: explicit `\n` + literal spaces (not `\` line-continuation,
    // which strips leading whitespace and breaks YAML indentation).
    let mut s = String::new();
    s.push_str("routes:\n");
    s.push_str(&format!("- name: {route_name}\n"));
    s.push_str("  service: svc\n");
    s.push_str("  match:\n");
    s.push_str("    path:\n");
    s.push_str("      type: prefix\n");
    s.push_str("      value: /api\n");
    s.push_str("  action:\n");
    s.push_str("    type: proxy\n");
    s.push_str("services:\n");
    s.push_str("- name: svc\n");
    s.push_str("  upstream: up\n");
    s.push_str("upstreams:\n");
    s.push_str("- name: up\n");
    s.push_str("  endpoints:\n");
    s.push_str("    - address: 127.0.0.1\n");
    s.push_str(&format!("      port: {port}\n"));
    s.push_str("allow_empty_routes: true\n");
    s
}

/// In-memory convergence backend for deterministic tests. Shares one
/// `Mutex<HashMap>` across instances so two coordinators see each
/// other's publishes.
#[derive(Default)]
struct MemoryBackend {
    instances: Mutex<HashMap<String, InstanceGeneration>>,
    configs: Mutex<HashMap<u64, String>>,
    /// When true, every operation returns a backend error (the
    /// fail-open test).
    broken: bool,
}

impl MemoryBackend {
    fn new() -> Self {
        Self::default()
    }

    /// A backend that fails every operation (simulates an unreachable
    /// backend).
    fn broken() -> Self {
        Self {
            broken: true,
            ..Self::default()
        }
    }
}

#[async_trait]
impl ConfigConvergenceBackend for MemoryBackend {
    async fn publish_generation(
        &self,
        generation: u64,
        config_hash: &str,
        instance_id: &str,
        config_yaml: &str,
    ) -> Result<(), ConvergenceError> {
        if self.broken {
            return Err(ConvergenceError::Backend(
                "backend unreachable (test)".into(),
            ));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.instances.lock().unwrap().insert(
            instance_id.to_string(),
            InstanceGeneration {
                instance_id: instance_id.to_string(),
                generation,
                config_hash: config_hash.to_string(),
                timestamp: now,
            },
        );
        self.configs
            .lock()
            .unwrap()
            .insert(generation, config_yaml.to_string());
        Ok(())
    }

    async fn watch_generations(&self) -> Result<Vec<InstanceGeneration>, ConvergenceError> {
        if self.broken {
            return Err(ConvergenceError::Backend(
                "backend unreachable (test)".into(),
            ));
        }
        Ok(self.instances.lock().unwrap().values().cloned().collect())
    }

    async fn load_config(&self, generation: u64) -> Result<String, ConvergenceError> {
        if self.broken {
            return Err(ConvergenceError::Backend(
                "backend unreachable (test)".into(),
            ));
        }
        self.configs
            .lock()
            .unwrap()
            .get(&generation)
            .cloned()
            .ok_or_else(|| ConvergenceError::NotFound(format!("generation {generation}")))
    }

    async fn remove_instance(&self, instance_id: &str) -> Result<(), ConvergenceError> {
        if self.broken {
            return Err(ConvergenceError::Backend(
                "backend unreachable (test)".into(),
            ));
        }
        self.instances.lock().unwrap().remove(instance_id);
        Ok(())
    }
}

/// Build a coordinator over the given backend and observability
/// registry (the registry is returned so the test can read the drift
/// gauge). Poll interval 100ms, drift check 1000ms, fail-open true.
fn build_coordinator(
    state: Arc<ConfigState>,
    backend: Arc<dyn ConfigConvergenceBackend>,
    obs: Arc<Observability>,
    instance_id: &str,
) -> Arc<ConvergenceCoordinator> {
    Arc::new(ConvergenceCoordinator::new(
        state,
        backend,
        obs,
        instance_id.to_string(),
        100,
        1000,
        true,
    ))
}

/// Publish a config locally (compile + publish + push to the backend).
async fn publish_local_config(
    state: &Arc<ConfigState>,
    coordinator: &Arc<ConvergenceCoordinator>,
    yaml: &str,
) {
    let gateway = parse_gateway(yaml).expect("config parses");
    state.compile_and_publish(&gateway).expect("publish");
    coordinator.publish_local().await;
}

/// Poll a predicate with bounded retries (10ms sleep, up to 2s). The
/// convergence poll interval is 100ms, so 2s is a generous margin.
async fn wait_for<F>(mut pred: F)
where
    F: FnMut() -> bool,
{
    for _ in 0..200 {
        if pred() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition never became true within 2s");
}

#[tokio::test]
async fn two_instances_converge_within_poll_interval() {
    let backend = Arc::new(MemoryBackend::new()) as Arc<dyn ConfigConvergenceBackend>;
    let obs_a = Arc::new(Observability::new());
    let obs_b = Arc::new(Observability::new());

    // Instance A and B both start with config v1 (route "a", port 9001).
    let state_a = Arc::new(ConfigState::new());
    let state_b = Arc::new(ConfigState::new());
    let coord_a = build_coordinator(
        Arc::clone(&state_a),
        Arc::clone(&backend),
        Arc::clone(&obs_a),
        "A",
    );
    let coord_b = build_coordinator(
        Arc::clone(&state_b),
        Arc::clone(&backend),
        Arc::clone(&obs_b),
        "B",
    );
    publish_local_config(&state_a, &coord_a, &gateway_yaml("a", 9001)).await;
    publish_local_config(&state_b, &coord_b, &gateway_yaml("a", 9001)).await;
    assert_eq!(state_a.snapshot().generation(), 1);
    assert_eq!(state_b.snapshot().generation(), 1);

    // Spawn B's poll loop (A does not need one for this test -- B is
    // the converging instance).
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let task = coord_b.spawn(shutdown_rx);

    // Instance A reloads to config v2 (route "b", port 9002) -- a
    // different content hash and a higher generation.
    publish_local_config(&state_a, &coord_a, &gateway_yaml("b", 9002)).await;
    assert_eq!(state_a.snapshot().generation(), 2);

    // B's poll loop should detect A's generation 2, load it, and
    // converge. The done-when is <1s with poll_interval_ms=100.
    let state_b_check = Arc::clone(&state_b);
    wait_for(|| state_b_check.snapshot().generation() >= 2).await;

    // B now serves the same config as A (same content hash).
    assert_eq!(
        state_b.snapshot().content_hash(),
        state_a.snapshot().content_hash()
    );

    // Shutdown B's poll loop; the task removes B's instance record.
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    let instances = backend.watch_generations().await.expect("watch");
    let ids: Vec<&str> = instances.iter().map(|i| i.instance_id.as_str()).collect();
    assert!(!ids.contains(&"B"), "B should be removed on shutdown");
    assert!(ids.contains(&"A"), "A should still be present");
}

#[tokio::test]
async fn drift_is_detected_and_reported() {
    let backend = Arc::new(MemoryBackend::new()) as Arc<dyn ConfigConvergenceBackend>;
    let obs_a = Arc::new(Observability::new());
    let obs_b = Arc::new(Observability::new());

    // Two instances with DIFFERENT configs (different route names ->
    // different content hashes). Neither generation is higher than the
    // other, so neither converges -- drift persists.
    let state_a = Arc::new(ConfigState::new());
    let state_b = Arc::new(ConfigState::new());
    let coord_a = build_coordinator(
        Arc::clone(&state_a),
        Arc::clone(&backend),
        Arc::clone(&obs_a),
        "A",
    );
    let coord_b = build_coordinator(
        Arc::clone(&state_b),
        Arc::clone(&backend),
        Arc::clone(&obs_b),
        "B",
    );
    publish_local_config(&state_a, &coord_a, &gateway_yaml("a", 9001)).await;
    publish_local_config(&state_b, &coord_b, &gateway_yaml("b", 9002)).await;

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let task = coord_b.spawn(shutdown_rx);

    // The drift check runs every 1000ms; wait for the drift gauge to
    // flip to 1 (the coordinator reads the cluster view and sets the
    // gauge when instances diverge).
    wait_for(|| obs_b.config_convergence_drift() == 1).await;
    // The instances gauge reflects the two-instance cluster view.
    assert_eq!(obs_b.config_convergence_instances(), 2);

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
}

#[tokio::test]
async fn fail_open_when_backend_unreachable() {
    // A broken backend: every operation errors. With fail_open=true
    // the coordinator keeps serving the local config and never
    // converges (the local snapshot is unchanged).
    let backend = Arc::new(MemoryBackend::broken()) as Arc<dyn ConfigConvergenceBackend>;
    let obs = Arc::new(Observability::new());
    let state = Arc::new(ConfigState::new());
    let coord = build_coordinator(
        Arc::clone(&state),
        Arc::clone(&backend),
        Arc::clone(&obs),
        "A",
    );
    publish_local_config(&state, &coord, &gateway_yaml("a", 9001)).await;
    let local_gen = state.snapshot().generation();
    let local_hash = state.snapshot().content_hash();

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let task = coord.spawn(shutdown_rx);

    // Let a few poll cycles run against the broken backend.
    tokio::time::sleep(Duration::from_millis(350)).await;

    // The local config is untouched: convergence never happened.
    assert_eq!(state.snapshot().generation(), local_gen);
    assert_eq!(state.snapshot().content_hash(), local_hash);

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
}

#[tokio::test]
async fn instance_removed_on_shutdown() {
    let backend = Arc::new(MemoryBackend::new()) as Arc<dyn ConfigConvergenceBackend>;
    let obs = Arc::new(Observability::new());
    let state = Arc::new(ConfigState::new());
    let coord = build_coordinator(
        Arc::clone(&state),
        Arc::clone(&backend),
        Arc::clone(&obs),
        "A",
    );
    publish_local_config(&state, &coord, &gateway_yaml("a", 9001)).await;

    // The instance is present after publishing.
    let instances = backend.watch_generations().await.expect("watch");
    assert!(instances.iter().any(|i| i.instance_id == "A"));

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let task = coord.spawn(shutdown_rx);

    // Let one poll cycle run so the task is alive, then shut down.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let _ = shutdown_tx.send(());
    // The task's shutdown path calls remove_instance; await it.
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;

    let instances = backend.watch_generations().await.expect("watch");
    assert!(
        !instances.iter().any(|i| i.instance_id == "A"),
        "instance A should be removed on shutdown"
    );
}

/// A real-Redis smoke test, skipped when REDIS_URL is unset. Verifies
/// the RedisConvergenceBackend round-trips a publish + watch + load +
/// remove.
#[tokio::test]
async fn redis_smoke_test_when_redis_available() {
    let Ok(url) = std::env::var("REDIS_URL") else {
        eprintln!("skipping redis smoke test: REDIS_URL not set");
        return;
    };
    use dwara_core::extensions::config_convergence::RedisConvergenceBackend;
    let client = redis::Client::open(url.as_str()).expect("redis client");
    let conn = tokio::time::timeout(Duration::from_secs(2), client.get_connection_manager())
        .await
        .expect("connect timeout")
        .expect("connect");
    // Unique prefix so this test run does not collide with others.
    let prefix = format!("dwara:test:config:{}", std::process::id());
    let backend = RedisConvergenceBackend::new(conn, prefix.clone(), 60, 3600);

    // Clean any leftover from a prior run.
    {
        let mut c = redis::aio::ConnectionManager::new(
            redis::Client::open(url.as_str()).expect("redis client"),
        )
        .await
        .expect("connect");
        let _: () = redis::cmd("DEL")
            .arg(format!("{prefix}:instances"))
            .query_async(&mut c)
            .await
            .expect("del");
    }

    let yaml = gateway_yaml("a", 9001);
    backend
        .publish_generation(1, "0x1", "smoke-A", &yaml)
        .await
        .expect("publish");
    let instances = backend.watch_generations().await.expect("watch");
    assert!(instances
        .iter()
        .any(|i| i.instance_id == "smoke-A" && i.generation == 1));
    let loaded = backend.load_config(1).await.expect("load");
    assert_eq!(loaded, yaml);
    backend.remove_instance("smoke-A").await.expect("remove");
    let instances = backend.watch_generations().await.expect("watch");
    assert!(!instances.iter().any(|i| i.instance_id == "smoke-A"));
}
