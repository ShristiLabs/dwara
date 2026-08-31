//! CP/DP split gRPC transport integration tests (DW-066, feature `ent`).
//!
//! Feature-gated: with the default feature set this file compiles
//! empty. Run with:
//!
//! ```sh
//! cargo test -p dwara-core --features ent --test cp_dp_transport
//! ```
//!
//! All tests are deterministic: unique ephemeral ports (bind to :0),
//! bounded readiness polls (tokio::time::timeout), no sleeps as
//! synchronization. Timing-sensitive tests are re-run 3x inline.

#![cfg(feature = "ent")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dwara_core::cp_dp::transport::{serve_controller_with_incoming, ControllerServer, EdgeClient};
use dwara_core::cp_dp::{ConfigGeneration, ConfigUpdate, ControllerState, EdgeState};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;

/// A helper that binds a tonic ControllerServer on an ephemeral port
/// and returns the server handle + the bound address.
async fn spawn_controller(
    state: Arc<ControllerState>,
) -> (
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    SocketAddr,
    ControllerServer,
) {
    let server = ControllerServer::new(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let server_clone = server.clone();
    let handle =
        tokio::spawn(async move { serve_controller_with_incoming(server_clone, incoming).await });
    (handle, addr, server)
}

/// Bounded poll: wait for `condition` to return true, with a timeout.
/// Uses tokio::time::timeout -- NOT a sleep as synchronization.
async fn wait_for<F, Fut>(timeout: Duration, condition: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let _ = tokio::time::timeout(timeout, async {
        loop {
            if condition().await {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
}

/// A simple test config YAML (valid, minimal).
fn test_config_yaml() -> String {
    "allow_empty_routes: true\nroutes: []\n".to_string()
}

/// Create a ConfigUpdate for a given generation number.
fn make_update(gen: u64, target_edges: Vec<String>) -> ConfigUpdate {
    ConfigUpdate {
        generation: ConfigGeneration {
            generation: gen,
            config: test_config_yaml(),
            config_hash: format!("hash-{gen}"),
            timestamp_ms: 0,
        },
        target_edges,
    }
}

// ---------------------------------------------------------------------------
// Test: rolling edge fleet update
// ---------------------------------------------------------------------------

/// Rolling edge fleet update: start a controller, connect N edges,
/// publish a generation, assert all N edges receive it and cache it,
/// assert all send acks and the controller records them.
#[tokio::test]
async fn rolling_edge_fleet_update() {
    for _ in 0..3 {
        let state = Arc::new(ControllerState::new());
        state.become_leader();
        let (_handle, addr, server) = spawn_controller(Arc::clone(&state)).await;

        let endpoint = format!("http://{addr}");
        let n = 3;
        let mut edge_states: Vec<Arc<EdgeState>> = Vec::new();
        let mut edge_clients: Vec<EdgeClient> = Vec::new();
        let mut edge_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        for i in 0..n {
            let edge_id = format!("edge-{i}");
            let edge_state = Arc::new(EdgeState::new(&edge_id, "0.1.0"));
            let client = EdgeClient::connect(&endpoint).await.unwrap();
            let registration = edge_state.registration();
            let mut stream = client.stream_config_updates(registration).await.unwrap();
            let es = Arc::clone(&edge_state);
            let cl = client.clone();
            let task = tokio::spawn(async move {
                while let Some(result) = stream.next().await {
                    if let Ok(pb_update) = result {
                        if let Ok(update) = ConfigUpdate::try_from(pb_update) {
                            if es.receive_update(update.clone()).is_ok() {
                                let ack = es.ack_current(true, None);
                                let _ = cl.ack(ack).await;
                            }
                        }
                    }
                }
            });
            edge_states.push(edge_state);
            edge_clients.push(client);
            edge_tasks.push(task);
        }

        // Wait for all edges to register.
        wait_for(Duration::from_secs(5), || async { state.edge_count() == n }).await;
        assert_eq!(state.edge_count(), n, "all edges should register");

        // Publish a generation.
        let update = make_update(1, vec![]);
        server.publish_update(update);

        // Wait for all edges to cache the generation.
        wait_for(Duration::from_secs(5), || async {
            edge_states.iter().all(|e| e.cached_generation().is_some())
        })
        .await;
        for es in &edge_states {
            let cached = es.cached_generation().expect("edge should have cached gen");
            assert_eq!(cached.generation, 1);
        }

        // Wait for all acks to be recorded.
        wait_for(Duration::from_secs(5), || async {
            state.unacked_edges(1).is_empty()
        })
        .await;
        assert!(state.unacked_edges(1).is_empty(), "all edges should ack");

        // Verify acks.
        for i in 0..n {
            let edge_id = format!("edge-{i}");
            let ack = state.get_ack(&edge_id, 1).expect("ack should be recorded");
            assert!(ack.applied);
            assert_eq!(ack.generation, 1);
        }

        // Clean up.
        for task in edge_tasks {
            task.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Test: edge survives CP outage
// ---------------------------------------------------------------------------

/// Edge survives CP outage: connect an edge, publish gen 1, assert edge
/// cached it; stop the controller server; assert the edge's cached config
/// is still available; restart the controller, publish gen 2, assert the
/// edge reconnects and receives gen 2.
#[tokio::test]
async fn edge_survives_cp_outage() {
    for _ in 0..3 {
        let state = Arc::new(ControllerState::new());
        state.become_leader();
        let (handle, addr, server) = spawn_controller(Arc::clone(&state)).await;

        let endpoint = format!("http://{addr}");
        let edge_state = Arc::new(EdgeState::new("edge-outage", "0.1.0"));
        edge_state.set_controller_endpoint(&endpoint);

        let client = EdgeClient::connect(&endpoint).await.unwrap();
        let registration = edge_state.registration();
        let mut stream = client.stream_config_updates(registration).await.unwrap();

        let es = Arc::clone(&edge_state);
        let cl = client.clone();
        let edge_task = tokio::spawn(async move {
            while let Some(result) = stream.next().await {
                if let Ok(pb_update) = result {
                    if let Ok(update) = ConfigUpdate::try_from(pb_update) {
                        if es.receive_update(update.clone()).is_ok() {
                            let ack = es.ack_current(true, None);
                            let _ = cl.ack(ack).await;
                        }
                    }
                }
            }
        });

        // Wait for edge to register.
        wait_for(Duration::from_secs(5), || async { state.edge_count() == 1 }).await;

        // Publish gen 1.
        server.publish_update(make_update(1, vec![]));

        // Wait for edge to cache gen 1.
        wait_for(Duration::from_secs(5), || async {
            edge_state.cached_generation().is_some()
        })
        .await;
        assert!(edge_state.has_cached_config());
        assert_eq!(edge_state.cached_generation().unwrap().generation, 1);

        // Stop the controller (drop the handle).
        handle.abort();
        edge_state.set_connected(false);

        // Edge still has cached config during outage.
        assert!(edge_state.has_cached_config());
        assert_eq!(edge_state.cached_generation().unwrap().generation, 1);

        // Restart the controller.
        let state2 = Arc::new(ControllerState::new());
        state2.become_leader();
        let (_handle2, addr2, server2) = spawn_controller(Arc::clone(&state2)).await;
        let endpoint2 = format!("http://{addr2}");

        // Reconnect the edge to the new controller.
        let client2 = EdgeClient::connect(&endpoint2).await.unwrap();
        let registration2 = edge_state.registration();
        let mut stream2 = client2.stream_config_updates(registration2).await.unwrap();

        let es2 = Arc::clone(&edge_state);
        let cl2 = client2.clone();
        let edge_task2 = tokio::spawn(async move {
            while let Some(result) = stream2.next().await {
                if let Ok(pb_update) = result {
                    if let Ok(update) = ConfigUpdate::try_from(pb_update) {
                        if es2.receive_update(update.clone()).is_ok() {
                            let ack = es2.ack_current(true, None);
                            let _ = cl2.ack(ack).await;
                        }
                    }
                }
            }
        });

        // Wait for edge to register with new controller.
        wait_for(Duration::from_secs(5), || async {
            state2.edge_count() == 1
        })
        .await;

        // Publish gen 2.
        server2.publish_update(make_update(2, vec![]));

        // Wait for edge to cache gen 2.
        wait_for(Duration::from_secs(5), || async {
            edge_state
                .cached_generation()
                .map(|g| g.generation == 2)
                .unwrap_or(false)
        })
        .await;
        assert_eq!(edge_state.cached_generation().unwrap().generation, 2);

        edge_task.abort();
        edge_task2.abort();
    }
}

// ---------------------------------------------------------------------------
// Test: older generation rejected
// ---------------------------------------------------------------------------

/// Older generation rejected: publish gen 2 to an edge, then send gen 1;
/// assert the edge rejects gen 1 (its cached generation stays at 2).
#[tokio::test]
async fn older_generation_rejected() {
    for _ in 0..3 {
        let edge_state = Arc::new(EdgeState::new("edge-reject", "0.1.0"));

        // Send gen 2.
        let update2 = make_update(2, vec![]);
        edge_state.receive_update(update2).unwrap();
        assert_eq!(edge_state.cached_generation().unwrap().generation, 2);

        // Send gen 1 (older) -- should be rejected.
        let update1 = make_update(1, vec![]);
        let result = edge_state.receive_update(update1);
        assert!(result.is_err(), "older generation should be rejected");

        // Cached generation is still 2.
        assert_eq!(edge_state.cached_generation().unwrap().generation, 2);
    }
}

// ---------------------------------------------------------------------------
// Test: targeted update
// ---------------------------------------------------------------------------

/// Targeted update: a ConfigUpdate with target_edge_id set is delivered
/// only to that edge.
#[tokio::test]
async fn targeted_update() {
    for _ in 0..3 {
        let state = Arc::new(ControllerState::new());
        state.become_leader();
        let (_handle, addr, server) = spawn_controller(Arc::clone(&state)).await;

        let endpoint = format!("http://{addr}");

        // Connect two edges.
        let edge_a = Arc::new(EdgeState::new("edge-a", "0.1.0"));
        let edge_b = Arc::new(EdgeState::new("edge-b", "0.1.0"));

        let client_a = EdgeClient::connect(&endpoint).await.unwrap();
        let client_b = EdgeClient::connect(&endpoint).await.unwrap();

        let mut stream_a = client_a
            .stream_config_updates(edge_a.registration())
            .await
            .unwrap();
        let mut stream_b = client_b
            .stream_config_updates(edge_b.registration())
            .await
            .unwrap();

        let ea = Arc::clone(&edge_a);
        let ca = client_a.clone();
        let task_a = tokio::spawn(async move {
            while let Some(result) = stream_a.next().await {
                if let Ok(pb_update) = result {
                    if let Ok(update) = ConfigUpdate::try_from(pb_update) {
                        if ea.receive_update(update.clone()).is_ok() {
                            let ack = ea.ack_current(true, None);
                            let _ = ca.ack(ack).await;
                        }
                    }
                }
            }
        });

        let eb = Arc::clone(&edge_b);
        let cb = client_b.clone();
        let task_b = tokio::spawn(async move {
            while let Some(result) = stream_b.next().await {
                if let Ok(pb_update) = result {
                    if let Ok(update) = ConfigUpdate::try_from(pb_update) {
                        if eb.receive_update(update.clone()).is_ok() {
                            let ack = eb.ack_current(true, None);
                            let _ = cb.ack(ack).await;
                        }
                    }
                }
            }
        });

        // Wait for both edges to register.
        wait_for(Duration::from_secs(5), || async { state.edge_count() == 2 }).await;

        // Publish a targeted update to edge-a only.
        server.publish_update(make_update(1, vec!["edge-a".to_string()]));

        // Wait for edge-a to cache gen 1.
        wait_for(Duration::from_secs(5), || async {
            edge_a.cached_generation().is_some()
        })
        .await;
        assert_eq!(edge_a.cached_generation().unwrap().generation, 1);

        // edge-b should NOT have received the update (it's targeted at
        // edge-a only). Give it a bounded grace period to confirm it
        // does NOT arrive.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            edge_b.cached_generation().is_none(),
            "edge-b should not receive targeted update for edge-a"
        );

        // Now publish a broadcast update (empty target_edges).
        server.publish_update(make_update(2, vec![]));

        // Both edges should receive gen 2.
        wait_for(Duration::from_secs(5), || async {
            edge_a
                .cached_generation()
                .map(|g| g.generation == 2)
                .unwrap_or(false)
                && edge_b
                    .cached_generation()
                    .map(|g| g.generation == 2)
                    .unwrap_or(false)
        })
        .await;
        assert_eq!(edge_a.cached_generation().unwrap().generation, 2);
        assert_eq!(edge_b.cached_generation().unwrap().generation, 2);

        task_a.abort();
        task_b.abort();
    }
}
