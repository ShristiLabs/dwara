//! dwara-edge (DW-066): the CP/DP split data plane binary.
//! A thin wrapper around [`dwara_core::cp_dp::edge::EdgeRuntime`]:
//! parse CLI flags / env vars, build an [`EdgeConfig`], and run.
//!
//! Configuration (CLI flags / environment variables):
//! - `--controller-endpoint` / `DWARA_CP_CONTROLLER_ENDPOINT`: the
//!   controller gRPC endpoint (default: `http://127.0.0.1:50051`).
//! - `--edge-id` / `DWARA_CP_EDGE_ID`: the edge instance ID (default:
//!   `edge-1`).
//! - `--version` / `DWARA_CP_EDGE_VERSION`: the edge version string
//!   (default: `0.1.0`).
//! - `--config-output` / `DWARA_CP_CONFIG_OUTPUT`: the local config
//!   output path (default: `/etc/dwara/dwara.yaml`).
//! - `DWARA_LOG`: the tracing filter (default:
//!   `dwara=info,dwara_core=info`); the runtime's own events
//!   (connect, receive, apply, ack, reconnect) come from
//!   `dwara_core::cp_dp`, so the default covers both prefixes.
//!
//! The edge connects to the controller, registers, receives config
//! updates, writes them to the local config file, and sends acks. On
//! CP outage, it continues serving from the cached config and
//! reconnects with bounded backoff.

use std::path::PathBuf;

use clap::Parser;

use dwara_core::cp_dp::edge::{EdgeConfig, EdgeRuntime};

/// Install the tracing subscriber: the same registry + EnvFilter +
/// JSON fmt stack dwara-bin installs, so edge logs flow through the
/// same pipeline as gateway logs. Without this the runtime's tracing
/// events are dropped and the edge is silent -- an operator could not
/// tell a converged edge from one that never received a generation.
fn init_tracing() {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    let filter = tracing_subscriber::EnvFilter::new(
        std::env::var("DWARA_LOG").unwrap_or_else(|_| "dwara=info,dwara_core=info".to_string()),
    );
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json().with_target(true))
        .init();
}

/// dwara CP/DP split data plane (edge).
#[derive(Parser)]
#[command(
    name = "dwara-edge",
    version,
    about = "CP/DP split data plane (edge) for dwara (Enterprise)"
)]
struct Args {
    /// The controller gRPC endpoint.
    #[arg(
        long,
        env = "DWARA_CP_CONTROLLER_ENDPOINT",
        default_value = "http://127.0.0.1:50051"
    )]
    controller_endpoint: String,

    /// The edge instance ID.
    #[arg(long, env = "DWARA_CP_EDGE_ID", default_value = "edge-1")]
    edge_id: String,

    /// The edge version string.
    #[arg(long, env = "DWARA_CP_EDGE_VERSION", default_value = "0.1.0")]
    version: String,

    /// The local config output path.
    #[arg(
        long,
        env = "DWARA_CP_CONFIG_OUTPUT",
        default_value = "/etc/dwara/dwara.yaml"
    )]
    config_output: String,
}

fn main() {
    let args = Args::parse();
    init_tracing();

    let config = EdgeConfig::new(
        &args.controller_endpoint,
        &args.edge_id,
        &args.version,
        PathBuf::from(args.config_output),
    );
    let runtime = EdgeRuntime::new(config);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(runtime.run());
}
