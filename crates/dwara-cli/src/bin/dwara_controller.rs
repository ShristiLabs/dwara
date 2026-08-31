//! dwara-controller (DW-066): the CP/DP split control plane binary.
//! A thin wrapper around [`dwara_core::cp_dp::controller::ControllerRuntime`]:
//! parse CLI flags / env vars, build a [`ControllerConfig`], and run.
//!
//! Configuration (CLI flags / environment variables):
//! - `--bind` / `DWARA_CP_BIND`: the gRPC bind address (default:
//!   `127.0.0.1:50051`).
//! - `--config-source` / `DWARA_CP_CONFIG_SOURCE`: the config source
//!   file path to watch (default: `./dwara.yaml`).
//! - `--leader` / `DWARA_CP_LEADER`: whether this controller is the
//!   leader (default: `true` for single-instance).
//!
//! The controller watches the config source file, compiles configs on
//! change, and pushes them to connected edges via gRPC streaming.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

use dwara_core::cp_dp::controller::{ControllerConfig, ControllerRuntime};

/// dwara CP/DP split control plane.
#[derive(Parser)]
#[command(
    name = "dwara-controller",
    version,
    about = "CP/DP split control plane for dwara (Enterprise)"
)]
struct Args {
    /// The gRPC bind address.
    #[arg(long, env = "DWARA_CP_BIND", default_value = "127.0.0.1:50051")]
    bind: String,

    /// The config source file path to watch.
    #[arg(long, env = "DWARA_CP_CONFIG_SOURCE", default_value = "./dwara.yaml")]
    config_source: String,

    /// Whether this controller is the leader.
    #[arg(long, env = "DWARA_CP_LEADER", default_value_t = true)]
    leader: bool,
}

fn main() {
    let args = Args::parse();

    let bind_addr: SocketAddr = args.bind.parse().expect("invalid bind address");
    let config_source = PathBuf::from(args.config_source);

    let config = ControllerConfig::from_env(bind_addr, config_source, args.leader);
    let runtime = ControllerRuntime::new(config);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    if let Err(e) = rt.block_on(runtime.run()) {
        eprintln!("dwara-controller: {e}");
        std::process::exit(1);
    }
}
