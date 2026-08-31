//! dwara-k8s-controller (DW-064): the Kubernetes Gateway API controller
//! binary. A thin wrapper around the controller in the library: parse
//! config from environment variables / flags, build a
//! [`dwara_core::k8s_gateway::controller::Controller`], and run it.
//!
//! Configuration (environment variables):
//! - `DWARA_K8S_CONTROLLER_NAME`: the GatewayClass controller name
//!   (default: `shristilabs.com/dwara`).
//! - `DWARA_K8S_INGRESS_CLASS`: the Ingress class to watch (default:
//!   `dwara`).
//! - `DWARA_K8S_OUTPUT_CONFIG`: the output path for the generated dwara
//!   config YAML (default: `/etc/dwara/dwara.yaml`).
//! - `DWARA_K8S_NAMESPACE`: the namespace to watch (default: all
//!   namespaces).
//! - `KUBECONFIG`: the kubeconfig path (standard kube-rs behavior; in-
//!   cluster service account is used when KUBECONFIG is unset).
//!
//! The controller writes a dwara config YAML to the output path on every
//! reconciliation. The dwara gateway (running as a sidecar or a separate
//! pod) watches that file via DW-054 file-watch and hot-reloads.

use std::path::PathBuf;

use clap::Parser;

use dwara_core::k8s_gateway::controller::{Controller, ControllerConfig};
use dwara_core::k8s_gateway::CONTROLLER_NAME;

/// dwara Kubernetes Gateway API controller.
#[derive(Parser)]
#[command(
    name = "dwara-k8s-controller",
    version,
    about = "Kubernetes Gateway API + Ingress controller for dwara"
)]
struct Args {
    /// The GatewayClass controller name.
    #[arg(long, env = "DWARA_K8S_CONTROLLER_NAME", default_value = CONTROLLER_NAME)]
    controller_name: String,

    /// The Ingress class to watch.
    #[arg(long, env = "DWARA_K8S_INGRESS_CLASS", default_value = "dwara")]
    ingress_class: String,

    /// Output path for the generated dwara config YAML.
    #[arg(
        long,
        env = "DWARA_K8S_OUTPUT_CONFIG",
        default_value = "/etc/dwara/dwara.yaml"
    )]
    output_config: String,

    /// Namespace to watch (empty = all namespaces).
    #[arg(long, env = "DWARA_K8S_NAMESPACE", default_value = "")]
    namespace: String,
}

fn main() {
    let args = Args::parse();
    let config = ControllerConfig {
        controller_name: args.controller_name,
        ingress_class: args.ingress_class,
        output_config_path: PathBuf::from(args.output_config),
        namespace: args.namespace,
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let mut controller = Controller::new(config);
    if let Err(e) = rt.block_on(controller.run()) {
        eprintln!("dwara-k8s-controller: {e}");
        std::process::exit(1);
    }
}
