//! dwara-loadgen (DW-024): the macro load-generation binary — a thin
//! wrapper around the rig in the library: parse [`Args`], call [`run`].
//! All logic (histogram, pacing, workers, echo upstream, report) lives in
//! `dwara_cli::loadgen`, so tests exercise exactly what this binary runs.
//! See that module's docs for the output contract and OS limits.

use clap::Parser;

use dwara_cli::loadgen::{run, Args};

fn main() {
    let args = Args::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(run(args));
    std::process::exit(code);
}
