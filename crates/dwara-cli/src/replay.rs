//! Replay time-travel debugging CLI logic (DW-102): the pure half of
//! the `dwara replay` subcommand, kept library-shaped so tests exercise
//! exactly what the binary runs.
//!
//! # Exit-code contract
//!
//! - 0 = no decision diffs (the candidate config behaves identically
//!   to the baseline for every recorded request).
//! - 1 = diffs found (useful as a CI gate: a config change that
//!   alters routing, authz, rate-limit, transform, or upstream
//!   decisions for recorded traffic is surfaced before deploy).
//! - 2 = the recording or a config could not be loaded (operator
//!   error, distinct from a clean diff).
//!
//! # Recording format
//!
//! A recording is a JSON document exported from the analytics store
//! (or authored by hand for test fixtures):
//!
//! ```json
//! {
//!   "baseline_config": "<baseline YAML string>",
//!   "requests": [
//!     {
//!       "method": "GET",
//!       "path": "/api/foo",
//!       "headers": [["x-plan", "pro"]],
//!       "auth_identity": "alice",
//!       "timestamp_ms": 1700000000000
//!     }
//!   ]
//! }
//! ```
//!
//! The `baseline_config` is the config the requests were captured
//! under; `--config` is the candidate (new) config. The replay runs
//! [`dwara_core::dataplane::replay::decide`] for each request under
//! BOTH configs and emits a per-request [`DecisionDiff`] report.

use dwara_core::config::parse_gateway;
use dwara_core::dataplane::replay::{decide, DecisionDiff, ReplayRequest, SimulatedCounter};
use dwara_core::snapshot::{compile, Snapshot};

/// One request in a recording (the JSON shape the CLI reads).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub auth_identity: Option<String>,
    pub timestamp_ms: i64,
}

/// A recording: the baseline config plus the captured requests.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Recording {
    pub baseline_config: String,
    pub requests: Vec<RecordedRequest>,
}

/// The outcome of a replay run: the per-request diffs and a summary
/// count. The CLI prints the diffs and exits 1 when `diff_count > 0`.
#[derive(Debug, Clone)]
pub struct ReplayReport {
    /// One diff per request (in recording order); empty summary means
    /// no change for that request.
    pub diffs: Vec<DecisionDiff>,
    /// The number of requests with at least one changed stage.
    pub diff_count: usize,
}

impl ReplayReport {
    /// A human-readable report (one line per changed request, plus a
    /// summary footer). Empty output means no diffs.
    pub fn render(&self) -> String {
        if self.diffs.is_empty() {
            return "no requests in recording\n".to_string();
        }
        let mut out = String::new();
        for diff in &self.diffs {
            let line = diff.summary();
            if !line.is_empty() {
                out.push_str(&line);
                out.push('\n');
            }
        }
        if self.diff_count == 0 {
            out.push_str("no decision differences\n");
        } else {
            out.push_str(&format!(
                "{} request(s) with decision differences\n",
                self.diff_count
            ));
        }
        out
    }
}

/// Run a replay: load the recording, compile the baseline and candidate
/// configs, run [`decide`] for each request under both, and diff.
/// Returns the report or an error message (operator error).
pub fn run_replay(
    recording_text: &str,
    candidate_config_text: &str,
) -> Result<ReplayReport, String> {
    let recording: Recording =
        serde_json::from_str(recording_text).map_err(|e| format!("cannot parse recording: {e}"))?;
    let baseline = compile_config(&recording.baseline_config)?;
    let candidate = compile_config(candidate_config_text)?;
    Ok(replay_against(&baseline, &candidate, &recording.requests))
}

/// Run [`decide`] for each request under both snapshots and diff.
/// Public for testing (the pure core of [`run_replay`] without the
/// parse/compile error paths).
pub fn replay_against(
    baseline: &Snapshot,
    candidate: &Snapshot,
    requests: &[RecordedRequest],
) -> ReplayReport {
    let mut diffs = Vec::with_capacity(requests.len());
    let mut diff_count = 0usize;
    for req in requests {
        let replay_req = ReplayRequest {
            method: req.method.clone(),
            path: req.path.clone(),
            headers: req.headers.clone(),
            auth_identity: req.auth_identity.clone(),
            timestamp_ms: req.timestamp_ms,
        };
        // Each request gets its OWN simulated counter: replay answers
        // "what would THIS request do under THIS config?" not "what
        // would a burst of these do?" — the per-request decision
        // boundary is what a diff cares about, and sharing a counter
        // across requests would make the rate-limit verdict depend on
        // recording order.
        let mut old_counter = SimulatedCounter::new();
        let mut new_counter = SimulatedCounter::new();
        let old = decide(baseline, &replay_req, &mut old_counter);
        let new = decide(candidate, &replay_req, &mut new_counter);
        let diff = DecisionDiff::compare(&req.path, &old, &new);
        if diff.any() {
            diff_count += 1;
        }
        diffs.push(diff);
    }
    ReplayReport { diffs, diff_count }
}

/// Compile a config YAML into a [`Snapshot`] (validate + compile). The
/// snapshot is generation-0 (replay does not need a real generation
/// id).
fn compile_config(text: &str) -> Result<Snapshot, String> {
    let gateway = parse_gateway(text).map_err(|e| format!("parse failed: {e}"))?;
    let compiled = compile(&gateway).map_err(|e| format!("{e}"))?;
    Ok(Snapshot::from_compiled(compiled))
}
