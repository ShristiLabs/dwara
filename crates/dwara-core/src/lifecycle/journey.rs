//! API journey recorder (DW-110): records the request flow through the
//! gateway as a JSON document for debugging.
//!
//! A [`Journey`] is the ordered sequence of phases a request passed
//! through (route match, authn, authz, transforms, upstream pick,
//! response), each captured as a [`JourneyStep`] (phase, duration,
//! result, detail). The recorder is a bounded in-memory ring buffer of
//! recent journeys (for live debugging) plus a JSON serializer that
//! stores the journey via the existing analytics raw table's custom
//! dimensions column (a JSON object column -- no schema change needed).
//!
//! ## Storage
//!
//! The journey JSON document is carried on the
//! [`AccessRecord`](crate::observability::AccessRecord)'s `custom`
//! dimensions as a `_journey` key (the same JSON object column the
//! DW-043 custom dimensions ride). This reuses the existing raw
//! table's fire-and-forget write path -- no schema migration, no new
//! table, no new writer channel. The in-memory ring buffer is a
//! bounded `VecDeque` (capped at `JOURNEY_BUFFER_CAP`) for live
//! debugging queries; the durable copy is the raw row.
//!
//! ## Retention
//!
//! The journey's durable retention is the raw table's retention (the
//! `analytics.retention` config, default 24h). The `retention_hours`
//! config field on [`JourneyConfig`] is an advisory cap that the
//! recorder honors by dropping journeys older than the window from the
//! in-memory buffer (the raw table's own retention handles the durable
//! copy).
//!
//! The config schema type ([`JourneyConfig`]) lives in
//! [`crate::config`] (always present, so configs round-trip without
//! the `api_lifecycle` feature). This module re-exports it as the
//! runtime-facing alias the recorder consumes.

use std::collections::VecDeque;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::config::LifecycleJourneyConfig as JourneyConfig;

/// The result of a journey step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JourneyStepResult {
    Success,
    Failure,
}

/// One step in a request's journey through the gateway.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JourneyStep {
    /// The phase name (e.g. `route_match`, `authn`, `authz`,
    /// `transforms`, `upstream_pick`, `response`).
    pub phase: String,
    /// The duration of this phase in milliseconds.
    pub duration_ms: f64,
    /// The outcome of this phase.
    pub result: JourneyStepResult,
    /// A free-form detail string (e.g. the matched route name, the
    /// picked upstream, the response status). Never secrets -- the
    /// same redaction posture as the access log applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A recorded request journey: the request id, the ordered steps, and
/// the timestamp (wall-clock ms since the Unix epoch).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journey {
    pub request_id: String,
    pub steps: Vec<JourneyStep>,
    pub timestamp_ms: u64,
}

impl Journey {
    /// Create a new empty journey for the given request id.
    pub fn new(request_id: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            steps: Vec::new(),
            timestamp_ms: now_ms(),
        }
    }

    /// Record a step in the journey.
    pub fn add_step(&mut self, step: JourneyStep) {
        self.steps.push(step);
    }

    /// Record a step with the given phase, result, and detail. The
    /// duration is measured from the `started` instant to now.
    pub fn add_timed_step(
        &mut self,
        phase: impl Into<String>,
        started: std::time::Instant,
        result: JourneyStepResult,
        detail: Option<String>,
    ) {
        let duration_ms = started.elapsed().as_secs_f64() * 1000.0;
        self.add_step(JourneyStep {
            phase: phase.into(),
            duration_ms,
            result,
            detail,
        });
    }

    /// Serialize the journey to a JSON string.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("journey serialize failed: {e}"))
    }

    /// Serialize the journey to a [`serde_json::Value`].
    pub fn to_value(&self) -> Result<Value, String> {
        serde_json::to_value(self).map_err(|e| format!("journey serialize failed: {e}"))
    }

    /// The total duration of all steps (sum of step durations).
    pub fn total_duration_ms(&self) -> f64 {
        self.steps.iter().map(|s| s.duration_ms).sum()
    }

    /// Whether any step failed.
    pub fn has_failure(&self) -> bool {
        self.steps
            .iter()
            .any(|s| s.result == JourneyStepResult::Failure)
    }
}

/// The in-memory ring buffer cap (recent journeys for live debugging).
const JOURNEY_BUFFER_CAP: usize = 4096;

/// The journey recorder: a bounded in-memory ring buffer of recent
/// journeys, plus the retention window for dropping stale entries.
#[derive(Debug)]
pub struct JourneyRecorder {
    config: JourneyConfig,
    buffer: Mutex<VecDeque<Journey>>,
}

impl JourneyRecorder {
    /// Build a recorder from the config.
    pub fn new(config: JourneyConfig) -> Self {
        Self {
            config,
            buffer: Mutex::new(VecDeque::new()),
        }
    }

    /// Whether recording is enabled.
    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// The configured retention window in hours.
    pub fn retention_hours(&self) -> u64 {
        self.config.retention_hours
    }

    /// Record a completed journey into the in-memory ring buffer. The
    /// caller is responsible for also stamping the journey onto the
    /// [`AccessRecord`]'s custom dimensions (via [`journey_dimension`])
    /// so the durable copy rides the raw table's write path. This
    /// method never blocks: the buffer is a short mutex over a capped
    /// `VecDeque`; when full, the oldest entry is evicted.
    pub fn record(&self, journey: Journey) {
        if !self.config.enabled {
            return;
        }
        let mut buf = self.buffer.lock().expect("journey buffer mutex poisoned");
        // Drop stale entries (older than the retention window).
        let cutoff = now_ms().saturating_sub(self.config.retention_hours * 3600 * 1000);
        while let Some(front) = buf.front() {
            if front.timestamp_ms < cutoff {
                buf.pop_front();
            } else {
                break;
            }
        }
        // Evict the oldest when at cap.
        if buf.len() >= JOURNEY_BUFFER_CAP {
            buf.pop_front();
        }
        buf.push_back(journey);
    }

    /// Snapshot the in-memory journeys (newest first). Never blocks
    /// beyond the short mutex hold.
    pub fn snapshot(&self) -> Vec<Journey> {
        let buf = self.buffer.lock().expect("journey buffer mutex poisoned");
        let mut out: Vec<Journey> = buf.iter().rev().cloned().collect();
        // Drop stale entries on read too (a long-idle buffer can hold
        // stale entries when no new recording evicted them).
        let cutoff = now_ms().saturating_sub(self.config.retention_hours * 3600 * 1000);
        out.retain(|j| j.timestamp_ms >= cutoff);
        out
    }

    /// The number of journeys currently in the buffer.
    pub fn len(&self) -> usize {
        self.buffer
            .lock()
            .expect("journey buffer mutex poisoned")
            .len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Build the custom-dimension entry that carries a journey on an
/// [`AccessRecord`] into the raw table's JSON object column. The key
/// is `_journey` (the leading underscore avoids collisions with
/// operator-declared dimensions). Returns the `(key, value)` pair to
/// push onto `AccessRecord::custom`.
pub fn journey_dimension(journey: &Journey) -> Result<(String, String), String> {
    let json = journey.to_json()?;
    Ok(("_journey".to_string(), json))
}

/// Wall-clock milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
