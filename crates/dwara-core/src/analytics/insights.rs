//! ML traffic insights (DW-092): EWMA-based capacity forecasting and
//! seasonal-baseline anomaly detection over the live sketch window
//! rotations.
//!
//! The engine is hand-rolled (no ML crates — no `hdrhistogram`, no
//! `tdigest`, no ML framework). It maintains two structures:
//!
//! - a **recent ring buffer** of completed sketch windows
//!   (`BaselineWindow` each), capped at `baseline_windows` entries,
//!   feeding an EWMA trend over the most recent observations; and
//! - a **minute-of-day seasonal pattern**: a fixed 1440-entry ring
//!   (one per minute of the day) of running averages for requests,
//!   error rate, and latency, updated incrementally as windows rotate.
//!
//! Forecasting combines the seasonal average for the NEXT minute with
//! an EWMA trend adjustment derived from the recent ring. Anomaly
//! detection compares the CURRENT window's shape to the seasonal
//! baseline for the same minute-of-day, flagging a window whose
//! requests, error rate, or latency exceed the baseline by a
//! configurable factor (default 2.0).
//!
//! The engine lives inside [`crate::analytics::EmbeddedAnalytics`] and
//! is fed by the live-sketch window rotation: when a sketch window
//! expires, the completed window's aggregates are handed to
//! [`InsightsEngine::observe`]. Reads (forecast, anomaly) are
//! admin-path only — never on the request hot path.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use crate::config::AnalyticsInsights;

/// The EWMA smoothing factor applied to the recent-window trend. A
/// higher value reacts faster to changes; 0.3 is a moderate
/// trend-following weight (the same family of weight the adaptive
/// rate-limiter's EWMA uses, DW-089).
const EWMA_ALPHA: f64 = 0.3;

/// The anomaly factor: a current value exceeding the seasonal baseline
/// by this multiple is flagged anomalous. 2.0 = a doubling.
const ANOMALY_FACTOR: f64 = 2.0;

/// One completed sketch window handed to the insights engine. A plain
/// DTO — the live-sketch rotation constructs it from its per-route
/// aggregates (summed across routes for the window-level shape).
#[derive(Debug, Clone, Copy, Default)]
pub struct BaselineWindow {
    /// Wall-clock ms since the Unix epoch (the window's start).
    pub ts_ms: i64,
    /// Total requests across all routes in the window.
    pub requests: u64,
    /// Total errors (status >= 500) across all routes.
    pub errors: u64,
    /// The window's average latency in milliseconds (mean of per-route
    /// averages, weighted by request count).
    pub avg_latency_ms: f64,
}

impl BaselineWindow {
    /// The error rate as a fraction in [0, 1].
    pub fn error_rate(&self) -> f64 {
        if self.requests == 0 {
            0.0
        } else {
            self.errors as f64 / self.requests as f64
        }
    }
}

/// One minute-of-day seasonal entry: running averages for the windows
/// that landed on this minute of the day. Updated incrementally with
/// an exponential moving average so a long-running gateway converges
/// on the daily traffic shape.
#[derive(Debug, Clone, Copy, Default)]
struct SeasonalEntry {
    /// Number of windows observed for this minute-of-day (the data
    /// volume behind the averages — drives forecast confidence).
    count: u64,
    /// Running average request count per window.
    avg_requests: f64,
    /// Running average error rate per window.
    avg_error_rate: f64,
    /// Running average latency per window.
    avg_latency_ms: f64,
}

/// The mutable state behind the insights engine, guarded by a RwLock.
struct BaselineState {
    /// Ring buffer of recent completed windows (newest at the back),
    /// capped at `baseline_windows`.
    recent: VecDeque<BaselineWindow>,
    /// The minute-of-day seasonal pattern: 1440 entries (one per
    /// minute of the day).
    seasonal: Box<[SeasonalEntry; 1440]>,
    /// The cap on the recent ring buffer.
    cap: usize,
}

/// The forecast result returned by [`InsightsEngine::forecast`].
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct ForecastResult {
    /// The wall-clock ms of the next window the forecast targets.
    pub next_window_ms: i64,
    /// Predicted request count for the next window.
    pub predicted_requests: f64,
    /// Predicted error rate (fraction in [0, 1]) for the next window.
    pub predicted_error_rate: f64,
    /// Predicted average latency in milliseconds for the next window.
    pub predicted_avg_latency_ms: f64,
    /// Forecast confidence in [0, 1]: higher when more seasonal data
    /// backs the prediction (0 when no baseline data exists).
    pub confidence: f64,
}

/// The anomaly result returned by [`InsightsEngine::detect_anomaly`].
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AnomalyResult {
    /// Whether the current window is anomalous (any metric exceeded
    /// the seasonal baseline by the anomaly factor).
    pub is_anomalous: bool,
    /// Anomaly score in [0, 1]: the maximum ratio of current to
    /// baseline across the checked metrics, normalized.
    pub score: f64,
    /// A human-readable reason naming the triggering metric, or None
    /// when not anomalous.
    pub reason: Option<String>,
    /// The seasonal baseline request count for the current
    /// minute-of-day.
    pub baseline_requests: f64,
    /// The current window's request count.
    pub current_requests: u64,
    /// The seasonal baseline error rate for the current
    /// minute-of-day.
    pub baseline_error_rate: f64,
    /// The current window's error rate.
    pub current_error_rate: f64,
    /// The seasonal baseline average latency for the current
    /// minute-of-day.
    pub baseline_latency_ms: f64,
    /// The current window's average latency.
    pub current_latency_ms: f64,
}

/// The ML traffic insights engine (DW-092): in-process, hand-rolled
/// EWMA forecasting and seasonal-baseline anomaly detection. Held
/// inside [`crate::analytics::EmbeddedAnalytics`] behind an `Arc` and
/// fed by the live-sketch window rotation.
pub struct InsightsEngine {
    forecast_enabled: bool,
    anomaly_enabled: bool,
    baseline_windows: u64,
    state: RwLock<BaselineState>,
}

impl InsightsEngine {
    /// Construct from the insights config. `baseline_windows` is
    /// clamped to at least 1 (the ring buffer must hold at least one
    /// window).
    pub fn new(config: &AnalyticsInsights) -> Arc<Self> {
        let cap = config.baseline_windows.max(1) as usize;
        Arc::new(InsightsEngine {
            forecast_enabled: config.forecast,
            anomaly_enabled: config.anomaly_baseline,
            baseline_windows: config.baseline_windows.max(1),
            state: RwLock::new(BaselineState {
                recent: VecDeque::with_capacity(cap),
                seasonal: Box::new([SeasonalEntry::default(); 1440]),
                cap,
            }),
        })
    }

    /// Whether forecasting is enabled.
    pub fn forecast_enabled(&self) -> bool {
        self.forecast_enabled
    }

    /// Whether anomaly detection is enabled.
    pub fn anomaly_enabled(&self) -> bool {
        self.anomaly_enabled
    }

    /// The configured baseline window cap.
    pub fn baseline_windows(&self) -> u64 {
        self.baseline_windows
    }

    /// Observe one completed sketch window: add it to the recent ring
    /// buffer (evicting the oldest when full) and update the
    /// minute-of-day seasonal entry with an exponential moving average.
    pub fn observe(&self, window: BaselineWindow) {
        let mut state = self.state.write().unwrap();
        // Update the recent ring buffer.
        if state.recent.len() >= state.cap {
            state.recent.pop_front();
        }
        state.recent.push_back(window);
        // Update the seasonal entry for the window's minute-of-day.
        let mod_idx = minute_of_day(window.ts_ms);
        let entry = &mut state.seasonal[mod_idx];
        let alpha = if entry.count == 0 { 1.0 } else { EWMA_ALPHA };
        entry.avg_requests = ema(entry.avg_requests, window.requests as f64, alpha);
        entry.avg_error_rate = ema(entry.avg_error_rate, window.error_rate(), alpha);
        entry.avg_latency_ms = ema(entry.avg_latency_ms, window.avg_latency_ms, alpha);
        entry.count = entry.count.saturating_add(1);
    }

    /// Forecast the next window's shape: the seasonal average for the
    /// next minute-of-day, trend-adjusted by an EWMA over the recent
    /// ring. Confidence is the fraction of the seasonal entry's data
    /// volume relative to a full day of observations (capped at 1.0).
    pub fn forecast(&self, now_ms: i64) -> ForecastResult {
        if !self.forecast_enabled {
            return ForecastResult::default();
        }
        let state = self.state.read().unwrap();
        let next_mod = minute_of_day(now_ms.saturating_add(60_000));
        let entry = state.seasonal[next_mod];
        // EWMA trend over the recent ring: the difference between the
        // most recent window and the seasonal average, applied as a
        // fractional adjustment (clamped so the trend cannot invert
        // the seasonal signal).
        let trend_req = state
            .recent
            .back()
            .map(|w| (w.requests as f64 - entry.avg_requests) * EWMA_ALPHA)
            .unwrap_or(0.0);
        let predicted_requests = (entry.avg_requests + trend_req).max(0.0);
        // Confidence: the seasonal entry's count relative to a full
        // day (1440 windows = one complete cycle). Saturates at 1.0.
        let confidence = (entry.count as f64 / 1440.0).min(1.0);
        ForecastResult {
            next_window_ms: now_ms.saturating_add(60_000),
            predicted_requests,
            predicted_error_rate: entry.avg_error_rate.clamp(0.0, 1.0),
            predicted_avg_latency_ms: entry.avg_latency_ms.max(0.0),
            confidence,
        }
    }

    /// Detect whether the current window is anomalous relative to the
    /// seasonal baseline for its minute-of-day. A metric is flagged
    /// when the current value exceeds the baseline by a factor of 2.0
    /// (the `ANOMALY_FACTOR` constant). The anomaly score is the
    /// maximum current/baseline ratio across the checked metrics,
    /// normalized to [0, 1].
    pub fn detect_anomaly(&self, current: &BaselineWindow) -> AnomalyResult {
        if !self.anomaly_enabled {
            return AnomalyResult::default();
        }
        let state = self.state.read().unwrap();
        let mod_idx = minute_of_day(current.ts_ms);
        let entry = state.seasonal[mod_idx];
        // No baseline data yet: nothing is anomalous (the baseline has
        // not been built).
        if entry.count == 0 {
            return AnomalyResult {
                baseline_requests: 0.0,
                current_requests: current.requests,
                baseline_error_rate: 0.0,
                current_error_rate: current.error_rate(),
                baseline_latency_ms: 0.0,
                current_latency_ms: current.avg_latency_ms,
                ..Default::default()
            };
        }
        let mut score = 0.0f64;
        let mut reason: Option<String> = None;
        // Requests: a spike is current > baseline * factor.
        if entry.avg_requests > 0.0 {
            let ratio = current.requests as f64 / entry.avg_requests;
            if ratio >= ANOMALY_FACTOR {
                score = score.max(ratio / ANOMALY_FACTOR);
                if reason.is_none() {
                    reason = Some(format!(
                        "request spike: {} current vs {:.1} baseline ({:.1}x)",
                        current.requests, entry.avg_requests, ratio
                    ));
                }
            }
        }
        // Error rate: a spike is current > baseline * factor (and the
        // current rate is non-trivial).
        let cur_err = current.error_rate();
        if entry.avg_error_rate > 0.0 {
            let ratio = cur_err / entry.avg_error_rate;
            if ratio >= ANOMALY_FACTOR && cur_err > 0.0 {
                score = score.max(ratio / ANOMALY_FACTOR);
                if reason.is_none() {
                    reason = Some(format!(
                        "error-rate spike: {:.4} current vs {:.4} baseline ({:.1}x)",
                        cur_err, entry.avg_error_rate, ratio
                    ));
                }
            }
        }
        // Latency: a spike is current > baseline * factor.
        if entry.avg_latency_ms > 0.0 {
            let ratio = current.avg_latency_ms / entry.avg_latency_ms;
            if ratio >= ANOMALY_FACTOR {
                score = score.max(ratio / ANOMALY_FACTOR);
                if reason.is_none() {
                    reason = Some(format!(
                        "latency spike: {:.1}ms current vs {:.1}ms baseline ({:.1}x)",
                        current.avg_latency_ms, entry.avg_latency_ms, ratio
                    ));
                }
            }
        }
        let is_anomalous = reason.is_some();
        AnomalyResult {
            is_anomalous,
            score: score.min(1.0),
            reason,
            baseline_requests: entry.avg_requests,
            current_requests: current.requests,
            baseline_error_rate: entry.avg_error_rate,
            current_error_rate: cur_err,
            baseline_latency_ms: entry.avg_latency_ms,
            current_latency_ms: current.avg_latency_ms,
        }
    }
}

/// The minute-of-day index (0..1440) for a wall-clock ms timestamp.
/// Computed from the timestamp's UTC minute-of-day so the seasonal
/// pattern is timezone-stable.
fn minute_of_day(ts_ms: i64) -> usize {
    let ms_per_day: i64 = 86_400_000;
    let within_day = ts_ms.rem_euclid(ms_per_day);
    (within_day / 60_000) as usize
}

/// One exponential moving average step: `prev` updated toward `sample`
/// by weight `alpha` (0..=1). When `prev` is the first observation
/// (`alpha == 1.0`), the result is the sample itself.
fn ema(prev: f64, sample: f64, alpha: f64) -> f64 {
    prev + alpha * (sample - prev)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(ts_ms: i64, requests: u64, errors: u64, latency: f64) -> BaselineWindow {
        BaselineWindow {
            ts_ms,
            requests,
            errors,
            avg_latency_ms: latency,
        }
    }

    #[test]
    fn minute_of_day_wraps_at_day_boundary() {
        // Midnight UTC = minute 0.
        assert_eq!(minute_of_day(0), 0);
        // 00:01 UTC = minute 1.
        assert_eq!(minute_of_day(60_000), 1);
        // 23:59 UTC = minute 1439.
        assert_eq!(minute_of_day(23 * 3_600_000 + 59 * 60_000), 1439);
        // Next day wraps back to 0.
        assert_eq!(minute_of_day(86_400_000), 0);
    }

    #[test]
    fn forecast_returns_zero_when_disabled() {
        let engine = InsightsEngine::new(&AnalyticsInsights {
            forecast: false,
            anomaly_baseline: false,
            baseline_windows: 10,
        });
        let r = engine.forecast(0);
        assert_eq!(r.predicted_requests, 0.0);
        assert_eq!(r.confidence, 0.0);
    }

    #[test]
    fn forecast_predicts_from_seasonal_baseline() {
        let engine = InsightsEngine::new(&AnalyticsInsights {
            forecast: true,
            anomaly_baseline: false,
            baseline_windows: 10,
        });
        // Feed one window at minute 0.
        engine.observe(window(0, 100, 5, 50.0));
        let r = engine.forecast(0);
        // Next window is minute 1 (now + 60s), which has no data yet:
        // confidence 0, predictions 0.
        assert_eq!(r.confidence, 0.0);
        // Forecast at minute 0 - 60s (so next is minute 0): the
        // seasonal entry for minute 0 has data.
        let r2 = engine.forecast(-60_000);
        assert!(r2.predicted_requests > 0.0);
        assert!(r2.confidence > 0.0);
    }

    #[test]
    fn anomaly_flags_request_spike() {
        let engine = InsightsEngine::new(&AnalyticsInsights {
            forecast: false,
            anomaly_baseline: true,
            baseline_windows: 10,
        });
        // Build a baseline at minute 0: 100 requests.
        engine.observe(window(0, 100, 0, 50.0));
        // Current window at the same minute: 300 requests (3x).
        let r = engine.detect_anomaly(&window(0, 300, 0, 50.0));
        assert!(r.is_anomalous);
        assert!(r.score > 0.0);
        assert!(r.reason.is_some());
    }

    #[test]
    fn anomaly_ignores_normal_traffic() {
        let engine = InsightsEngine::new(&AnalyticsInsights {
            forecast: false,
            anomaly_baseline: true,
            baseline_windows: 10,
        });
        engine.observe(window(0, 100, 0, 50.0));
        // Current window within normal range.
        let r = engine.detect_anomaly(&window(0, 120, 0, 55.0));
        assert!(!r.is_anomalous);
        assert!(r.reason.is_none());
    }

    #[test]
    fn anomaly_returns_default_when_disabled() {
        let engine = InsightsEngine::new(&AnalyticsInsights {
            forecast: false,
            anomaly_baseline: false,
            baseline_windows: 10,
        });
        let r = engine.detect_anomaly(&window(0, 999, 999, 999.0));
        assert!(!r.is_anomalous);
    }

    #[test]
    fn anomaly_no_baseline_is_not_anomalous() {
        let engine = InsightsEngine::new(&AnalyticsInsights {
            forecast: false,
            anomaly_baseline: true,
            baseline_windows: 10,
        });
        // No observations yet.
        let r = engine.detect_anomaly(&window(0, 999, 0, 999.0));
        assert!(!r.is_anomalous);
    }

    #[test]
    fn seasonal_baseline_builds_over_time() {
        let engine = InsightsEngine::new(&AnalyticsInsights {
            forecast: true,
            anomaly_baseline: true,
            baseline_windows: 100,
        });
        // Feed several windows at minute 0 across "days".
        for day in 0..5 {
            engine.observe(window(day * 86_400_000, 100, 5, 50.0));
        }
        let r = engine.forecast(-60_000);
        // After 5 observations the confidence is 5/1440.
        assert!((r.confidence - 5.0 / 1440.0).abs() < 1e-9);
        assert!(r.predicted_requests > 0.0);
    }

    #[test]
    fn recent_ring_evicts_oldest() {
        let engine = InsightsEngine::new(&AnalyticsInsights {
            forecast: false,
            anomaly_baseline: true,
            baseline_windows: 3,
        });
        for i in 0..5 {
            engine.observe(window(i * 60_000, 100, 0, 50.0));
        }
        let state = engine.state.read().unwrap();
        assert_eq!(state.recent.len(), 3);
        // The oldest two (i=0, i=1) were evicted; the back is i=4.
        assert_eq!(state.recent.front().unwrap().ts_ms, 2 * 60_000);
        assert_eq!(state.recent.back().unwrap().ts_ms, 4 * 60_000);
    }
}
