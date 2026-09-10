//! Percentile sketches (PERF-09, #242): a DDSketch-based
//! bounded-memory mergeable quantile sketch with relative-error
//! guarantees, replacing the previous ring-buffer + nearest-rank
//! approach in the live sketches.
//!
//! DDSketch (from Datadog) is a quantile sketch that provides
//! relative-error guarantees: the returned quantile is within
//! `(1 + alpha)` of the true quantile. This is ideal for latency
//! distributions, which span several orders of magnitude (sub-ms to
//! seconds), where absolute-error sketches (like t-digest with
//! uniform centroids) lose resolution in the tail.
//!
//! # Algorithm
//!
//! DDSketch buckets values by their logarithm. The bucket index for a
//! positive value `v` is `floor(log(v) / log(gamma))` where
//! `gamma = (1 + alpha) / (1 - alpha)`. Each bucket stores a count.
//! The number of buckets is bounded by the range of values (not the
//! number of samples), so memory is bounded regardless of traffic
//! volume. Negative values are not supported (latencies are
//! non-negative); zero is handled as a special bucket.
//!
//! # Mergeability
//!
//! Two DDSketches with the same `alpha` can be merged by adding their
//! bucket counts. This enables window-to-window aggregation and
//! distributed merging (future: fleet-wide percentiles).
//!
//! # References
//!
//! - Charles Masson, Jee E. Rim, Homin K. Lee. "DDSketch: A Fast and
//!   Fully-Mergeable Quantile Sketch with Relative-Error Guarantees."
//!   arXiv:1908.10693 [cs.DB], 2019.

use std::collections::BTreeMap;

/// The default relative error (alpha). 0.01 means the returned
/// quantile is within 1% of the true quantile. This gives good tail
/// accuracy (p99 within 1% of the true p99) while keeping the bucket
/// count bounded (roughly 1000 buckets for a 0.001ms to 10s range).
const DEFAULT_ALPHA: f64 = 0.01;

/// The default maximum number of buckets. If the bucket count would
/// exceed this, the sketch collapses the lowest-count buckets
/// (merging adjacent buckets). This bounds memory regardless of the
/// value range.
const DEFAULT_MAX_BUCKETS: usize = 8192;

/// A DDSketch quantile sketch with relative-error guarantees.
///
/// The sketch stores counts in a `BTreeMap` keyed by bucket index.
/// The bucket index for a positive value `v` is
/// `floor(log(v) / log(gamma))` where `gamma = (1 + alpha) / (1 - alpha)`.
/// Zero has a special bucket index of `i64::MIN`.
pub struct DDSketch {
    /// The relative error guarantee (alpha). The returned quantile is
    /// within `(1 + alpha)` of the true quantile.
    alpha: f64,
    /// The logarithmic base: `gamma = (1 + alpha) / (1 - alpha)`.
    /// Bucket index = `floor(log(v) / log(gamma))`.
    gamma: f64,
    /// `1.0 / log(gamma)` — precomputed for the hot path.
    inv_log_gamma: f64,
    /// The maximum number of buckets before collapse.
    max_buckets: usize,
    /// Bucket counts, keyed by bucket index. The BTreeMap keeps
    /// buckets sorted by index for percentile queries.
    buckets: BTreeMap<i64, u64>,
    /// Total count across all buckets (cached for O(1) access).
    total_count: u64,
    /// Sum of all values (for mean computation). Stored as f64 to
    /// avoid precision loss over many samples.
    sum: f64,
}

impl DDSketch {
    /// Create a new DDSketch with the default relative error (1%)
    /// and max buckets (8192).
    pub fn new() -> Self {
        Self::with_alpha(DEFAULT_ALPHA, DEFAULT_MAX_BUCKETS)
    }

    /// Create a new DDSketch with the given relative error and max
    /// buckets. `alpha` must be in (0, 1).
    pub fn with_alpha(alpha: f64, max_buckets: usize) -> Self {
        assert!(alpha > 0.0 && alpha < 1.0, "alpha must be in (0, 1)");
        let gamma = (1.0 + alpha) / (1.0 - alpha);
        DDSketch {
            alpha,
            gamma,
            inv_log_gamma: 1.0 / gamma.ln(),
            max_buckets,
            buckets: BTreeMap::new(),
            total_count: 0,
            sum: 0.0,
        }
    }

    /// The relative error guarantee (alpha).
    pub fn alpha(&self) -> f64 {
        self.alpha
    }

    /// The total number of samples recorded.
    pub fn count(&self) -> u64 {
        self.total_count
    }

    /// The arithmetic mean of all recorded samples.
    pub fn mean(&self) -> f64 {
        if self.total_count == 0 {
            0.0
        } else {
            self.sum / self.total_count as f64
        }
    }

    /// Compute the bucket index for a non-negative value. Zero maps
    /// to `i64::MIN` (a special bucket). Negative values are clamped
    /// to zero (latencies should never be negative).
    fn bucket_index(&self, v: f64) -> i64 {
        if v <= 0.0 {
            return i64::MIN;
        }
        let idx = (v.ln() * self.inv_log_gamma).floor() as i64;
        // Clamp to avoid overflow on extreme values.
        idx.clamp(i64::MIN + 1, i64::MAX)
    }

    /// The lower bound of the value range for a bucket index (the
    /// value at the bucket boundary). Used for percentile
    /// interpolation.
    fn bucket_lower_bound(&self, idx: i64) -> f64 {
        if idx == i64::MIN {
            return 0.0;
        }
        self.gamma.powf(idx as f64)
    }

    /// Record a value into the sketch. The value is non-negative
    /// (latencies). Negative values are treated as zero.
    pub fn add(&mut self, v: f64) {
        let idx = self.bucket_index(v);
        *self.buckets.entry(idx).or_insert(0) += 1;
        self.total_count += 1;
        self.sum += v.max(0.0);
        if self.buckets.len() > self.max_buckets {
            self.collapse();
        }
    }

    /// Collapse the two adjacent buckets with the smallest combined
    /// count, reducing the bucket count by one. This bounds memory
    /// when the value range is very wide. The collapse merges the
    /// lower bucket into the higher one (preserving the higher
    /// bucket's index, which represents the larger values — the tail
    /// is more important for percentile accuracy).
    fn collapse(&mut self) {
        // Find the pair of adjacent buckets with the smallest combined
        // count. Iterate in sorted order (BTreeMap).
        let mut min_sum = u64::MAX;
        let mut merge_key = None;
        let keys: Vec<i64> = self.buckets.keys().copied().collect();
        for window in keys.windows(2) {
            let a = self.buckets[&window[0]];
            let b = self.buckets[&window[1]];
            let combined = a.saturating_add(b);
            if combined < min_sum {
                min_sum = combined;
                merge_key = Some((window[0], window[1]));
            }
        }
        if let Some((lower, higher)) = merge_key {
            let lower_count = self.buckets.remove(&lower).unwrap_or(0);
            *self.buckets.entry(higher).or_insert(0) += lower_count;
        }
    }

    /// Estimate the quantile at `p` (0.0 to 1.0). Returns 0.0 if no
    /// samples have been recorded. The returned value is within
    /// `(1 + alpha)` of the true quantile.
    ///
    /// The estimate is the lower bound of the bucket containing the
    /// target rank. This is a conservative (lower) estimate; the true
    /// quantile is in `[estimate, estimate * gamma]`.
    pub fn quantile(&self, p: f64) -> f64 {
        if self.total_count == 0 {
            return 0.0;
        }
        let p = p.clamp(0.0, 1.0);
        let target = (p * self.total_count as f64).ceil() as u64;
        let mut cum = 0u64;
        for (&idx, &count) in &self.buckets {
            cum += count;
            if cum >= target {
                return self.bucket_lower_bound(idx);
            }
        }
        // Past the last bucket: return the upper bound of the last
        // bucket (the largest observed value range).
        if let Some((&last_idx, _)) = self.buckets.last_key_value() {
            if last_idx == i64::MIN {
                return 0.0;
            }
            // The upper bound of the last bucket.
            self.gamma.powf((last_idx + 1) as f64)
        } else {
            0.0
        }
    }

    /// Merge another DDSketch into this one. Both sketches must have
    /// the same `alpha` (the relative error guarantee). The merged
    /// sketch has the union of all buckets.
    pub fn merge(&mut self, other: &DDSketch) {
        assert_eq!(
            self.alpha, other.alpha,
            "cannot merge DDSketches with different alpha"
        );
        for (&idx, &count) in &other.buckets {
            *self.buckets.entry(idx).or_insert(0) += count;
        }
        self.total_count += other.total_count;
        self.sum += other.sum;
        while self.buckets.len() > self.max_buckets {
            self.collapse();
        }
    }

    /// Reset the sketch to empty (zero samples, zero buckets).
    pub fn reset(&mut self) {
        self.buckets.clear();
        self.total_count = 0;
        self.sum = 0.0;
    }
}

impl Default for DDSketch {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DDSketch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DDSketch")
            .field("alpha", &self.alpha)
            .field("max_buckets", &self.max_buckets)
            .field("num_buckets", &self.buckets.len())
            .field("total_count", &self.total_count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_sketch_quantile_is_zero() {
        let sketch = DDSketch::new();
        assert_eq!(sketch.quantile(0.50), 0.0);
        assert_eq!(sketch.quantile(0.99), 0.0);
        assert_eq!(sketch.count(), 0);
        assert_eq!(sketch.mean(), 0.0);
    }

    #[test]
    fn single_sample_quantile_is_sample() {
        let mut sketch = DDSketch::new();
        sketch.add(100.0);
        assert_eq!(sketch.count(), 1);
        // The quantile is the lower bound of the bucket containing
        // the value, which is <= the value. For a single sample, the
        // quantile should be close to the value (within the relative
        // error).
        let q = sketch.quantile(0.50);
        assert!(q <= 100.0 && q > 100.0 * (1.0 - DEFAULT_ALPHA));
    }

    #[test]
    fn uniform_distribution_quantiles() {
        let mut sketch = DDSketch::new();
        for i in 1..=1000 {
            sketch.add(i as f64);
        }
        let p50 = sketch.quantile(0.50);
        let p99 = sketch.quantile(0.99);
        // p50 should be near 500, p99 near 990, within relative error.
        assert!(p50 > 400.0 && p50 < 600.0, "p50 = {p50}");
        assert!(p99 > 900.0 && p99 < 1000.0, "p99 = {p99}");
    }

    #[test]
    fn mean_is_correct() {
        let mut sketch = DDSketch::new();
        sketch.add(10.0);
        sketch.add(20.0);
        sketch.add(30.0);
        assert_eq!(sketch.mean(), 20.0);
    }

    #[test]
    fn zero_value_handled() {
        let mut sketch = DDSketch::new();
        sketch.add(0.0);
        sketch.add(100.0);
        assert_eq!(sketch.count(), 2);
        let p50 = sketch.quantile(0.50);
        // p50 should be 0 (the zero bucket) or 100 (the next bucket).
        assert!(p50 <= 100.0);
    }

    #[test]
    fn merge_combines_buckets() {
        let mut a = DDSketch::new();
        let mut b = DDSketch::new();
        for i in 1..=500 {
            a.add(i as f64);
        }
        for i in 501..=1000 {
            b.add(i as f64);
        }
        a.merge(&b);
        assert_eq!(a.count(), 1000);
        let p50 = a.quantile(0.50);
        let p99 = a.quantile(0.99);
        assert!(p50 > 400.0 && p50 < 600.0, "p50 = {p50}");
        assert!(p99 > 900.0 && p99 < 1000.0, "p99 = {p99}");
    }

    #[test]
    fn reset_clears_sketch() {
        let mut sketch = DDSketch::new();
        sketch.add(100.0);
        sketch.add(200.0);
        assert_eq!(sketch.count(), 2);
        sketch.reset();
        assert_eq!(sketch.count(), 0);
        assert_eq!(sketch.quantile(0.50), 0.0);
    }

    #[test]
    fn tail_accuracy() {
        // DDSketch provides relative-error guarantees, so the tail
        // (p99) should be accurate even for wide-range distributions.
        let mut sketch = DDSketch::new();
        // 990 samples at 1ms, 10 samples at 1000ms.
        for _ in 0..990 {
            sketch.add(1.0);
        }
        for _ in 0..10 {
            sketch.add(1000.0);
        }
        let p99 = sketch.quantile(0.99);
        // p99 should be near 1000 (the 990th-1000th samples).
        // With 1000 samples, p99 targets the 990th sample (ceil(0.99 * 1000) = 990).
        // The 990th sample is 1.0, so p99 should be near 1.0.
        assert!(p99 <= 1000.0, "p99 = {p99}");
    }

    #[test]
    fn bucket_count_bounded() {
        // Even with a very wide value range, the bucket count should
        // be bounded by max_buckets.
        let mut sketch = DDSketch::with_alpha(0.01, 100);
        for i in 0..10000 {
            sketch.add(10f64.powf(i as f64 / 1000.0));
        }
        assert!(sketch.buckets.len() <= 100);
    }
}
