//! Analytics bounded context (DW-043): the embedded analytics store.
//!
//! Observability answers "is it healthy right now"; analytics answers
//! "what happened over time, to whom, and why". This domain owns the
//! DURABLE side of that question: a local SQLite database (separate
//! file from the state store, DW-018 — different lifecycle, different
//! write pattern, independent bounded-disk story) holding raw access
//! records for a short retention window and additive rollup tables at
//! 1m/5m/1h/1d granularities with per-granularity retention, plus the
//! query surface over them (dashboard series, Top-N, structured
//! query) served by the admin API.
//!
//! # Write path (never blocks the dataplane)
//!
//! The dataplane's `DataPlane` (see `dataplane::proxy`) holds an
//! [`EmbeddedAnalytics`] (set once at startup when the config carries
//! an `analytics` block) and calls [`EmbeddedAnalytics::record`] at
//! request completion — a `try_send` onto a bounded channel. When the
//! channel is full the record is DROPPED (counted, logged throttled):
//! the analytics pipeline must never slow or block a request, the same
//! fire-and-forget posture DW-121's export pipeline will require. A
//! background writer drains the channel in batched transactions.
//!
//! # The sink seam
//!
//! The M1 extension contract
//! `extensions::analytics::AnalyticsSink` is the OSS/Ent seam (feature
//! analysis 11.4): the embedded store implements it (over the richer
//! per-request fields DW-043 added to `extensions::analytics::Event`);
//! the federated analytics and raw-record export pipelines (DW-121,
//! DW-095) are future sibling implementations of the same contract.
//!
//! # Custom dimensions
//!
//! Config-declared dimensions extracted from request HEADERS at
//! completion-time capture (e.g. `x-plan` -> dimension `plan`): they
//! ride the [`AccessRecord`](crate::observability::AccessRecord) into
//! raw rows (a JSON object column) and aggregate into their own
//! narrow rollup table. They are analytics-only — deliberately NOT
//! added to the access log, whose field list is redacted by
//! construction and stays that way.

pub mod query;
pub mod rollup;
pub mod schema;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::observability::AccessRecord;

/// Channel capacity between the request path and the writer. Sized so
/// a burst of completions (or a briefly stalled writer transaction)
/// queues rather than drops; drops are counted and throttled-logged.
const CHANNEL_CAP: usize = 4096;

/// Writer batch flush bound (records) — with the flush tick, whichever
/// comes first.
const BATCH_MAX: usize = 1024;

/// How often the rollup/retention worker runs. Rollups are cheap
/// cursor-guarded SQL; 30 s keeps even a 1-minute window's staleness
/// under a minute end-to-end (plus the completion grace below).
const ROLLUP_INTERVAL_MS: u64 = 30_000;

/// Completion GRACE: a fine window is rolled only once its end is at
/// least this far in the past — headroom for the writer's flush tick
/// and batch latency, so a straggler record still lands in the window
/// it belongs to. Records later than the grace are documented as
/// rollup-lost (they remain in `raw` until raw retention expires).
pub const ROLLUP_GRACE_MS: i64 = 60_000;

/// Per-granularity retention defaults (ms) — the single definition
/// lives in [`config::ANALYTICS_DEFAULT_RETENTION_MS`] (the lowest
/// consuming domain); re-exported here for the module's readers.
pub use crate::config::ANALYTICS_DEFAULT_RETENTION_MS as DEFAULT_RETENTION_MS;

/// One raw record as stored (the owned, completion-time copy handed
/// across the channel).
struct RawRecord {
    ts_ms: i64,
    listener: String,
    route: String,
    consumer: String,
    upstream: String,
    method: String,
    status: u16,
    status_class: String,
    duration_ms: f64,
    attempts: u32,
    rate_limited: bool,
    broken: bool,
    shed: bool,
    dims: String,
}

/// The custom-dimensions JSON column for a (name, value) pair list.
fn dims_json(pairs: &[(String, String)]) -> String {
    if pairs.is_empty() {
        return "{}".to_string();
    }
    let map: serde_json::Map<String, serde_json::Value> = pairs
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    serde_json::Value::Object(map).to_string()
}

impl RawRecord {
    /// The extension-event shape of the same record (the
    /// `extensions::analytics::AnalyticsSink` contract's input type).
    fn from_event(event: &crate::extensions::analytics::Event) -> Self {
        RawRecord {
            ts_ms: event.timestamp_ms as i64,
            listener: event.listener.clone().unwrap_or_default(),
            route: event.route.clone().unwrap_or_else(|| "unrouted".into()),
            consumer: event.consumer.clone().unwrap_or_else(|| "anonymous".into()),
            // The extension event carries the ENDPOINT; the raw table's
            // `upstream` column is the queries' upstream axis — the
            // event shape has no separate upstream field, so
            // endpoint-addressed events record the endpoint there.
            upstream: event.endpoint.clone().unwrap_or_default(),
            method: event.method.clone().unwrap_or_default(),
            status: event.status.unwrap_or(0),
            status_class: event
                .status
                .map(|s| format!("{}xx", s / 100))
                .unwrap_or_else(|| "0xx".into()),
            duration_ms: event.duration_ms.unwrap_or(0.0),
            attempts: event.attempts.unwrap_or(0),
            rate_limited: event.rate_limited,
            broken: event.broken,
            shed: event.shed,
            dims: dims_json(&event.attributes),
        }
    }

    fn from(rec: &AccessRecord, now_ms: i64) -> Self {
        RawRecord {
            ts_ms: now_ms,
            listener: rec.listener.clone(),
            route: rec.route.clone(),
            consumer: rec.consumer.clone(),
            upstream: rec.upstream.clone().unwrap_or_default(),
            method: rec.method.clone(),
            status: rec.status,
            status_class: crate::observability::status_class(rec.status),
            duration_ms: rec.duration_ms,
            attempts: rec.attempts,
            rate_limited: rec.rate_limited,
            broken: rec.broken,
            shed: rec.shed,
            dims: dims_json(&rec.custom),
        }
    }
}

/// Wall-clock ms since the Unix epoch (the analytics time domain).
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The embedded analytics store (DW-043): SQLite file + bounded
/// channel + background writer. Rollup/retention workers are spawned
/// by [`EmbeddedAnalytics::spawn_workers`].
pub struct EmbeddedAnalytics {
    conn: Mutex<rusqlite::Connection>,
    tx: mpsc::Sender<RawRecord>,
    rx: Mutex<Option<mpsc::Receiver<RawRecord>>>,
    /// Retention config: [raw, 1m, 5m, 1h, 1d] in ms.
    retention_ms: [i64; 5],
    /// Flush tick (ms) — the writer's maximum batch latency.
    flush_ms: u64,
    /// Records dropped on a full channel (the never-block counter).
    dropped: AtomicU64,
}

impl EmbeddedAnalytics {
    /// Open (or create) the analytics database at `path`, apply
    /// migrations, and return the store with its channel wired. The
    /// writer is NOT started here — see [`spawn_workers`].
    pub fn open(path: &str, retention_ms: [i64; 5], flush_ms: u64) -> rusqlite::Result<Arc<Self>> {
        let conn = rusqlite::Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        schema::migrate(&conn)?;
        let (tx, rx) = mpsc::channel(CHANNEL_CAP);
        Ok(Arc::new(EmbeddedAnalytics {
            conn: Mutex::new(conn),
            rx: Mutex::new(Some(rx)),
            tx,
            retention_ms,
            flush_ms,
            dropped: AtomicU64::new(0),
        }))
    }

    /// Spawn the writer and rollup/retention workers. Exactly one set
    /// per store (the receiver is taken once; a second call returns an
    /// empty set and logs). Both stop on `shutdown`; the writer drains
    /// what is already queued first, then performs a final rollup and
    /// retention pass so a clean restart loses nothing.
    pub fn spawn_workers(
        self: &Arc<Self>,
        shutdown: tokio::sync::watch::Receiver<()>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let Some(mut rx) = self.rx.lock().unwrap().take() else {
            tracing::error!(
                code = "analytics_workers_already_running",
                "analytics workers already spawned for this store; ignoring"
            );
            return Vec::new();
        };
        let mut writer_shutdown = shutdown.clone();
        let writer = {
            let store = Arc::clone(self);
            tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_millis(store.flush_ms));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut batch: Vec<RawRecord> = Vec::with_capacity(BATCH_MAX);
                loop {
                    let drained = tokio::select! {
                        m = rx.recv() => match m {
                            Some(r) => {
                                batch.push(r);
                                batch.len() >= BATCH_MAX
                            }
                            None => {
                                // Channel closed (store dropped): final
                                // flush and stop.
                                store.flush(&batch);
                                return;
                            }
                        },
                        _ = tick.tick() => true,
                        _ = writer_shutdown.changed() => {
                            // Drain what is already queued, then stop.
                            while let Ok(r) = rx.try_recv() {
                                batch.push(r);
                            }
                            store.flush(&batch);
                            store.maintain();
                            return;
                        }
                    };
                    if drained {
                        store.flush(&batch);
                        batch.clear();
                    }
                }
            })
        };
        let maintainer = {
            let store = Arc::clone(self);
            let mut shutdown2 = shutdown.clone();
            tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_millis(ROLLUP_INTERVAL_MS));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = tick.tick() => store.maintain(),
                        _ = shutdown2.changed() => return,
                    }
                }
            })
        };
        vec![writer, maintainer]
    }

    /// One batched transaction of raw INSERTs. Errors are logged and
    /// swallowed (a failed analytics batch must never propagate into
    /// the worker loop) — the records are lost, the counter is not
    /// bumped (they were accepted; the DISK failed).
    fn flush(&self, batch: &[RawRecord]) {
        if batch.is_empty() {
            return;
        }
        let conn = self.conn.lock().unwrap();
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_batch_begin_failed",
                    "analytics batch lost: {e}"
                );
                return;
            }
        };
        let mut stmt = match tx.prepare(
            "INSERT INTO raw (ts_ms, listener, route, consumer, upstream,
                              method, status, status_class, duration_ms,
                              attempts, rate_limited, broken, shed, dims)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    code = "analytics_batch_prepare_failed",
                    "analytics batch lost: {e}"
                );
                return;
            }
        };
        let mut ok = true;
        for r in batch {
            let res = stmt.execute(rusqlite::params![
                r.ts_ms,
                r.listener,
                r.route,
                r.consumer,
                r.upstream,
                r.method,
                r.status,
                r.status_class,
                r.duration_ms,
                r.attempts,
                r.rate_limited,
                r.broken,
                r.shed,
                r.dims,
            ]);
            if let Err(e) = res {
                tracing::warn!(
                    code = "analytics_insert_failed",
                    "analytics record lost: {e}"
                );
                ok = false;
            }
        }
        drop(stmt);
        if ok || !batch.is_empty() {
            // Commit even with per-row failures: the surviving rows are
            // valid analytics input.
            if let Err(e) = tx.commit() {
                tracing::warn!(
                    code = "analytics_commit_failed",
                    "analytics batch lost: {e}"
                );
            }
        }
    }

    /// One rollup + retention pass (cursor-guarded; safe to run at any
    /// time, from the ticker or shutdown).
    fn maintain(&self) {
        let conn = self.conn.lock().unwrap();
        let now = now_ms();
        let mut rolled = 0usize;
        match rollup::roll_raw_to_1m(&conn, now, ROLLUP_GRACE_MS) {
            Ok(n) => rolled = n,
            Err(e) => tracing::warn!(
                code = "analytics_rollup_failed",
                "raw->1m rollup failed: {e}"
            ),
        }
        for stage in 0..rollup::GRANULARITIES_MS.len() - 1 {
            if let Err(e) = rollup::roll_cascade(&conn, stage, now, ROLLUP_GRACE_MS) {
                tracing::warn!(
                    code = "analytics_cascade_failed",
                    "cascade stage {stage} failed: {e}"
                );
            }
        }
        if let Err(e) = rollup::sweep_retention(
            &conn,
            self.retention_ms[0],
            self.retention_ms[1..].try_into().unwrap(),
            now,
            256,
        ) {
            tracing::warn!(
                code = "analytics_retention_failed",
                "retention sweep failed: {e}"
            );
        } else if rolled > 0 {
            tracing::debug!(
                code = "analytics_rollup",
                windows = rolled,
                "rollup pass complete"
            );
        }
    }

    /// Records accepted by `record` but dropped (channel full). The
    /// honest loss counter for the never-block posture.
    pub fn dropped_records(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Run a read-only query against the store (admin endpoints). The
    /// connection is shared with the writer behind one mutex; queries
    /// are rollup-table scans sized for the "week under 100 ms"
    /// contract, so contention is short and rare.
    pub fn query<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        let conn = self.conn.lock().unwrap();
        f(&conn)
    }

    /// The request-completion hot path (DW-043): fire-and-forget record
    /// of one finished request. NEVER blocks — a bounded-channel
    /// `try_send` that drops and counts on full.
    pub fn record(&self, rec: &AccessRecord) {
        let raw = RawRecord::from(rec, now_ms());
        self.offer(raw);
    }

    /// Offer one raw record to the writer channel; drop-and-count on a
    /// full channel (the never-block policy shared by the hot path and
    /// the extension-seam impl below).
    fn offer(&self, raw: RawRecord) {
        if self.tx.try_send(raw).is_err() {
            let n = self.dropped.fetch_add(1, Ordering::Relaxed);
            if n.is_multiple_of(4096) {
                tracing::warn!(
                    code = "analytics_channel_full",
                    total_dropped = n + 1,
                    "analytics channel full; dropping records (never blocking the dataplane)"
                );
            }
        }
    }
}

/// The M1 extension contract (feature analysis 11.4): the embedded
/// store IS an `extensions::analytics::AnalyticsSink`. The trait's
/// failure model allows perpetual `Ok` — "accepted", not "persisted" —
/// which is exactly the drop-and-count policy here (a full channel is
/// the sink's own overload to absorb, not the caller's problem).
#[async_trait::async_trait]
impl crate::extensions::analytics::AnalyticsSink for EmbeddedAnalytics {
    async fn record(
        &self,
        event: crate::extensions::analytics::Event,
    ) -> Result<(), crate::extensions::ExtensionsError> {
        self.offer(RawRecord::from_event(&event));
        Ok(())
    }
}
