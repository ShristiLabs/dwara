//! Read side of the analytics store (DW-043): dashboard series, Top-N
//! reports, and the structured query endpoint's translator.
//!
//! Every query reads ONLY the rollup tables (the dashboard contract is
//! "week of traffic under 100 ms" — that is rollup-shaped work, not
//! raw-scan work). All dynamic values bind as SQL parameters; the ONLY
//! strings interpolated into SQL are schema identifiers chosen from
//! closed sets ([`DIM_COLUMNS`]) — the structured query endpoint never
//! accepts SQL text.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::rollup::GRANULARITIES_MS;
use super::schema::{percentile, BUCKET_COLS};

/// The fixed dimension columns queries may group or filter by. The
/// closed set the structured endpoint accepts; also the dashboard's
/// drill-down axes.
pub const DIM_COLUMNS: [&str; 6] = [
    "listener",
    "route",
    "upstream",
    "consumer",
    "method",
    "status_class",
];

/// One point of a dashboard series.
#[derive(Debug, Serialize)]
pub struct SeriesPoint {
    /// Window start (ms since epoch).
    pub window_start: i64,
    pub requests: i64,
    pub errors: i64,
    pub error_rate: f64,
    pub rate_limited: i64,
    pub shed: i64,
    pub avg_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    /// The group-by key values, when the series is grouped (parallel
    /// to the query's single group column).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// Equality filters on dimension columns (dashboard drill-down).
#[derive(Debug, Default, Clone)]
pub struct Filters {
    pub listener: Option<String>,
    pub route: Option<String>,
    pub upstream: Option<String>,
    pub consumer: Option<String>,
    pub method: Option<String>,
    pub status_class: Option<String>,
}

impl Filters {
    /// WHERE fragments (leading ` AND ...` each) plus their bind
    /// values, in the order the fragments appear.
    fn clauses(&self) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
        let mut sql = String::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        for (col, val) in [
            ("listener", &self.listener),
            ("route", &self.route),
            ("upstream", &self.upstream),
            ("consumer", &self.consumer),
            ("method", &self.method),
            ("status_class", &self.status_class),
        ] {
            if let Some(v) = val {
                sql.push_str(&format!(" AND {col} = ?"));
                params.push(Box::new(v.clone()));
            }
        }
        (sql, params)
    }
}

/// Shared aggregate read state: 5 metric sums plus 13 bucket sums.
struct Agg {
    requests: i64,
    errors: i64,
    rate_limited: i64,
    shed: i64,
    duration_sum_ms: f64,
    buckets: Vec<i64>,
}

/// Shared aggregate read: 5 metric sums then 13 bucket sums starting
/// at column `start`. NULL-tolerant: an UNGROUPED aggregate over an
/// empty range still yields one all-NULL row (there is no GROUP BY to
/// eliminate it), and the documented totals shape is zeros, not a
/// type error (found by DW-120's totals statement; grouped reads are
/// never NULL — a group exists only where rows do).
fn read_agg(row: &rusqlite::Row<'_>, start: usize) -> rusqlite::Result<Agg> {
    let mut i = start;
    let requests = row.get::<_, Option<i64>>(i)?.unwrap_or(0);
    i += 1;
    let errors = row.get::<_, Option<i64>>(i)?.unwrap_or(0);
    i += 1;
    let rate_limited = row.get::<_, Option<i64>>(i)?.unwrap_or(0);
    i += 1;
    let shed = row.get::<_, Option<i64>>(i)?.unwrap_or(0);
    i += 1;
    let duration_sum_ms = row.get::<_, Option<f64>>(i)?.unwrap_or(0.0);
    i += 1;
    let mut buckets = Vec::with_capacity(BUCKET_COLS);
    for _ in 0..BUCKET_COLS {
        buckets.push(row.get::<_, Option<i64>>(i)?.unwrap_or(0));
        i += 1;
    }
    Ok(Agg {
        requests,
        errors,
        rate_limited,
        shed,
        duration_sum_ms,
        buckets,
    })
}

fn metrics_of(a: &Agg) -> (f64, f64, f64, f64, f64, f64, f64) {
    let n = a.requests.max(0);
    (
        if n > 0 {
            a.errors as f64 / n as f64
        } else {
            0.0
        },
        a.rate_limited as f64,
        a.shed as f64,
        if n > 0 {
            a.duration_sum_ms / n as f64
        } else {
            0.0
        },
        percentile(&a.buckets, 0.50),
        percentile(&a.buckets, 0.95),
        percentile(&a.buckets, 0.99),
    )
}

/// Dashboard series: per-window metric points at a granularity
/// (0=1m..3=1d), optionally split by ONE dimension and filtered — the
/// drill-down axes of the dashboard data API.
pub fn dashboard(
    conn: &Connection,
    from_ms: i64,
    to_ms: i64,
    gran: usize,
    group_by: Option<&str>,
    filters: &Filters,
) -> rusqlite::Result<Vec<SeriesPoint>> {
    let group_col = group_by.and_then(|g| DIM_COLUMNS.iter().find(|c| **c == g).copied());
    let key_sel = group_col.map(|c| format!("{c}, ")).unwrap_or_default();
    let group_key = group_col.unwrap_or("window_start");
    let (filter_sql, bind) = filters.clauses();
    let sql = format!(
        "SELECT window_start, {key_sel}
                SUM(requests), SUM(errors), SUM(rate_limited), SUM(shed),
                SUM(duration_sum_ms),
                SUM(b0), SUM(b1), SUM(b2), SUM(b3), SUM(b4), SUM(b5),
                SUM(b6), SUM(b7), SUM(b8), SUM(b9), SUM(b10), SUM(b11),
                SUM(b12)
         FROM rollup_fixed
         WHERE gran = ? AND window_start >= ? AND window_start < ?{filter_sql}
         GROUP BY window_start, {group_key}
         ORDER BY window_start ASC"
    );
    let mut all: Vec<Box<dyn rusqlite::ToSql>> =
        vec![Box::new(gran as i64), Box::new(from_ms), Box::new(to_ms)];
    all.extend(bind);
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(all.iter().map(|p| p.as_ref())))?;
    let key_len = usize::from(group_col.is_some());
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let window_start: i64 = row.get(0)?;
        let key = if key_len == 1 {
            Some(row.get::<_, String>(1)?)
        } else {
            None
        };
        let agg = read_agg(row, 1 + key_len)?;
        let (error_rate, rate_limited, shed, avg_ms, p50, p95, p99) = metrics_of(&agg);
        out.push(SeriesPoint {
            window_start,
            requests: agg.requests,
            errors: agg.errors,
            error_rate,
            rate_limited: rate_limited as i64,
            shed: shed as i64,
            avg_ms,
            p50_ms: p50,
            p95_ms: p95,
            p99_ms: p99,
            key,
        });
    }
    Ok(out)
}

/// Top-N report kinds (the five frozen in the feature analysis).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopKind {
    Consumers,
    Routes,
    Slowest,
    ErrorProne,
    RateLimited,
}

impl TopKind {
    /// Parse the endpoint's `kind` parameter. The closed set.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "consumers" => Some(TopKind::Consumers),
            "routes" => Some(TopKind::Routes),
            "slowest" => Some(TopKind::Slowest),
            "error_prone" => Some(TopKind::ErrorProne),
            "rate_limited" => Some(TopKind::RateLimited),
            _ => None,
        }
    }
    fn as_str(&self) -> &'static str {
        match self {
            TopKind::Consumers => "consumers",
            TopKind::Routes => "routes",
            TopKind::Slowest => "slowest",
            TopKind::ErrorProne => "error_prone",
            TopKind::RateLimited => "rate_limited",
        }
    }
}

/// One Top-N entry.
#[derive(Debug, Serialize)]
pub struct TopEntry {
    pub kind: &'static str,
    pub name: String,
    pub requests: i64,
    pub errors: i64,
    pub error_rate: f64,
    pub avg_ms: f64,
    pub p95_ms: f64,
    pub rate_limited: i64,
}

/// Top-N over a time range, summed across the FINEST granularity's
/// windows (summing finer windows loses nothing — the whole schema is
/// additive).
pub fn top(
    conn: &Connection,
    kind: TopKind,
    from_ms: i64,
    to_ms: i64,
    limit: usize,
) -> rusqlite::Result<Vec<TopEntry>> {
    let group = match kind {
        TopKind::Consumers | TopKind::RateLimited => "consumer",
        TopKind::Routes | TopKind::Slowest | TopKind::ErrorProne => "route",
    };
    let order = match kind {
        TopKind::Consumers | TopKind::Routes => "SUM(requests) DESC",
        TopKind::Slowest => "avg_ms DESC",
        TopKind::ErrorProne => "err_rate DESC, SUM(requests) DESC",
        TopKind::RateLimited => "SUM(rate_limited) DESC",
    };
    let sql = format!(
        "SELECT {group} AS name,
                SUM(requests), SUM(errors), SUM(rate_limited), SUM(shed),
                SUM(duration_sum_ms),
                SUM(b0), SUM(b1), SUM(b2), SUM(b3), SUM(b4), SUM(b5),
                SUM(b6), SUM(b7), SUM(b8), SUM(b9), SUM(b10), SUM(b11),
                SUM(b12),
                (SUM(errors) * 1.0 / MAX(SUM(requests), 1)) AS err_rate,
                (SUM(duration_sum_ms) / MAX(SUM(requests), 1)) AS avg_ms
         FROM rollup_fixed
         WHERE gran = 0 AND window_start >= ?1 AND window_start < ?2
         GROUP BY {group}
         ORDER BY {order}
         LIMIT ?3"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params![from_ms, to_ms, limit as i64])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        let agg = read_agg(row, 1)?;
        let requests = agg.requests.max(0);
        let error_rate = if requests > 0 {
            agg.errors as f64 / requests as f64
        } else {
            0.0
        };
        out.push(TopEntry {
            kind: kind.as_str(),
            name,
            requests,
            errors: agg.errors,
            error_rate,
            avg_ms: if requests > 0 {
                agg.duration_sum_ms / requests as f64
            } else {
                0.0
            },
            p95_ms: percentile(&agg.buckets, 0.95),
            rate_limited: agg.rate_limited,
        });
    }
    Ok(out)
}

/// The structured query endpoint's request body (DW-043): a closed
/// grammar translated to SQL — never SQL text from the caller.
#[derive(Debug, Deserialize)]
pub struct StructuredQuery {
    pub from_ms: i64,
    pub to_ms: i64,
    /// Granularity index 0..=3 (1m/5m/1h/1d).
    pub gran: usize,
    /// Dimension columns to group by (closed set; empty = one totals
    /// row).
    #[serde(default)]
    pub group_by: Vec<String>,
    /// Equality filters on dimension columns.
    #[serde(default)]
    pub filters: FiltersBody,
    /// Maximum returned rows (default 1000, hard cap 10 000).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// The filter map of a [`StructuredQuery`]: column -> required value.
#[derive(Debug, Default, Deserialize)]
pub struct FiltersBody {
    pub listener: Option<String>,
    pub route: Option<String>,
    pub upstream: Option<String>,
    pub consumer: Option<String>,
    pub method: Option<String>,
    pub status_class: Option<String>,
}

/// Why a structured query was rejected before SQL was built.
#[derive(Debug)]
pub enum QueryError {
    UnknownGroupBy(String),
    BadGranularity(usize),
    BadRange,
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryError::UnknownGroupBy(g) => write!(
                f,
                "unknown group_by '{g}' (one of: {})",
                DIM_COLUMNS.join(", ")
            ),
            QueryError::BadGranularity(g) => {
                write!(f, "gran must be 0..=3 (1m/5m/1h/1d), got {g}")
            }
            QueryError::BadRange => write!(f, "from_ms must be < to_ms"),
        }
    }
}

impl std::error::Error for QueryError {}

impl StructuredQuery {
    /// Reject anything outside the closed grammar.
    pub fn validate(&self) -> Result<(), QueryError> {
        if self.gran >= GRANULARITIES_MS.len() {
            return Err(QueryError::BadGranularity(self.gran));
        }
        if self.from_ms >= self.to_ms {
            return Err(QueryError::BadRange);
        }
        for g in &self.group_by {
            if !DIM_COLUMNS.contains(&g.as_str()) {
                return Err(QueryError::UnknownGroupBy(g.clone()));
            }
        }
        Ok(())
    }
}

/// The structured query endpoint's row: group key (in the query's
/// `group_by` order) plus the full metric set.
#[derive(Debug, Serialize)]
pub struct QueryRow {
    pub key: Vec<String>,
    pub requests: i64,
    pub errors: i64,
    pub error_rate: f64,
    pub rate_limited: i64,
    pub shed: i64,
    pub avg_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

/// Execute a validated structured query. Range-aggregate shape: the
/// window column is NOT grouped (per-window series is the dashboard
/// endpoint's job); rows order by request volume descending.
pub fn structured(conn: &Connection, q: &StructuredQuery) -> rusqlite::Result<Vec<QueryRow>> {
    let key_len = q.group_by.len();
    let key_sel = if key_len == 0 {
        String::new()
    } else {
        format!("{}, ", q.group_by.join(", "))
    };
    let filters = Filters {
        listener: q.filters.listener.clone(),
        route: q.filters.route.clone(),
        upstream: q.filters.upstream.clone(),
        consumer: q.filters.consumer.clone(),
        method: q.filters.method.clone(),
        status_class: q.filters.status_class.clone(),
    };
    let (filter_sql, bind) = filters.clauses();
    let sql = format!(
        "SELECT {key_sel}
                SUM(requests), SUM(errors), SUM(rate_limited), SUM(shed),
                SUM(duration_sum_ms),
                SUM(b0), SUM(b1), SUM(b2), SUM(b3), SUM(b4), SUM(b5),
                SUM(b6), SUM(b7), SUM(b8), SUM(b9), SUM(b10), SUM(b11),
                SUM(b12)
         FROM rollup_fixed
         WHERE gran = ? AND window_start >= ? AND window_start < ?{filter_sql}
         {group_all}
         ORDER BY SUM(requests) DESC
         LIMIT ?",
        group_all = if key_len == 0 {
            // No group keys: a plain aggregate over the range — ONE
            // totals row (the documented shape). A literal `GROUP BY
            // 1` would resolve positionally to the leading SUM(...) —
            // an invalid aggregate-in-GROUP-BY (found by DW-120's
            // totals statement).
            String::new()
        } else {
            format!("GROUP BY {}", q.group_by.join(", "))
        }
    );
    let limit = q.limit.unwrap_or(1000).min(10_000);
    let mut all: Vec<Box<dyn rusqlite::ToSql>> = vec![
        Box::new(q.gran as i64),
        Box::new(q.from_ms),
        Box::new(q.to_ms),
    ];
    all.extend(bind);
    all.push(Box::new(limit as i64));
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(all.iter().map(|p| p.as_ref())))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut key = Vec::with_capacity(key_len);
        for i in 0..key_len {
            key.push(row.get::<_, String>(i)?);
        }
        let agg = read_agg(row, key_len)?;
        let (error_rate, rate_limited, shed, avg_ms, p50, p95, p99) = metrics_of(&agg);
        out.push(QueryRow {
            key,
            requests: agg.requests,
            errors: agg.errors,
            error_rate,
            rate_limited: rate_limited as i64,
            shed: shed as i64,
            avg_ms,
            p50_ms: p50,
            p95_ms: p95,
            p99_ms: p99,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// DW-079: spend aggregation over the `ai_spend` table.
// ---------------------------------------------------------------------------

/// The dimension columns the spend summary may group by (DW-079). The
/// closed set the spend endpoint accepts — a subset of the `ai_spend`
/// table's columns (no `provider`/`version` to keep the billing view
/// focused on who/what, not the routing detail).
pub const SPEND_GROUP_COLUMNS: [&str; 3] = ["consumer", "team", "model"];

/// One spend summary row (DW-079): aggregated token and cost totals
/// for one group key over a billing window.
#[derive(Debug, Serialize)]
pub struct SpendRow {
    /// The group-by key values, in the query's `group_by` order (empty
    /// for an ungrouped totals row).
    pub key: Vec<String>,
    /// Sum of prompt (input) tokens.
    pub prompt_tokens: i64,
    /// Sum of completion (output) tokens.
    pub completion_tokens: i64,
    /// Sum of total tokens.
    pub total_tokens: i64,
    /// Sum of priced cost (integer micro-USD).
    pub cost_micros: i64,
    /// Number of AI requests in the group.
    pub request_count: i64,
}

/// The spend query endpoint's request body (DW-079): a closed grammar
/// over the `ai_spend` table — never SQL text from the caller.
#[derive(Debug, Deserialize)]
pub struct SpendQuery {
    pub from_ms: i64,
    pub to_ms: i64,
    /// Dimensions to group by (closed set: consumer, team, model).
    /// Empty = one totals row.
    #[serde(default)]
    pub group_by: Vec<String>,
    /// Maximum returned rows (default 10 000, hard cap 10 000).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Why a spend query was rejected before SQL was built.
#[derive(Debug)]
pub enum SpendQueryError {
    UnknownGroupBy(String),
    BadRange,
}

impl std::fmt::Display for SpendQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpendQueryError::UnknownGroupBy(g) => write!(
                f,
                "unknown group_by '{g}' (one of: {})",
                SPEND_GROUP_COLUMNS.join(", ")
            ),
            SpendQueryError::BadRange => write!(f, "from_ms must be < to_ms"),
        }
    }
}

impl std::error::Error for SpendQueryError {}

impl SpendQuery {
    /// Reject anything outside the closed grammar.
    pub fn validate(&self) -> Result<(), SpendQueryError> {
        if self.from_ms >= self.to_ms {
            return Err(SpendQueryError::BadRange);
        }
        for g in &self.group_by {
            if !SPEND_GROUP_COLUMNS.contains(&g.as_str()) {
                return Err(SpendQueryError::UnknownGroupBy(g.clone()));
            }
        }
        Ok(())
    }
}

/// Execute a validated spend query (DW-079): aggregate the `ai_spend`
/// table over a billing window, grouped by the requested dimensions.
/// Rows order by cost descending (the billing-relevant axis). Reads
/// the RAW `ai_spend` rows directly — spend is per-request, not
/// rolled up (the volume is orders of magnitude below the access
/// record path, and billing windows are short).
pub fn spend_summary(conn: &Connection, q: &SpendQuery) -> rusqlite::Result<Vec<SpendRow>> {
    let key_len = q.group_by.len();
    let key_sel = if key_len == 0 {
        String::new()
    } else {
        format!("{}, ", q.group_by.join(", "))
    };
    let group_all = if key_len == 0 {
        String::new()
    } else {
        format!("GROUP BY {}", q.group_by.join(", "))
    };
    let sql = format!(
        "SELECT {key_sel}
                SUM(prompt_tokens), SUM(completion_tokens), SUM(total_tokens),
                SUM(cost_micros), COUNT(*)
         FROM ai_spend
         WHERE ts_ms >= ? AND ts_ms < ?
         {group_all}
         ORDER BY SUM(cost_micros) DESC
         LIMIT ?"
    );
    let limit = q.limit.unwrap_or(10_000).min(10_000);
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params![q.from_ms, q.to_ms, limit as i64])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut key = Vec::with_capacity(key_len);
        for i in 0..key_len {
            key.push(row.get::<_, String>(i)?);
        }
        let base = key_len;
        out.push(SpendRow {
            key,
            prompt_tokens: row.get::<_, i64>(base)?,
            completion_tokens: row.get::<_, i64>(base + 1)?,
            total_tokens: row.get::<_, i64>(base + 2)?,
            cost_micros: row.get::<_, i64>(base + 3)?,
            request_count: row.get::<_, i64>(base + 4)?,
        });
    }
    Ok(out)
}
