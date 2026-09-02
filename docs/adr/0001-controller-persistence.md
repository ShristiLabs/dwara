# ADR-0001: Ent controller durable store selection

- **Status:** Accepted
- **Date:** 2025-09-02
- **Tracking:** DW-116

## Context

The Ent controller (the control-plane process in the CP/DP split
architecture, DW-066) needs a durable store for several distinct
workloads:

- **Config snapshots** — the published gateway configurations
  distributed to edges over the controller-to-edge gRPC transport
  (`cp_dp/transport.rs`).
- **License state** — verified license claims, grace-period counters,
  and feature-claim flags (DW-032).
- **Fleet membership** — registered edges, version skew policy, and
  rolling-upgrade orchestration state (DW-098).
- **Federated analytics** — edge-to-controller analytics streams
  aggregated controller-side through the `AnalyticsCollector` trait
  (DW-095).
- **Runtime override tables** — prompt-version overrides, MCP session
  management, and the AI governance/prompt-log audit tables
  (`state/` and `analytics/` schemas).

The current OSS path uses an embedded SQLite store (`state/` and
`analytics/` each own a SQLite file with `rusqlite_migration` files).
SQLite is the right call for the single-process OSS edition: zero
external dependencies, file-backed, trivial to ship. It does not,
however, scale to the multi-DP HA posture the Ent controller targets:
multiple controller replicas behind a load balancer, each needing a
consistent view of config, license, and fleet state, and each able to
accept concurrent writes from many edges. SQLite's single-writer model
and file-based concurrency are a poor fit for that topology.

This decision covers only the Ent controller's durable store. The OSS
edge and OSS single-process editions continue to use the embedded
SQLite stores unchanged; the `extensions::ConfigSource` and
`analytics::AnalyticsSink` seams keep the two paths behind a single
trait surface.

## Decision

PostgreSQL is selected as the Ent controller's durable store.

## Rationale

- **SQL migrations map 1:1 from the existing `rusqlite_migration`
  files.** The `state/` migrations (001-007) and `analytics/`
  migrations (v1-v9) are already written as ordered SQL DDL with
  semver-style schema versions. Porting them to PostgreSQL DDL is a
  mechanical exercise (type adjustments, `SERIAL`/`BIGSERIAL` vs
  `INTEGER PRIMARY KEY`, `RETURNING` clauses) rather than a redesign.
  The schema-version ledger pattern carries over directly.
- **Strong HA/backup story.** Streaming replication plus point-in-time
  recovery (PITR) give the controller the durability and recovery
  posture an HA control plane requires. Backup is a solved,
  well-understood operational problem rather than a custom
  file-snapshot scheme.
- **Operational familiarity.** PostgreSQL aligns with the licensing
  platform's existing ops surface — the same team that runs the
  licensing infrastructure runs the controller store, so there is no
  new operational skill barrier.
- **Handles concurrent DP writers.** Multiple controller replicas and
  many edges produce concurrent writes. PostgreSQL's MVCC and
  row-level locking handle that without the single-writer bottleneck
  of SQLite, and `SELECT ... FOR UPDATE` / advisory locks cover the
  coordination cases (e.g. fleet-upgrade wave advancement).
- **`LISTEN/NOTIFY` primitive for config convergence.** When a new
  config is published, the controller can `NOTIFY` a channel so
  interested controller processes (and the config-distribution
  transport) wake immediately rather than polling. This gives
  sub-second config-convergence latency without a separate
  coordination service.
- **Audit-grade retention.** `ai_governance_events` and
  `ai_prompt_logs` are audit tables: they need WAL-backed durability,
  retention policies, and queryability for compliance review.
  PostgreSQL's WAL, partitioning, and retention-tooling ecosystem
  fit that bar directly; a KV store would require bolting a separate
  audit store on top.

## Consequences

- **Heavier to ship/embed than SQLite.** PostgreSQL is an external
  database dependency, not an embedded library. The Ent controller's
  deployment story gains a "bring a PostgreSQL instance" prerequisite
  (the quickstart `enterprise/` compose already includes one). The OSS
  edition is unaffected — it keeps the embedded SQLite stores.
- **Separate ops surface.** PostgreSQL adds its own admin/backup/HA
  surface (cluster management, replication setup, vacuum tuning,
  connection pooling). This is accepted as the cost of the HA posture
  and is absorbed by the licensing platform ops team.
- **Migration story.** The `state/` and `analytics/` migration files
  must be ported to PostgreSQL DDL. The schema-version ledger and the
  ordered-migration discipline carry over; the DDL itself is ported
  per-phase (see Migration plan below).
- **The seams absorb the change.** `extensions::ConfigSource` and
  `analytics::AnalyticsSink` are the intended swappable seams (see
  [Extension points](../features/extension-points.md)). The
  PostgreSQL implementations sit behind them, so the controller's
  transport layer (`cp_dp/transport.rs`) and the rest of the
  dataplane are unaffected — they consume the trait, not the store.

## Alternatives considered

- **etcd.** Purpose-built key/value store with a first-class watch
  primitive, strong consistency, and a compact operational profile.
  Excellent for config distribution and fleet membership. Rejected as
  the sole store because the analytics/audit tables
  (`ai_governance_events`, `ai_prompt_logs`, the rollup cascade) are
  relational and retention-heavy — modeling them as KV would push the
  query and retention logic into the application and lose SQL's
  audit-query ergonomics.
- **Redis-only.** Lowest operational friction and very low latency.
  Rejected because Redis's durability/HA story (RDB + AOF, async
  replication) is weaker than PostgreSQL's for audit-grade tables, and
  the retention/partitioning tooling for long-lived audit data is
  thinner. The risk of data loss on a controller failover is
  unacceptable for compliance-sensitive tables.
- **Hybrid (PostgreSQL + etcd).** PostgreSQL for the
  analytics/audit/license tables, etcd for config distribution and
  fleet membership (leveraging etcd's watch for sub-second config
  convergence). Rejected as the initial choice because it introduces
  two stores, two ops surfaces, and a cross-store consistency
  boundary. It remains the fallback if a PoC shows a single
  PostgreSQL store cannot meet both the watch-latency bar (config
  convergence) and the audit-retention bar simultaneously —
  `LISTEN/NOTIFY` is the single-store mechanism that must prove out
  first.

## Fleet sizing target

The decision is sized against the following target workload (the
upper bound the initial implementation must handle without
re-architecting):

- **Max 100 edges** in a single controller's fleet.
- **10 config-publishes/day** — each publish writes a new config
  snapshot and notifies edges.
- **10K analytics events/sec/edge** — federated analytics ingress at
  the controller, batched through `PostgresAnalyticsSink`.
- **30-day raw retention** for raw analytics records.
- **1-year rollup retention** for the additive rollup cascade
  (1m/5m/1h/1d).

These numbers drive connection-pool sizing, batch-insert throughput
targets, and the retention/partitioning strategy for the analytics
tables.

## Migration plan

The migration is phased so each step is independently shippable and
revertible. Each phase lands behind the relevant trait seam before the
next begins.

- **Phase 1: `PostgresConfigSource` behind
  `extensions::ConfigSource`.** Reads config snapshots from
  PostgreSQL; uses `LISTEN/NOTIFY` for change events so the
  config-distribution transport wakes on publish. The SQLite
  `ConfigSource` remains the OSS default.
- **Phase 2: `PostgresAnalyticsSink` behind
  `analytics::AnalyticsSink`.** Batch INSERT path with the same
  fire-and-forget contract (drop-and-count on full, never block the
  request path) as the embedded SQLite sink.
- **Phase 3: Port `state/` migrations (001-007) to PostgreSQL DDL.**
  Mechanical port of the schema-version ledger and the state tables
  (including the DW-086 prompt-overrides and DW-087 MCP-session
  tables).
- **Phase 4: Port `analytics/` migrations (v1-v9) to PostgreSQL DDL.**
  Port the raw/rollup cascade, `ai_spend`, `ai_governance_events`,
  `ai_prompt_logs`, the experimentation tables, `mcp_tool_calls`, and
  the DW-093 correlation-id index.
- **Phase 5: Federated analytics aggregation (DW-095) through the
  `AnalyticsCollector` trait.** The controller-side collector
  forwards aggregated edge streams into `PostgresAnalyticsSink`,
  completing the end-to-end federated analytics path.

## Mapping to existing seams

The decision is deliberately scoped to the swappable seams so the
controller's transport and dataplane layers are untouched:

- **`extensions::ConfigSource` -> `PostgresConfigSource`** — reads
  config snapshots from PostgreSQL; subscribes to a `LISTEN/NOTIFY`
  channel for change events that drive config convergence to edges.
- **`analytics::AnalyticsSink` -> `PostgresAnalyticsSink`** — batch
  INSERT into the analytics tables; same fire-and-forget contract as
  the embedded SQLite sink (drop-and-count on full channel, never
  blocks the request path).
- **`ai::analytics::FederatedAnalyticsSink` -> controller-side
  `AnalyticsCollector` forwards to `PostgresAnalyticsSink`** — edge
  streams arrive over the `PublishAnalytics` RPC, the collector
  aggregates, and the aggregated records land in PostgreSQL through
  the same `AnalyticsSink` the local path uses.

## References

- [CP/DP split](../features/cp-dp-split.md) — DW-066, the control-
  plane/data-plane architecture this store serves.
- [Extension points](../features/extension-points.md) — the
  `ConfigSource` and `AnalyticsSink` seams the PostgreSQL
  implementations sit behind.
- [State store](../features/state-store.md) — the existing SQLite
  store and migration discipline being ported.
- [Embedded analytics](../features/analytics.md) — the analytics
  store and rollup cascade being ported (DW-043, DW-095).
- [Enterprise licensing gate](../features/licensing.md) — DW-032,
  the license state this store persists.
