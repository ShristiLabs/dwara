# Ent controller persistence

The Ent edition controller -- the management-plane component that
distributes config to a fleet of gateway data-plane instances -- stores
its durable state in a [PostgreSQL](https://en.wikipedia.org/wiki/PostgreSQL)
database. This page records what the controller persists and the
architecture decision that chose PostgreSQL over the other candidates.
It is short because the decision itself is the point; the operator-facing
configuration is covered in [CP/DP split](./cp-dp-split) and
[Cluster sync](./cluster-sync).

## What the controller stores

The controller's durable store holds four categories of state:

- **Config snapshots.** Every published config version is stored
  immutably, with its version number, author, publish time, and the
  full YAML. The controller serves the current snapshot to data-plane
  instances over the cluster-sync protocol and retains history for
  audit and rollback.
- **License state.** The Ent edition license, its entitlements, and the
  fleet-wide consumption counters (active data-plane instances, feature
  usage against entitlement limits) are persisted so entitlements
  survive a controller restart.
- **Fleet membership.** The set of registered data-plane instances,
  their last-seen heartbeat, reported version, and health status. The
  controller uses this to decide which instances receive a config
  rollout and to surface fleet health in the web console.
- **Federated analytics.** Aggregated analytics streamed up from the
  data-plane instances (see [Analytics stream](./analytics-stream)) are
  persisted in rollup tables for cross-fleet queries and dashboards.

## The decision

The controller's persistence backend was chosen via an architecture
decision record (ADR). The ADR evaluated SQLite, PostgreSQL, and an
external object store. SQLite was rejected because the controller is a
multi-writer service (config publishes, heartbeat updates, and analytics
ingestion can overlap) and SQLite's single-writer model would serialize
those paths. The object-store option was rejected because the query
patterns (fleet membership lookups, rollup aggregation, snapshot
history) are relational and would require a secondary index anyway.
PostgreSQL was chosen for its multi-writer concurrency, mature
operational tooling, and relational fit for the four state categories.

The store is accessed only by the controller; data-plane instances never
touch the database directly. They receive config and report heartbeats
over the cluster-sync protocol, and the controller translates those
interactions into database rows.
