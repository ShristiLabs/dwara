# Cluster sync (GA)

Cluster sync is the GA-hardened convergence layer for the CP/DP
split control plane. It adds conflict resolution, split-brain
guards, and version skew tolerance to ensure a fleet of edge
gateways converges on the correct configuration even under
partitions, slow members, and rollbacks.

## When to use this

Use cluster sync when you are running the CP/DP split (DW-066) and
need production-grade convergence guarantees:

- Multiple controllers may publish conflicting generations.
- The fleet must converge after a network partition heals.
- Edges may run different versions during a rolling upgrade.

This is an enterprise feature -- build with the `ent` feature:

```sh
cargo build --features ent
```

## Conflict resolution

When multiple controllers publish different generations
simultaneously (e.g. during a leader election transition), the
conflict is resolved using a configurable strategy:

| Strategy | Description |
|---|---|
| `highest_generation` (default) | The generation with the highest generation number wins. Safest for monotonic generation numbering. |
| `most_recent_timestamp` | The generation with the most recent timestamp wins. Useful when generation numbers reset after a failover. |
| `leader_wins` | The generation from the leader controller wins. Requires leader election metadata. |

Configure the strategy in the controller config:

```yaml
controller:
  conflict_resolution: highest_generation
```

## Split-brain detection

The split-brain detector tracks active controllers and their
last-seen times. A controller is "active" if it has sent a
heartbeat within the lease timeout. If more than one controller is
active, split-brain is detected.

```yaml
controller:
  lease_timeout_seconds: 10
```

When split-brain is detected:

1. The controller logs a warning with the list of active controllers.
2. Edges refuse to accept new generations until the split-brain
   resolves (one controller remains).
3. Edges continue serving traffic with their cached generation.

This prevents two controllers from pushing conflicting configs to
the fleet simultaneously.

## Version skew tolerance

During a rolling upgrade, edges may run different versions than the
controller. The version skew policy controls what happens:

| Policy | Description |
|---|---|
| `allow` | Allow any version skew. The edge accepts the config regardless of version. |
| `allow_minor_skew` (default) | Allow skew within one minor version (e.g. 1.2.x can talk to 1.3.x, but not 2.0.x). |
| `require_exact` | Require exact version match. The edge rejects the config if its version differs. |

```yaml
controller:
  version_skew_policy: allow_minor_skew
```

### How version skew is checked

1. The controller publishes a generation with its version.
2. The edge compares its version to the controller's version using
   the configured policy.
3. If the versions are incompatible, the edge rejects the generation
   and logs a `VersionSkewError` (major skew, minor skew too large,
   or exact mismatch).
4. The edge continues serving traffic with its cached generation.

### Fleet operations (DW-098, Enterprise)

Fleet operations extend the cluster sync layer with fleet-wide status
APIs and rolling upgrade orchestration. This is an enterprise feature
-- build with `--features ent` and a valid license.

**Fleet status APIs:**

- `GET /fleet/skew` -- returns per-edge version compatibility against
  the controller. Each entry reports the edge's version, the
  controller's version, and whether the pair satisfies the configured
  skew policy.
- `GET /fleet/status` -- returns the full fleet configuration and every
  registered edge's version, giving a single snapshot of the whole
  fleet.

**Rolling upgrade orchestration:**

The fleet config block declares the upgrade order so the controller
can roll a new generation out in controlled waves rather than all at
once. A wave is a set of edges selected by a Kubernetes-style
label selector; the controller waits for each wave to converge before
starting the next.

```yaml
fleet:
  upgrade:
    waves:
      - selector: { env: staging }
        max_concurrent: 2
      - selector: { env: canary }
        max_concurrent: 1
      - selector: { env: prod }
        max_concurrent: 3
    halt_on_failure: true
```

- `waves` is an ordered list; each wave's `selector` picks the edges
  it applies to and `max_concurrent` caps how many edges in that wave
  receive the new generation at once.
- `halt_on_failure` (default `true`) stops the rollout when an edge in
  an earlier wave fails to converge, so a bad generation never reaches
  the prod wave.

**Version skew on registration:**

When an edge registers with the controller, the controller checks the
edge's version against the configured skew policy. A skew violation is
**fail-open**: the edge is accepted and continues serving traffic, and
the controller logs a warning so the operator can see the skew. This
keeps the fleet serving during upgrades while making the skew visible.

## Convergence state

The controller tracks convergence state for each generation:

- **Total edges**: the number of registered edges.
- **Acked edges**: edges that have acknowledged the generation.
- **Pending edges**: edges that have not yet acknowledged.
- **Converged**: true when all edges have acknowledged.

The convergence state is exposed via the admin API:

```sh
curl --cert admin.crt --key admin.key \
  https://127.0.0.1:2019/controller/convergence
```

```json
{
  "generation": 42,
  "total_edges": 5,
  "acked_edges": ["edge-1", "edge-2", "edge-3"],
  "pending_edges": ["edge-4", "edge-5"],
  "converged": false,
  "acked_percentage": 60
}
```

## Chaos resilience

The cluster sync layer is validated against three chaos scenarios:

1. **Partition**: some edges are disconnected from the controller.
   After the partition heals, the edges reconnect and acknowledge the
   current generation. The fleet converges.
2. **Slow member**: one edge is slow to acknowledge. The fleet still
   converges (the slow edge eventually acks).
3. **Rollback**: the controller publishes a new generation, then
   rolls back to the previous generation. All edges acknowledge the
   rollback. The fleet converges on the rolled-back generation.

All three scenarios are covered by the chaos test suite and must
converge for the GA gate to pass.

## Lineage

- **DW-054** (M2): shipped a lighter-weight, non-CP/DP-split
  convergence (generation watch + drift report over etcd/Consul).
- **DW-066** (M3): replaced DW-054 with a real control plane
  (`dwara-controller`/`dwara-edge`, gRPC watch).
- **DW-074** (this): GA hardening pass on DW-066's control plane --
  conflict resolution, split-brain guards, version skew tolerance.
