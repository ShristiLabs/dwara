# Enterprise features

Dwara is open-core: the default build is the OSS edition (Apache-2.0),
and a small set of features that span multiple instances or require a
separate license are gated behind an enterprise license. In an OSS
build every enterprise feature is inert - a config block for one is
accepted but ignored, and the gateway runs in OSS mode regardless.

For the complete feature-by-feature comparison of the two editions, see
[Editions: OSS vs Enterprise](./editions). To configure the license
gate, start with [Enterprise licensing](./licensing); the remaining
pages cover each gated feature.

## In this section

**Reference:**

- [Editions: OSS vs Enterprise](./editions) - the full feature matrix
  and how each edition is gated.
- [Feature reference](./feature-reference) - all cargo feature flags,
  their edition gating, build commands, and maturity status.
- [Enterprise licensing](./licensing) - the OSS vs enterprise split,
  the `license` config block, and how the gate is enforced.

**Shared-state extensions** (single-instance features backed by external
infrastructure for fleet-wide state):

- [Distributed Redis rate limiter](./redis-rate-limiter) - move GCRA
  bucket state to Redis so every instance shares one limit.
- [Distributed cache](./distributed-cache) - two-tier response caching
  with a shared Redis backend across all instances.
- [Config convergence](./config-convergence) - share config generation
  state across instances via a backend so a reload converges everywhere.
- [Vault secrets](./vault-secrets) - resolve secrets at
  request time from HashiCorp Vault.
- [KMS secrets](./kms-secrets) - resolve secrets at request time
  from a cloud KMS provider.

**Multi-tenant management:**

- [Workspaces](./workspaces) - multi-tenant isolation: each workspace
  owns its config subtree and consumers.
- [RBAC](./rbac) - role-based access control over gateway resources.
- [Audit log](./audit-log) - the append-only record of admin and API
  activity.

**Fleet and control plane** (multi-instance coordination):

- [CP/DP split](./cp-dp-split) - the `dwara-controller` /
  `dwara-edge` control-plane / data-plane architecture.
- [Cluster sync (GA)](./cluster-sync) - hardened convergence for the
  CP/DP split control plane: conflict resolution, split-brain guards,
  and version skew tolerance.
- [Ent controller persistence](./ent-controller-persistence) - the
  controller's PostgreSQL durable store for config snapshots, license
  state, fleet membership, and federated analytics.
- [Service mesh mode](./service-mesh) - run the gateway as a sidecar
  for east-west traffic between services with identity, mTLS, and
  policy.

**Cross-referenced from other sections:**

- [Global load balancing and data residency](./cp-dp-split#global-load-balancing-and-data-residency) - locality-aware endpoint selection and region-restricted routing for the CP/DP split fleet.
- [Federated analytics](./analytics#federated-analytics) - aggregate analytics across all edges in a CP/DP split fleet.
- [Fleet operations](./cluster-sync#fleet-operations) - version skew policy, fleet status, and rolling upgrade orchestration.
- [Web console v2](./web-console#console-v2) - CRUD operations, fleet views, config editor, and workspace switcher.
- [AI credential pools](./ai-gateway#credential-pools) - multi-key rotation with 429 quarantine for AI providers.

**Runnable demo:**

- [Enterprise quickstart](../demos/enterprise-quickstart) - a CP/DP
  split topology on one Docker network: a controller broadcasting config
  to two edge/gateway data planes. One `docker compose up`, one config
  file, watch the fleet converge.
- [`demos/11-enterprise/`](https://github.com/shristilabs/dwara/tree/main/demos/11-enterprise) - a live stack for every feature in this
  section, run with the OSS image: the test scripts document each
  enterprise config block (accepted but inert) and verify the
  OSS-equivalent behavior. The category README covers prerequisites,
  test scripts, and teardown.
