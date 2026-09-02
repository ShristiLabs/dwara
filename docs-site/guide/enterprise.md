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

- [Editions: OSS vs Enterprise](./editions) - the full feature matrix
  and how each edition is gated.
- [Enterprise licensing](./licensing) - the OSS vs enterprise split, the
  `license` config block, and how the gate is enforced.
- [Distributed Redis rate limiter](./redis-rate-limiter) - move GCRA
  bucket state to Redis so every instance shares one limit.
- [Config convergence](./config-convergence) - share config generation
  state across instances via a backend so a reload converges everywhere.
- [Distributed cache](./distributed-cache) - two-tier response caching
  with a shared Redis backend across all instances.
- [Vault and KMS secrets](./vault-kms-secrets) - resolve secrets at
  request time from HashiCorp Vault or a KMS provider.
- [Workspaces, RBAC, and audit](./workspaces-rbac-audit) - multi-tenant
  isolation with role-based access control and an append-only audit log.
- [Cluster sync (GA)](./cluster-sync) - hardened convergence for the
  CP/DP split control plane: conflict resolution, split-brain guards,
  and version skew tolerance.
- [CP/DP split](./cp-dp-split) - the `dwara-controller` /
  `dwara-edge` control-plane / data-plane architecture.
- [Global load balancing and data residency](./cp-dp-split#global-load-balancing-and-data-residency) - locality-aware endpoint selection and region-restricted routing for the CP/DP split fleet.
- [Federated analytics](./analytics#federated-analytics) - aggregate analytics across all edges in a CP/DP split fleet.
- [Fleet operations](./cluster-sync#fleet-operations) - version skew policy, fleet status, and rolling upgrade orchestration.
- [Web console v2](./web-console#console-v2) - CRUD operations, fleet views, config editor, and workspace switcher.
- [AI credential pools](./ai-gateway#credential-pools) - multi-key rotation with 429 quarantine for AI providers.
