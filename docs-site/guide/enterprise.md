# Enterprise features

Dwara is open-core: the default build is the OSS edition (Apache-2.0),
and a small set of features that span multiple instances or require a
separate license are gated behind an enterprise license. In an OSS
build every enterprise feature is inert - a config block for one is
accepted but ignored, and the gateway runs in OSS mode regardless.

Start with [Enterprise licensing](./licensing) to configure the license
gate; the remaining pages cover each gated feature.

## In this section

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
- [Cedar and OPA authorization](./cedar-opa-authz) - external policy
  engines for fine-grained, attribute-based access control.
