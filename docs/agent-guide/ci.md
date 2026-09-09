# CI workflows

All workflows live in `.github/workflows/`. Every action ref is pinned to a
full commit SHA (`# pinned: <tag> @ <sha>`). Dependabot keeps pins fresh.

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | push/PR to main (path-filtered) | verify (fmt/clippy/build/test + config-reference freshness) + supply-chain (cargo-deny + SBOM) |
| `bench.yml` | scheduled weekly + manual | micro-bench gate/baseline-refresh/soak (`-f job=<value>`) |
| `bench-nightly.yml` | scheduled + manual | nightly bench runs |
| `fuzz.yml` | scheduled weekly + manual | cargo-fuzz on dated nightly pin |
| `soak.yml` | scheduled | soak test runs |
| `chaos.yml` | scheduled | chaos/resilience runs |
| `feature-matrix.yml` | push/PR | cross-feature build/test matrix |
| `release-artifacts.yml` | tag `v*` only | musl binaries + GHCR multi-arch images |
| `docs-site.yml` | push to main touching `docs-site/**` | build + deploy to GitHub Pages |

Bench and fuzz workflows never run on PRs. Dependabot also has an `npm` lane
scoped to `docs-site/`.
