# Dwara Agent Skills

A suite of [Agent Skills](https://agentskills.io/specification) that teach AI
agents (Claude Code, Cursor, Codex CLI, Copilot CLI, Gemini CLI, and any
harness that reads `SKILL.md`) how to configure, secure, operate, and extend
[Dwara](https://github.com/shristilabs/dwara) — the Rust API gateway.

Each skill is a self-contained directory: a `SKILL.md` entry point with
progressively-disclosed `references/`, `assets/` (runnable config examples),
and `scripts/` where useful.

## The suite

| Skill | Use it to |
| --- | --- |
| [`dwara-quickstart`](./dwara-quickstart/) | Install Dwara and get a first gateway serving traffic (Docker quickstart or cargo). |
| [`dwara-config`](./dwara-config/) | Author the single strict YAML config; use the validate → fmt → lint → diff → explain → reload loop; manage secrets and hot reload. |
| [`dwara-ai-gateway`](./dwara-ai-gateway/) | Proxy LLM traffic: providers, model aliases, failover/canary/routing policies, token budgets, guardrails, semantic cache, prompt logging, MCP, A2A. |
| [`dwara-traffic`](./dwara-traffic/) | Routing and matching precedence, load balancing, health checks, retries/hedging/breakers, traffic splitting, caching, transforms, admission control, h3/L4/gRPC. |
| [`dwara-security`](./dwara-security/) | Consumers and credentials (API key, JWT, OIDC, HMAC, mTLS), the authorization chain, IP/GeoIP ACLs, WAF, TLS, secrets. |
| [`dwara-operations`](./dwara-operations/) | The mTLS admin API, hot reload and zero-downtime upgrade, observability, rate limits and quotas, analytics, troubleshooting. |
| [`dwara-migration`](./dwara-migration/) | Import existing config from NGINX, Kong, Envoy, or OpenAPI (with mock mode); Terraform-compatible state; Kubernetes Gateway API. |
| [`dwara-plugins`](./dwara-plugins/) | Extend Dwara: proxy-wasm plugins, native Rust filters, extension traits, filter-chain ordering, plugin registry. |

## Install

From the registry ([skills.sh](https://skills.sh)):

```sh
npx skills add shristilabs/dwara
```

The CLI lists the skills in this repository and installs your selection into
your agent's skills directory (`.claude/skills/`, `.cursor/skills/`, etc.,
depending on the harness).

Manual install (any harness): copy a skill directory into your skills folder:

```sh
git clone https://github.com/shristilabs/dwara
cp -r dwara/skills/dwara-ai-gateway ~/.claude/skills/
```

## Badge

```md
[![skills.sh](https://skills.sh/b/shristilabs/dwara)](https://skills.sh/shristilabs/dwara)
```

## Accuracy model

Gateway behavior moves faster than any snapshot. Every skill in this suite
therefore teaches two ground-truth checks and expects the agent to run them:

1. `dwara-cli schema` — the JSON Schema of the config, generated from the
   running code. If a key is not in the schema, it does not exist in the
   build, no matter what any document says.
2. `dwara-cli validate <file>` — the same Parse → Validate → Compile pipeline
   the gateway runs; reports every issue at once with exact paths.

Edition gating in the skills reflects the build system: the OSS build
compiles in everything except enterprise features (`cargo build --features
ent`); a few advanced surfaces do not have config blocks in the schema yet
and are marked accordingly. When the docs site and the schema disagree, the
schema wins.

Operator documentation: <https://shristilabs.github.io/dwara/>

## Maintenance

- Skills are versioned independently via `metadata.version` in each
  `SKILL.md`; bump on content changes.
- Config examples in `assets/` are trimmed from the runnable
  [quickstart](../quickstart/oss/dwara.yaml) config and should stay
  schema-valid — verify with `dwara-cli validate` after editing.
- Validate frontmatter against the spec with
  [skills-ref](https://github.com/agentskills/agentskills/tree/main/skills-ref):
  `skills-ref validate skills/<skill-name>`.

License: Apache-2.0 (same as the gateway).
