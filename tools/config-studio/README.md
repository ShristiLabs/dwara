# Dwara Config Studio

A single-file, offline browser tool for building, visualizing,
validating, and editing Dwara gateway YAML configs. Operators open
`index.html` in any modern browser - no server, no build step, no
network access required.

## What it does

- **Generate**: start from a template (reverse proxy, API with key
  auth + rate limiting, TLS edge, AI gateway, or blank) and build the
  config through schema-driven forms. Required fields are shown
  first; optional fields are collapsed but never hidden.
  Cross-reference fields are ref-aware: `route.service` and
  `service.upstream` are dropdowns of the names you have defined, and
  policy attachments are toggle chips - dangling references are hard
  to create and easy to see.
- **Visualize**: an Overview shows entity counts, the request wiring
  table (route -> service -> upstream -> endpoints) with
  dangling-reference chips, and copyable next-step commands
  (`dwara validate`, `DWARA_CONFIG=... dwara run`). A Diagrams view
  generates live mermaid flowcharts from the current config: request
  flow (listener -> route -> service -> upstream -> endpoints),
  policy attachments (where each policy attaches across the
  consumer/route/service/listener/global precedence chain), consumer
  and auth provider relationships (JWT, OIDC, HMAC, mTLS), and the AI
  gateway topology (model aliases -> providers -> upstreams, with
  failover and canary edges). Click any diagram node to jump to its
  editor; dangling references are shown in red.
- **Validate**: structural validation against the same JSON Schema
  Dwara generates from its Rust config types (`dwara schema`), plus
  cross-reference checks the schema cannot express (route -> service
  -> upstream name resolution, policy refs, AI model alias ->
  provider refs) and advisory warnings (unauthenticated public
  routes, plaintext listeners on all interfaces).
- **Edit YAML**: a live YAML pane mirrors the forms; "Edit as YAML"
  accepts pasted configs and round-trips them back into the builder
  (parsed with the vendored js-yaml).
- **Learn in place**: a Help overlay explains the workflow and the
  listener -> route -> service -> upstream -> endpoint model, with
  links to the published guides; every section header deep-links its
  docs page.

The tool only helps produce the YAML. **Loading it into Dwara is a
separate step**: `dwara validate dwara.yaml`, then run the gateway
with `DWARA_CONFIG=dwara.yaml`. Browser validation is structural;
`dwara validate` remains the final authority for semantic checks
(route conflicts, reachable TLS files, feature interactions).

## Adding and removing things

- **Add**: the "+ add" button under each entity list in the sidebar
  (listeners, routes, services, upstreams, consumers, policies), or
  "Add ... block" for optional sections like `ai`.
- **Remove an entity** (a listener, route, etc.): select it in the
  sidebar, then "remove this route/listener/..." in the section
  header. Removing the last entity drops the key from the YAML
  entirely (Dwara rejects `routes: []` unless `allow_empty_routes`
  is set, so empty blocks are never emitted).
- **Remove nested items** (endpoints, credentials, policy refs, AI
  model entries): the "remove" button on each item card. Reordering
  uses the up/down buttons on the same card.
- **Remove an optional block** (e.g. `tls:`): "Remove ... block" at
  the bottom of the block.
- **Start over**: Clear wipes the whole draft (after confirmation).

Drafts autosave to browser localStorage. Secrets should be written
as `${env:...}` / `${file:...}` references, which this tool does not
resolve.

Internal development tracking references present in the upstream
schema descriptions (issue-tracker IDs, enhancement-catalog IDs,
bare GitHub issue refs, internal analysis-doc pointers) are
scrubbed at build time; the schema embedded here matches
`config-reference.json` in every other respect. Technical tokens
(SHA-256, HTTP-01, "N-1 or N+1" version-skew semantics) are
preserved.

## End-user documentation

The tool links to the published documentation site where it helps:

- Getting started: https://shristilabs.github.io/dwara/guide/getting-started
- Configuration guide: https://shristilabs.github.io/dwara/guide/configuration
- Configuration schema reference: https://shristilabs.github.io/dwara/reference/configuration-schema
- CLI reference (validate/run): https://shristilabs.github.io/dwara/guide/cli
- Routing, traffic policy, security, AI gateway, observability,
  admin API guides: https://shristilabs.github.io/dwara/

Section headers in the builder deep-link to the matching guide page
(routing, traffic policy, security, AI gateway, observability and
analytics, admin API, service mesh, API lifecycle, enterprise).

## Files

| File | Purpose |
|---|---|
| `index.html` | The built, distributable tool (commit this) |
| `src/app.template.html` | Application source with build markers |
| `vendor/js-yaml.min.js` | js-yaml 4.1.0 (MIT) for YAML round-tripping |
| `vendor/mermaid.min.js` | mermaid 11.15.0 (MIT) for diagram rendering |
| `vendor/mermaid-LICENSE` | mermaid MIT license text |
| `build.py` | Inlines schema + js-yaml + mermaid into the template |

## Rebuilding

Whenever `config-reference.json` changes at the repo root (it is
regenerated and diffed by CI via `dwara schema`), rebuild:

```sh
python3 tools/config-studio/build.py
```

Requires Python 3 (stdlib only).

## Vendored dependencies

`vendor/js-yaml.min.js` is js-yaml 4.1.0, MIT licensed
(https://github.com/nodeca/js-yaml). The license header is preserved
at the top of the file. It is embedded at build time so the tool
works fully offline; no other third-party code is included.

`vendor/mermaid.min.js` is mermaid 11.15.0, MIT licensed
(https://github.com/mermaid-js/mermaid). The license is preserved as
`vendor/mermaid-LICENSE`. It is embedded at build time to render the
diagram flowcharts offline.
