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
- **Visualize**: an Overview shows entity counts and the request
  wiring table (route -> service -> upstream -> endpoints) with
  dangling-reference chips.
- **Validate**: structural validation against the same JSON Schema
  Dwara generates from its Rust config types (`dwara schema`), plus
  cross-reference checks the schema cannot express (route -> service
  -> upstream name resolution, policy refs, AI model alias ->
  provider refs) and advisory warnings (unauthenticated public
  routes, plaintext listeners on all interfaces).
- **Edit YAML**: a live YAML pane mirrors the forms; "Edit as YAML"
  accepts pasted configs and round-trips them back into the builder
  (parsed with the vendored js-yaml).

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

Internal development tracking references (DW-###) present in the
upstream schema descriptions are scrubbed at build time; the schema
embedded here matches `config-reference.json` in every other respect.

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
| `build.py` | Inlines schema + js-yaml into the template |

## Rebuilding

Whenever `config-reference.json` changes at the repo root (it is
regenerated and diffed by CI via `dwara schema`), rebuild:

```sh
python3 tools/config-studio/build.py
```

Requires Python 3 (stdlib only).

## Vendored dependency

`vendor/js-yaml.min.js` is js-yaml 4.1.0, MIT licensed
(https://github.com/nodeca/js-yaml). The license header is preserved
at the top of the file. It is embedded at build time so the tool
works fully offline; no other third-party code is included.
