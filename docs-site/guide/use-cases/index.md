# Extension use cases and recipes

Concrete recipes that map real problems to the right extension
surface: proxy-wasm plugins, nano-services, or extension traits.
Each recipe page states the problem, why the built-ins do not fit,
the options with tradeoffs, a complete implementation with its
configuration, operational notes, and how to test it. Plugin code
samples use only hostcalls from the
[supported set](../plugin-sdk#hostcall-support-matrix).

Every recipe on these pages works in the current build. Where a
recipe requires an embedding build (a binary you compile that links
dwara-core as a library), the page says so.

## Recipes

| Recipe | Surface | The problem it solves |
| --- | --- | --- |
| [User-subset migration to a new API version](./user-subset-migration) | proxy-wasm plugin, `request_headers` | Only a subset of users (entitlements owned elsewhere) should be forwarded to the new endpoint |
| [Response PII redaction at the edge](./response-pii-redaction) | proxy-wasm plugin, `response_body` | An upstream leaks card numbers or tokens into response bodies |
| [Custom request authentication](./custom-request-auth) | proxy-wasm plugin, `request_headers` | A proprietary token scheme — not JWT, not API keys — must be verified per request |
| [Zero-upstream feature flags](./zero-upstream-feature-flags) | nano-service | An endpoint too dynamic for a `respond` action, too small for a service |
| [Tenant-aware routing and tagging](./tenant-aware-routing) | proxy-wasm plugin, two phases | Tenant identity lives in a grammar static match criteria cannot express |
| [Your own rate limiting, config, cache, analytics, or secrets backend](./custom-backends-traits) | extension traits (embedding) | Decisions or state must live in your infrastructure |
| [Per-request external decisions](./per-request-external-decisions) | proxy-wasm plugin with HTTP callouts | The verdict genuinely must be computed per request by an external service |

The first recipe is the deepest walkthrough: it contrasts a
config-snapshot plugin with a per-request callout, which is the
central design decision behind most of the others.

## Runnable demos

Every recipe has a runnable demo in
[`demos/13-extensibility-usecases/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases):
one directory per recipe, each with a `test.sh` that builds what it
needs (plugin, module, gateway) and asserts the documented behavior
end to end against purpose-built mock services. The category README
covers prerequisites, the port map, and running all seven in order.

## Where to start

- New to extending dwara? [Extending Dwara: getting
  started](../extensibility-getting-started) walks the four surfaces,
  where each one sits in the
  [request pipeline](../extensibility-getting-started#where-each-option-sits-in-the-request-pipeline),
  and a first plugin in 15 minutes.
- Unsure which surface fits? The
  [picking diagram](../extensibility-getting-started#picking-an-option)
  decides it in four questions.
- Writing the plugin itself? The [Plugin SDK](../plugin-sdk) page is
  the API reference; [Plugin testing](../plugin-testing) covers the
  unit, integration, and replay levels.
