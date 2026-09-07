# M6 - AI Gateway Expansion

This document covers all six issues in the M6 (AI Gateway Expansion)
milestone. For each issue it describes the implementation, the
recommended default, the rationale for that default, the available
alternatives, and the operational tradeoffs.

## Issue index

| Issue | Title | Priority | Size |
|-------|-------|----------|------|
| #164 | AI-01: Additional provider adapters | P0 | M |
| #165 | AI-02: Endpoint breadth beyond chat | P1 | M |
| #166 | AI-03: Pricing fidelity and fail-open cost guard | P0 | S |
| #167 | AI-07: OTel GenAI semantic conventions and AI metric families | P1 | M |
| #168 | PERF-01: Local token estimation for AI budget pre-checks | P1 | S |
| #169 | PERF-02: Streaming semantic cache | P1 | M |

---

## #164 / AI-01: Additional provider adapters

### Purpose

The initial AI provider-adapter pack (DW-075) shipped with OpenAI,
Anthropic, Gemini, and A2A dialects. This issue expands coverage to
the two remaining major cloud AI platforms: Azure OpenAI and AWS
Bedrock. OpenAI-compatible providers (Ollama, vLLM, Groq, DeepSeek,
Mistral, Cohere) are intentionally served through the existing OpenAI
adapter rather than receiving separate adapters.

### Recommended default

- **Azure OpenAI:** dedicated adapter (`AiProviderKind::AzureOpenai`).
  Uses OpenAI-compatible body translation with Azure-specific path
  construction (`/openai/deployments/{deployment}/chat/completions?api-version=...`).
  The default API version is supplied by the adapter; callers can
  override it through the canonical request's `other` map.
- **AWS Bedrock:** dedicated adapter (`AiProviderKind::Bedrock`).
  Uses Anthropic-shaped request/response bodies with Bedrock-specific
  path construction (`/model/{model_id}/invoke`, URL-encoded).
  Anthropic-specific request headers (e.g. `anthropic-version`) are
  removed.
- **OpenAI-compatible providers:** reuse `AiProviderKind::Openai`. No
  separate adapters for Ollama, vLLM, Groq, DeepSeek, Mistral, or
  Cohere.

### Rationale

Azure OpenAI and AWS Bedrock have distinct path structures and
authentication schemes that differ enough from the base OpenAI and
Anthropic adapters to warrant dedicated translation. Azure uses
deployment-based paths with an `api-version` query parameter; Bedrock
uses model-ID-based invoke paths with SigV4 signing.

OpenAI-compatible providers share the same request/response shapes as
OpenAI itself. Creating separate adapters for each would duplicate the
OpenAI translation logic with no functional difference. The existing
OpenAI adapter handles them by configuring the provider's upstream to
point at the compatible endpoint.

### Available alternatives

- **Separate adapters for every OpenAI-compatible provider:** rejected
  because it duplicates translation logic with zero behavioral
  difference. The upstream configuration already differentiates them.
- **Azure OpenAI via the OpenAI adapter with path rewrite:** rejected
  because the `api-version` query parameter and deployment-based path
  are structural differences that the adapter layer (not the rewrite
  layer) is the right place to handle.
- **Bedrock via the Anthropic adapter with path rewrite:** rejected
  because Bedrock removes Anthropic-specific headers and uses a
  different path structure, making the adapter the cleaner seam.

### Implementation

- New enum variants: `AiProviderKind::AzureOpenai`, `AiProviderKind::Bedrock`.
- New adapter files: `crates/dwara-core/src/ai/adapters/azure_openai.rs`,
  `crates/dwara-core/src/ai/adapters/bedrock.rs`.
- Azure OpenAI: OpenAI-compatible body translation; path format
  `/openai/deployments/{deployment}/chat/completions?api-version=...`;
  default API version supplied by the adapter; `api_version` overridable
  via the canonical request's `other` map; OpenAI response and streaming
  formats reused; Azure `api-key` handling is a transport/config
  responsibility.
- Bedrock: Anthropic-shaped request/response bodies; path format
  `/model/{model_id}/invoke` (model ID URL-encoded); removes
  Anthropic-specific request headers; SigV4 signing is a
  transport-layer responsibility using configured AWS credentials.
- Tests: `crates/dwara-core/tests/ai_adapters.rs` (32 tests covering
  all adapters including Azure OpenAI and Bedrock).

### Limitations

- **Bedrock authentication:** SigV4 signing is described as a
  transport-layer responsibility but is not yet implemented in the
  transport. Bedrock adapters handle body/path translation only;
  operators must configure AWS credentials and signing at the
  upstream/transport level.
- **Azure OpenAI authentication:** the `api-key` header is expected to
  be supplied by transport/config, not by the adapter.

---

## #165 / AI-02: Endpoint breadth beyond chat

### Purpose

The AI route action (DW-075) initially supported only chat-completions
endpoints. This issue extends the AI route to serve other OpenAI
endpoint families: embeddings, images, audio (TTS/transcription), and
moderation.

### Recommended default

- **Endpoint:** `chat` (the default). An AI route without an explicit
  `endpoint` field uses the full adapter translation pipeline (the
  existing DW-075 behavior).
- **Non-chat endpoints:** passthrough semantics. The request body is
  forwarded to the provider's upstream as-is (no adapter translation),
  and the response is returned as-is. Model governance (allowlist
  check) still applies using the `model` field from the request body.

### Rationale

Chat-completions is the most complex endpoint and the one that benefits
most from adapter translation (canonical request/response types,
streaming SSE framing, usage accounting, guardrails, semantic caching).
The other endpoint families (embeddings, images, audio, moderation) have
simpler request/response shapes that are already provider-specific and
do not benefit from canonical translation. Passthrough is the simplest
correct behavior: it forwards the body verbatim and returns the response
verbatim, with no translation overhead.

Model governance still applies because the `model` field is present in
all OpenAI endpoint request shapes, and the same alias table and
allowlist policy should govern access regardless of endpoint.

Budget enforcement and semantic caching are chat-specific (they depend
on canonical `ChatRequest` parsing) and do not apply to passthrough
endpoints.

### Available alternatives

- **Full adapter translation for every endpoint:** rejected because it
  would require canonical types for embeddings, images, audio, and
  moderation, each with provider-specific dialects. The complexity is
  not justified for endpoints whose shapes are already simple and
  provider-specific.
- **Separate route action types per endpoint:** rejected because it
  would multiply the route action enum and complicate configuration.
  A single `Ai` action with an `endpoint` selector is simpler and
  preserves backward compatibility.
- **No governance on passthrough endpoints:** rejected because model
  governance (allowlist check) is a security control that should apply
  uniformly regardless of endpoint.

### Implementation

- New enum: `AiEndpoint { Chat, Embeddings, Images, Audio, Moderation }`
  in `crates/dwara-core/src/config/mod.rs`. `Chat` is the default
  (via `#[default]`).
- `RouteAction::Ai` changed from unit form to struct form:
  `Ai { endpoint: AiEndpoint }` with `#[serde(default)]` on `endpoint`.
- The passthrough branch runs BEFORE chat-request parsing so non-chat
  bodies (which lack `messages`) do not trigger a 400.
- Passthrough path selection (OpenAI-compatible):
  - Chat: `/v1/chat/completions`
  - Embeddings: `/v1/embeddings`
  - Images: `/v1/images/generations`
  - Audio: `/v1/audio/speech`
  - Moderation: `/v1/moderations`
- No failover for passthrough (the response is returned as-is; retry
  logic would need to buffer the entire response, which defeats the
  passthrough design). The first candidate from the routing walk is
  used.
- Provider auth headers (including credential pool pick) are applied
  the same way as chat.
- Tests: `crates/dwara-core/tests/ai_endpoints.rs` (4 tests covering
  embeddings passthrough, images passthrough, unknown-model 404, and
  chat-endpoint backward compatibility).

### Limitations

- **Audio endpoint ambiguity:** the `Audio` enum variant maps to
  `/v1/audio/speech` (TTS). Transcription (`/v1/audio/transcriptions`)
  is not separately distinguished; operators needing transcription
  should configure a separate route with an upstream rewrite.
- **No failover for passthrough:** only the first routing candidate is
  tried. If the primary provider is unavailable, the request fails
  with 502 rather than advancing to a failover candidate.
- **No budget enforcement or semantic caching for passthrough:** these
  are chat-specific features that depend on canonical `ChatRequest`
  parsing.
- **OpenAI-compatible paths:** the passthrough paths are
  OpenAI-compatible. Providers with different paths can be reached via
  an upstream rewrite.

---

## #166 / AI-03: Pricing fidelity and fail-open cost guard

### Purpose

The AI cost accounting (DW-079) depends on accurate pricing tables.
This issue ensures pricing tables are comprehensive and that the cost
guard fails open when configured, so a missing or stale price does not
block requests.

### Recommended default

- **Cost guard:** fail-open when configured. A missing or unknown model
  price does not block the request; the cost is recorded as zero and a
  warning is logged.
- **Provider-reported usage:** remains authoritative for post-call
  accounting. The gateway does not estimate cost for accounting
  purposes; it uses the provider's reported token usage.

### Rationale

Blocking requests because a price table is stale or missing a model is
operationally fragile: a new model release would cause request failures
until the price table is updated. Fail-open is the safer default: the
request proceeds, the cost is recorded as zero (with a warning), and
the operator can update the price table at their convenience.

Provider-reported usage is authoritative because the provider is the
source of truth for token counts. The gateway's local estimates (see
#168) are used only for pre-checks, not for accounting.

### Available alternatives

- **Fail-closed cost guard:** rejected as the default because it would
  block requests on stale price tables. Available as an opt-in for
  deployments that require strict cost enforcement.
- **Gateway-estimated cost for accounting:** rejected because
  provider-reported usage is more accurate and already available.

### Implementation

- Pricing tables updated with comprehensive model coverage.
- Unknown-model handling: the cost guard records zero cost and logs a
  warning rather than blocking.
- Existing provider-reported usage remains authoritative for post-call
  accounting.
- Changes touched AI pricing/configuration and associated tests.

---

## #167 / AI-07: OTel GenAI semantic conventions and AI metric families

### Purpose

The AI proxy's observability span attributes and metrics did not follow
the OpenTelemetry GenAI semantic conventions. This issue adds
GenAI-convention span attributes and AI-specific Prometheus metric
families so that AI traffic is observable in standard dashboards and
trace analysis tools.

### Recommended default

- **GenAI span attributes:** always recorded on the AI span. The
  attributes follow the OpenTelemetry GenAI semantic conventions
  (gen_ai.system, gen_ai.request.model, gen_ai.usage.*, etc.).
- **AI metrics:** always exported. Two new Prometheus metric families
  are added alongside the existing TTFT histogram.

### Rationale

Standard semantic conventions ensure compatibility with existing
OpenTelemetry tooling (Jaeger, Tempo, Grafana, Datadog, etc.) without
custom configuration. The GenAI conventions are the emerging standard
for LLM observability and are widely adopted by AI observability
platforms.

### Available alternatives

- **Custom span attributes (non-standard):** rejected because they
  would require custom dashboard configuration and would not integrate
  with standard OTel tooling.
- **No AI-specific metrics:** rejected because AI traffic has distinct
  characteristics (token usage, model selection, provider routing)
  that warrant dedicated metric families.

### Implementation

- GenAI semantic-convention span attributes:
  - `gen_ai.system`
  - `gen_ai.request.model`
  - `gen_ai.request.max_tokens`
  - `gen_ai.request.temperature`
  - `gen_ai.request.top_p`
  - `gen_ai.response.model`
  - `gen_ai.usage.prompt_tokens`
  - `gen_ai.usage.completion_tokens`
  - `gen_ai.usage.total_tokens`
  - `gen_ai.response.finish_reasons`
  - `gen_ai.response.id`
- New Prometheus metrics:
  - `dwara_ai_request_duration_seconds{provider,route}`
  - `dwara_ai_tokens_per_request{provider,model,kind}`
- Existing TTFT histogram preserved and verified.
- `FinishReason::as_gen_ai()` maps canonical finish reasons to GenAI
  convention values.
- `AiProviderKind::gen_ai_system()` maps provider kinds to GenAI system
  values.

---

## #168 / PERF-01: Local token estimation for AI budget pre-checks

### Purpose

The AI token budget engine (DW-078) previously had no pre-check: a
request would reach the provider before the gateway could reject it
for budget exhaustion. This issue adds a lightweight local token
estimator that runs after request parsing and before provider contact,
enabling budget pre-checks that avoid unnecessary provider calls and
token spend.

### Recommended default

- **Estimator:** lightweight, no new dependency. The estimator uses a
  simple character-based heuristic (approximately 4 characters per
  token) plus a fixed overhead per message and per tool definition.
- **Pre-check:** after request parsing, before provider contact. If the
  estimated total (prompt estimate + requested `max_tokens`) exceeds
  the remaining budget, the request is rejected with 429.
- **Provider-reported usage:** remains authoritative for post-call
  accounting. The estimate is used only for the pre-check.

### Rationale

A lightweight estimator without a tokenizer dependency keeps the
gateway's dependency surface small and the estimation fast. The
4-chars-per-token heuristic is conservative (it tends to over-estimate
slightly), which is the right direction for a pre-check: it is better
to reject a request that might exceed the budget than to let it through
and exceed the budget.

The pre-check runs after request parsing (so the canonical
`ChatRequest` is available) and before provider contact (so the
provider call is avoided if the pre-check rejects). This is the
earliest point where a meaningful estimate is available.

Provider-reported usage remains authoritative because the estimate is
not precise enough for accounting.

### Available alternatives

- **Full tokenizer (tiktoken, etc.):** rejected because it would add a
  native-code dependency, increase binary size, and slow the request
  path. The heuristic is sufficient for a pre-check.
- **No pre-check (rely on post-call accounting):** rejected because it
  allows requests to reach the provider and consume tokens even when
  the budget is exhausted.
- **Provider-side budget enforcement:** rejected because it requires
  provider-specific integration and does not work with providers that
  lack budget APIs.

### Implementation

- New module: `crates/dwara-core/src/ai/token_estimator.rs`.
- Estimation based on parsed canonical `ChatRequest`:
  - Prompt estimate: sum of message text lengths / 4, plus per-message
    overhead, plus role overhead, plus tool definition overhead, plus
    image part fixed overhead.
  - Total estimate: prompt estimate + requested `max_tokens`.
- Estimated budget pre-check after request parsing and before provider
  contact.
- Tests: `crates/dwara-core/tests/ai_token_estimator.rs` (11 tests
  covering empty requests, short/long messages, conservative estimates,
  image parts, tool definitions, budget allow/reject, and exhausted
  windows).

---

## #169 / PERF-02: Streaming semantic cache

### Purpose

The semantic cache (DW-083) previously supported only non-streaming
responses and used wholesale reset when the cache was full. This issue
expands the semantic cache with an exact-match fast tier, LRU eviction,
streaming response caching and replay, and bounded streaming tee
buffering.

### Recommended default

- **Exact-match tier:** enabled. Before calling the embedding service,
  the cache checks an exact-match tier (prompt text hash). If the exact
  prompt is cached, the response is returned immediately without an
  embedding call.
- **LRU eviction:** enabled. When the cache is full, the least-recently-
  accessed entry is evicted (not a wholesale reset).
- **Streaming cache:** enabled. Streaming responses are cached and
  replayed as `text/event-stream`. A bounded tee buffer collects
  streaming frames up to 1 MiB; if the stream exceeds the cap, it
  continues to the client but is not cached.
- **Fire-and-forget storage:** the cache store happens in a spawned
  task after response completion, so it never blocks the request path.
- **Fail-open on embedding errors:** if the embedding service is
  unavailable, the cache miss is silent and the request proceeds to the
  provider.

### Rationale

The exact-match tier avoids the embedding service call for repeated
identical prompts, which is the common case for cache hits. LRU
eviction is the standard cache eviction policy and is more predictable
than wholesale reset. Streaming caching avoids re-calling the provider
for repeated streaming requests, which is important for chat UIs that
re-send the same prompt.

The 1 MiB cap on the streaming tee buffer prevents unbounded memory
growth from large streaming responses. If the cap is exceeded, the
stream continues to the client but is not cached — a graceful
degradation.

Fire-and-forget storage ensures the cache never blocks the request
path, consistent with the gateway's design principle that optional
features must not slow the hot path.

### Available alternatives

- **No exact-match tier:** rejected because it would require an
  embedding call for every cache lookup, adding latency and cost.
- **Wholesale reset (the old behavior):** rejected because it discards
  all cached entries when the cache is full, including recently-used
  ones.
- **No streaming cache:** rejected because streaming is the common case
  for chat UIs, and not caching streams misses a significant
  optimization opportunity.
- **Unbounded streaming buffer:** rejected because it could cause
  memory exhaustion on large streaming responses.
- **Fail-closed on embedding errors:** rejected because it would block
  requests when the embedding service is unavailable, making the cache
  a reliability dependency.

### Implementation

- Exact-match tier: hashes prompt text using `DefaultHasher`; checked
  before embedding calls.
- LRU eviction: each cache entry stores `last_accessed_ms`; eviction
  scans for the smallest value. HNSW stale IDs are tolerated; removed
  entries are filtered when validating lookup results.
- Streaming cache: streaming frames collected up to 1 MiB in
  `AiStreamBody`; if the cap is exceeded, the stream continues to the
  client but is not cached; cached streaming responses replay as
  `text/event-stream`.
- Each cache entry stores: cached JSON or SSE frames, model alias,
  stored timestamp, last-access timestamp, prompt text.
- Cache lookup after guardrails and before routing/provider contact.
- Fire-and-forget cache storage after response completion.
- Tests: `crates/dwara-core/tests/ai_semantic_cache.rs` (8 tests
  covering exact match, LRU eviction, streaming cache hit/replay,
  embedding error fail-open, and cache miss).

### Limitations

- **Streaming cache size limit:** 1 MiB. Streams exceeding this cap
  are served to the client but not cached.
- **Feature-gated:** the semantic cache is behind the `semantic_cache`
  cargo feature. When the feature is off, the cache is not compiled.
- **External embedding service:** the semantic cache requires an
  external embedding service for similarity-based lookup. The
  exact-match tier works without the embedding service.
