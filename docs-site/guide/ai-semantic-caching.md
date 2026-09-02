# AI semantic caching

Semantic caching caches AI responses by prompt embedding similarity: a
paraphrased prompt within the similarity threshold returns the cached
response with no provider call and no token spend. This is a
significant cost saver for workloads with repeated or paraphrased
prompts.

Semantic caching is OFF by default and feature-gated behind the
`semantic_cache` cargo feature (the `hnsw_rs` HNSW ANN index adds
binary size). Build with `cargo build --features semantic_cache` to
enable it. Without the feature, the config is accepted but the cache
is inert (all requests hit the provider).

## Configuration

```yaml
ai:
  semantic_cache:
    enabled: true
    embedding_url: http://localhost:11434/v1/embeddings
    embedding_model: all-MiniLM-L6-v2
    embedding_dim: 384
    threshold: 0.85
    ttl_secs: 3600
    max_entries: 10000
    embedding_timeout_ms: 5000
    embedding_api_key: ${EMBEDDING_API_KEY}
```

| Field | Default | Notes |
|---|---|---|
| `enabled` | `false` | Must be true to activate the cache |
| `embedding_url` | (required) | URL of an OpenAI-compatible `/v1/embeddings` API |
| `embedding_model` | (required) | Model name passed to the embedding service |
| `embedding_dim` | (required) | Vector dimension; must match the embedding service's output |
| `threshold` | `0.85` | Cosine similarity threshold (0.0 to 1.0); higher = stricter |
| `ttl_secs` | `3600` | Entry TTL in seconds; stale entries are not returned |
| `max_entries` | `10000` | Max cached entries; when full, the cache resets (all evicted) |
| `embedding_timeout_ms` | `5000` | Timeout for the embedding service HTTP call |
| `embedding_api_key` | (optional) | Sent as `Authorization: Bearer <key>`; supports `${...}` refs |

## How it works

1. On a non-streaming AI request, AFTER guardrails and BEFORE the
   provider call, the gateway sends the prompt text to the configured
   embedding service and receives a vector embedding.
2. The embedding is searched against the HNSW ANN index for the
   nearest cached entry (k=1).
3. If the nearest entry's cosine similarity is >= the threshold, the
   entry is within TTL, and the model alias matches, the cached
   response is returned immediately (no provider call, no token
   spend).
4. On a cache miss, the request proceeds to the provider. After a
   successful response, the prompt embedding and response are stored
   in the cache (fire-and-forget -- the store never blocks the
   response path).

## Limitations

- **Non-streaming only**: streaming responses cannot be cached (the
  zero-buffer design precludes full content reassembly).
- **External dependency**: the embedding service must be reachable
  and responsive. If the embedding call fails or times out, the cache
  fails open (the request proceeds to the provider as a miss).
- **Per-model**: the cache is keyed by model alias; the same prompt
  with different models does not cross-hit.
- **No persistence**: the HNSW index and cached entries are in-memory
  only; they are lost on restart. The cache persists across config
  reloads (the index and entries survive; config updates in place).
- **Eviction**: when the cache reaches `max_entries`, the entire
  index is reset (all entries evicted). This is a simple full-reset
  policy; LRU eviction is a follow-up.

## Cost savings

The primary value of semantic caching is provider-call avoidance. For
a workload with N requests and M cache hits, the provider is called
N - M times. The cost savings are:

- **Token cost**: zero tokens spent on cache hits (the response is
  served from cache, not from the provider).
- **Latency**: cache hits skip the provider round-trip (the embedding
  call is typically faster than a full LLM completion).
- **Embedding cost**: each cache lookup and store makes one embedding
  API call. The embedding cost should be significantly cheaper than
  the LLM completion cost for the savings to be positive.

The `dwara_ai_semantic_cache_hits_total{model}` and
`dwara_ai_semantic_cache_misses_total{model}` metrics quantify the
hit rate; combine with `dwara_ai_cost_micros_total` to measure the
dollar savings.

## See also

- [AI gateway](./ai-gateway)
