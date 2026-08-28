# Secrets

Source: `crates/dwara-core/src/config/credentials.rs` (the grammar,
resolution, and redaction — most rationale lives in its `//!` docs),
`crates/dwara-core/src/extensions/secrets.rs` (the `SecretSource` seam
and its impls), with consumption sites in `snapshot/mod.rs`
(validation), `security/authn.rs` (registry build), `state/store.rs`
(seeding), and `dwara-admin/src/lib.rs` (`GET /config`). Tests:
`secrets_handling` (dwara-core), `secrets_redaction`, plus redaction
cases in `admin_api` (dwara-admin); unit level in
`tests/unit/{credentials,secrets}.rs`. DW-045 / #46.

Secret-bearing config fields — today `consumers[].credentials[]`
`api_key.key`, `hmac.secret` (DW-036), and `gateway.webhooks[].headers`
values (DW-044) — carry either the value
INLINE or a `${...}` REFERENCE.
Inline values remain accepted for backward compatibility, but they are
redacted in every config echo (below); references are the recommended
shape because the config file then never holds the secret bytes at all.
The end-user material (how to write references, how rotation works,
what `${redacted:...}` in `GET /config` means) is at
[docs-site: Secrets](../../docs-site/guide/secrets.md) — this page is
the implementation and the why.

## The grammar

One function, `parse_secret_reference`, classifies a configured value:

| Shape | Meaning | Fails closed when |
| --- | --- | --- |
| `${ENV_NAME}` | environment variable; name is `[A-Za-z_][A-Za-z0-9_]*` (case free) | unset, set-but-empty, or not valid Unicode |
| `${file:/path}` | file read at resolution time, bounded at 1 MiB | missing, unreadable, not UTF-8, empty after trim, or larger than the 1 MiB read cap |
| `${redacted:...}` | the redaction placeholder — **never resolvable** | always |
| anything else starting `${` (malformed, or never closed like `${unclosed`) | malformed reference | always — a validation error, never a literal key |
| no `${` prefix, or `${...}` only mid-string | a plain literal (including `$X`) | — |

`${file:...}` trims exactly ONE trailing newline (`\n` or `\r\n`), the
Docker/Kubernetes mounted-secret and systemd `LoadCredential`
convention; interior newlines are preserved and the remainder must be
non-empty. The read is BOUNDED at 1 MiB (`MAX_SECRET_FILE_BYTES`, the
same bounded-read posture as the 64 KiB ClientHello cap): NUL bytes are
valid UTF-8, so `${file:/dev/zero}` under an unbounded read would
consume memory until the process dies — on every reload. The bound is
enforced on the file's metadata AND on the bytes read, so a file that
grows between the two checks is still capped.

**Why malformed `${`-shaped garbage is an error rather than a
literal:** a typo'd reference — malformed, or never closed like
`${file:/run/token` — treated as a literal key would silently
install garbage bytes as a live credential — a failure mode that
surfaces only as every request with the real key answering 401.
Failing at validation with a message naming the reference (never a
resolved value) turns that into a startup/reload error with a precise
`ValidationIssue`.

The `file:` and `redacted` prefixes are reserved and matched before
the env-name check, so no variable name can collide with them.

## Read-time model: config-compile time, never per request

References resolve when a config generation is built — cold start and
every hot reload or admin `PATCH /config` publish. This is the same
generation-follows-config contract as TLS cert material: a rotated
secret file lands on the next reload (`SIGHUP`, file change, or
publish), and the request path never touches a secret source.

```mermaid
sequenceDiagram
    participant FS as Secret file / env
    participant Val as snapshot::validate
    participant Pub as compile_and_publish
    participant Authn as authn registry build
    participant Store as store seeding

    Note over Val: every generation: cold start,\nfile-watch/SIGHUP reload, admin PATCH
    Val->>FS: resolve every ${...} reference
    alt any unresolvable / malformed
        Val->>Val: ValidationIssue naming the field —\ngeneration rejected, old one keeps serving
    else all resolve
        Pub->>Authn: publish (atomic ArcSwap)
        Authn->>FS: re-resolve, hash RESOLVED bytes,\ndrop the plaintext
        Store->>FS: re-resolve, hash into stored rows
        Note over Authn,Store: a second failure here is the\nvalidate-vs-build microsecond race:\nskip the credential + ERROR log; the store\nalso revokes the row that reference\nseeded in a previous generation (fail loud)
    end
    Note over FS,Store: rotating the file changes nothing live\nuntil the next reload re-runs the whole ladder
```

**Why compile-time rather than per-request lookup:** the resolved
value is needed exactly once per generation — to hash it into the
lookup selector and stored hash (see
[Authentication and authorization](./authn-authz.md)). After the build,
authn compares hashes only; keeping the plaintext reachable per
request would multiply the surfaces it can leak through (every log
line, every error path, every future feature) for zero behavioral
gain. The plaintext never outlives the build call that resolved it.
The one exception is the HMAC signing secret (DW-036): recomputing a
MAC needs the raw key bytes, so the resolved value is held —
zeroized, `Debug`-redacted — in the authenticator's in-memory key map
rather than hashed; the rest of the model (compile-time resolution,
fail-closed validation, redaction of inline values) is identical.

**Why the build and seeding re-resolve after validation already did:**
the file can change (or an env var be unset) in the microseconds
between validate and build. Validation's resolution is the contract;
the build-time re-resolution is a fail-closed backstop for that race —
the same pattern as `trusted_ca_file` (see [TLS](./tls.md#outbound-trust-per-entity-121)).
A failure there skips that one credential with an ERROR log (code
`config_api_key_unresolvable`, naming the consumer and the reference,
never the value), so the key stops authenticating loudly instead of
authenticating against stale bytes; the next successful publish
re-resolves. It is never a fallback to the previously resolved value.
In a `DWARA_STATE_DB` deployment the registry serves store rows, not
config, so the seeding path's skip ALSO revokes the row the SAME
reference seeded in a previous generation (`credentials.source_ref`,
schema v4, is the linkage; rows without it — inline keys,
operator-managed rows, pre-v4 databases — keep the documented
upsert-only posture). Without that revocation the old key would keep
authenticating through the store, the opposite of fail-closed.

## Redaction: typed, not regex

Every surface that echoes configuration — today admin
`GET /config` — serves `Gateway::redacted()`: a clone of the config in
which each inline `api_key` value and inline `hmac` secret is replaced
by `${redacted:sha256:<8 hex>}`. References pass through unchanged (an
env-var name or file path is not secret bytes; the config file already
carries it). Alongside this, `Credential`'s `Debug` impl is manual and
prints `[redacted]` for the key, so the whole config tree is safe to
`Debug`-log.

**Why a typed transform (`redacted()`) instead of a custom serializer
or a scrubbing regex over the emitted YAML:** the transform walks the
schema's own types, so it cannot drift from the schema — a future
secret-bearing field fails *visibly* (its value reaches the dump
unredacted, which canary tests catch) instead of silently escaping
whatever an allowlist regex happened to cover. A regex over serialized
YAML is exactly the wrong direction: it must know every field name
that can carry a secret, and YAML has infinitely many spellings of the
same bytes (quoting, anchors, block scalars) to hide them in.

**The fingerprint trade-off:** the placeholder carries the first 8 hex
of the key's sha256 deliberately. Without it, two generations carrying
different keys would produce identical output and an operator could
not tell whether a rotation landed; with it, `GET /config` answers
"which key is live" without ever returning key material. The prefix
identifies a *candidate* (an operator can confirm a known key matches)
but reveals nothing about an unknown one.

## The placeholder round-trip contract

`${redacted:...}` is unresolvable **by design**: `SecretRef::resolve`
on it returns the error "re-enter the secret or reference it as
`${ENV_NAME}` or `${file:/path/to/secret}`". The point is the GET ->
edit -> PATCH workflow: an operator fetches the config, edits
something unrelated, and PATCHes the document back — which now carries
placeholders wherever inline keys were. If the placeholder were
resolvable to anything, those bytes would become live keys and every
consumer on an inline key would break mysteriously. Instead the PATCH
dry-run fails with 400 and a `ValidationIssue` naming the field, and
the operator either re-enters the real key or (better) switches the
field to a reference — after which the round trip is stable, because
references echo verbatim.

## The extension seam stays in step

`EnvSecretSource` is unchanged; `FileSecretSource` now ships (DW-045)
and re-reads the file on every `resolve` call — no caching — since
resolution runs at publish cadence, so a rotation lands on the next
reload for the cost of one small read per publish. Its failure model
differs from `EnvSecretSource` in one deliberate way: for this source
the name IS the location, so a missing or unreadable file is not a
miss (`Ok(None)`) but a fail-closed `ExtensionsError::Io` naming the
path — mirroring validation's contract that a referenced secret must
exist when the generation is built.

The config grammar and the extension impls share the same reading
rules (`read_secret_file` in `config::credentials` is called by both),
so the seam and the grammar cannot drift apart. See
[Extension points](./extension-points.md#secretsource).

## Where to look next

- [Authentication and authorization](./authn-authz.md) — what the
  resolved bytes are hashed into (selectors, stored hashes, the
  pepper).
- [Admin API](./admin-api.md) — the surface whose `GET /config`
  serves the redacted copy.
- [docs-site: Secrets](../../docs-site/guide/secrets.md) — the
  operator-facing guide (writing references, rotation, reading
  redacted output).
