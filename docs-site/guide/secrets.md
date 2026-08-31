# Secrets

A secret-bearing config field — today, a consumer's API key
(`consumers[].credentials[].api_key.key`), HMAC signing secret, or
[webhook](./webhooks) header value
(`consumers[].credentials[].hmac.secret`) — accepts either the value
inline or a **reference** that is resolved when the config is loaded.
References are the recommended shape for new configs: the config file
then never holds the secret bytes at all, which keeps it safe to back
up, commit to a pipeline, or paste into an issue.

Inline values keep working, but they are never echoed back: see
[Reading `GET /config`](#reading-get-config) below.

## When to use this

Secret references keep secret bytes out of the config file entirely,
so the config is safe to back up, commit to a pipeline, or share in a
code review without leaking credentials. Use references for any
production credential; inline values are accepted but never echoed
back, so a config dump never exposes them either.

## Referencing a secret

Two reference forms are supported, written as the field's entire
value:

```yaml
consumers:
  - name: acme
    credentials:
      - type: api_key
        key: ${file:/etc/dwara/secrets/acme.key}   # from a file
```

```yaml
consumers:
  - name: acme
    credentials:
      - type: api_key
        key: ${ACME_API_KEY}                       # from the environment
```

- **`${file:/path}`** — the file's contents become the secret. One
  trailing newline is trimmed (`\n` or `\r\n`), matching how Docker,
  Kubernetes, and systemd write mounted secret files; anything else,
  including interior newlines, is used verbatim. The file must exist,
  be valid [UTF-8](https://en.wikipedia.org/wiki/UTF-8), be non-empty, and be no larger than 1 MiB at
  config-load time.
- **`${ENV_NAME}`** — an environment variable of the gateway process
  (`[A-Za-z_][A-Za-z0-9_]*`, any case). The variable must be set,
  non-empty, and valid Unicode at config-load time.

Anything else that looks like a reference but is malformed —
`${file:}` naming no file, `${1BAD-NAME}`, an unclosed
`${file:/run/token`, a stray `${redacted:...}` pasted from a config
dump — is a **validation error**, never treated as a literal key: the
gateway refuses the config rather than installing garbage bytes as a
live credential. Every such error names the offending field and the
reference; it never prints the secret's value.

A config whose references do not resolve is rejected the same way any
invalid config is: startup exits non-zero, a
[reload](./operations#reload) is rejected with the previous generation
still serving, and a `PATCH /config` (see [Admin API](./admin-api))
answers `400` with the problem spelled out.

## Rotating a secret

Secrets are read when a config generation is built — at startup and on
every reload — not per request. How to rotate depends on the reference
form:

- **File reference** — write the new value to the secret file, then
  trigger a reload (`SIGHUP`, a change to the config file, or any
  successful `PATCH /config`). Changing the secret file alone does
  nothing: only the config file is watched.
- **Environment reference** — restart the gateway with the new
  environment. A process cannot see environment changes made after it
  started, and a reload re-reads the process's own environment.

You can confirm a rotation landed by comparing the fingerprints in
`GET /config` (below) across the generations, or by watching the
config generation advance via `GET /health` or the
`config_generation` metric.

## Reading `GET /config`

`GET /config` never returns secret values. An inline key appears as a
redaction placeholder carrying a short fingerprint:

```yaml
consumers:
  - name: acme
    credentials:
      - type: api_key
        key: ${redacted:sha256:9f86d081}
```

The fingerprint (a short, stable summary of a key that identifies it without revealing it — the first 8 hex characters of the key's [SHA-256](https://en.wikipedia.org/wiki/SHA-2) (a cryptographic hash function)) lets
you tell *which* key a generation carries — the same key always
produces the same fingerprint, a different key a different one —
without the key itself ever leaving the gateway.

References echo verbatim: a config using `${file:/etc/dwara/secrets/acme.key}`
shows exactly that string, because a variable name or file path is not
secret material.

**PATCHing a redacted value back fails, on purpose.** If you `GET
/config`, edit the document, and `PATCH` it back, the placeholders it
contains are rejected with `400` naming the field — otherwise the
placeholder text itself would become a live API key and every consumer
using the real key would stop authenticating. Replace the placeholder
with either:

- the real key value (it will be redacted again in the next `GET`), or
- a `${ENV_NAME}` / `${file:/path}` reference — after which the
  GET-edit-PATCH loop is stable, because references round-trip
  unchanged.

The cleanest workflow is to move inline keys to references first; then
`GET /config` output is a complete, directly PATCHable document.
