# HMAC request signing

[HMAC](https://en.wikipedia.org/wiki/HMAC) (Hash-based Message Authentication Code — a signature keyed with a shared secret) signing is a credential family for machine-to-machine traffic:
instead of presenting a static secret (an API key) that a network
observer could capture and reuse, the client signs every request with
a shared secret. The gateway verifies that the request — method, path,
query, and body — was constructed by the holder of the secret at the
stated time, and rejects anything modified in transit or [replayed](https://en.wikipedia.org/wiki/Replay_attack) (re-sending a captured valid request).
Use it when a calling service can keep a secret and generate
signatures, and you want request integrity rather than just
identification.

## When to use this

HMAC signing is for machine-to-machine traffic where a static API key
is too risky (a network observer could capture and reuse it) and you
want request integrity — the gateway verifies the request was signed
by the secret holder and rejects anything modified in transit or
replayed. Use it when a calling service can keep a secret and generate
signatures; it is not the right choice for browser clients or any
caller that cannot safely hold a shared secret.

## Configuring the gateway

Declare an `hmac` credential on a consumer. The `key_id` is a public
label the client presents to select the key; only the `secret` is
secret:

```yaml
consumers:
  - name: batch-worker
    credentials:
      - type: hmac
        key_id: worker-key-1
        secret: ${file:/etc/dwara/secrets/worker.key}
```

The secret accepts the same forms as an API key: inline (accepted but
redacted in every config echo) or a `${...}` reference to an
environment variable or secret file — references are recommended, see
[Secrets](./secrets). The secret can never be stored hashed (the
gateway needs the raw bytes to recompute the MAC (message authentication code)), so it is always
config-served and held only in gateway memory.

One optional gateway block tunes the verification window:

```yaml
hmac_auth:
  max_clock_skew_secs: 300   # default; allowed range 1..=3600
```

A request is a signed request only if it carries
`X-Dwara-Signature`; unsigned traffic on the same gateway flows
through untouched. Signed requests are evaluated by policies
(rate limiting, authorization) exactly like any other authenticated
consumer.

## The signed headers

Every signed request carries five headers — all five are required
whenever `X-Dwara-Signature` is present:

| Header | Content |
| --- | --- |
| `X-Dwara-Key-Id` | the credential's `key_id` (1..=128 bytes, visible ASCII) |
| `X-Dwara-Timestamp` | [Unix time](https://en.wikipedia.org/wiki/Unix_time) (seconds since 1970-01-01) in seconds, taken when signing (digits only) |
| `X-Dwara-Nonce` | a [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) (a one-time random value that prevents replay), 16..=256 bytes, visible ASCII (use at least 128 bits of [entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) (randomness, measured in bits)) |
| `X-Dwara-Body-Sha256` | lowercase hex [SHA-256](https://en.wikipedia.org/wiki/SHA-2) of the request body; for an empty body, the SHA-256 of the empty string, `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `X-Dwara-Signature` | lowercase hex HMAC-SHA256 of the canonical string below, keyed with the secret |

## How to sign a request

1. Hash the exact body bytes you will send (nothing, if the request
   has no body).
2. Take the current Unix time and a fresh random nonce.
3. Build the canonical string: eight lines — the version tag, then
   the key id, method, path, query, timestamp, nonce, and body digest
   — separated by single newline characters, with no trailing
   newline. The query line is the query exactly as sent, without the
   leading `?`, and is an **empty line** when the request has no
   query.
4. Compute HMAC-SHA256 of that string keyed with the secret; send it
   lowercase-hex in `X-Dwara-Signature` along with the other four
   headers.

```text
dwara-hmac-v1
<key id>
<METHOD>            uppercase, e.g. GET, POST
<path>              exactly as sent — [percent-encoding](https://developer.mozilla.org/en-US/docs/Glossary/percent-encoding) preserved, never normalized
<query>             exactly as sent, without the leading '?'; empty line if none
<timestamp>
<nonce>
<body sha256>
```

The path and query are signed **exactly as you transmit them**:
percent-encoding is preserved, query parameter order matters
(`?a=1&b=2` differs from `?b=2&a=1`), and nothing is re-sorted or
re-encoded. Build the signature from the final wire form of the
request — if your HTTP client library normalizes paths or reorders
query parameters, sign after that step or disable the normalization.

### Worked example (curl + openssl)

```sh
KEY_ID="worker-key-1"
SECRET="${WORKER_SECRET}"     # keep the secret in the environment, not the script
METHOD="POST"
PATH_PART="/api/submit"       # the path exactly as it will be sent
QUERY=""                      # the query exactly as sent, no leading '?'; empty if none
BODY='hello hmac'

TIMESTAMP="$(date +%s)"
NONCE="$(openssl rand -hex 16)"   # 128 bits of entropy
BODY_SHA256="$(printf '%s' "$BODY" | openssl dgst -sha256 -hex | awk '{print $NF}')"

CANONICAL="$(printf 'dwara-hmac-v1\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
  "$KEY_ID" "$METHOD" "$PATH_PART" "$QUERY" "$TIMESTAMP" "$NONCE" "$BODY_SHA256")"

SIGNATURE="$(printf '%s' "$CANONICAL" | openssl dgst -sha256 -hmac "$SECRET" -hex \
  | awk '{print $NF}')"

curl "http://localhost:8080${PATH_PART}${QUERY:+?$QUERY}" \
  -X POST \
  --data-raw "$BODY" \
  -H "X-Dwara-Key-Id: $KEY_ID" \
  -H "X-Dwara-Timestamp: $TIMESTAMP" \
  -H "X-Dwara-Nonce: $NONCE" \
  -H "X-Dwara-Body-Sha256: $BODY_SHA256" \
  -H "X-Dwara-Signature: $SIGNATURE"
```

For a GET, set `METHOD=GET` and `BODY=""` — the digest line becomes
the SHA-256 of the empty string shown above, and the body digest is
still sent. A correct request passes as the `batch-worker` consumer:
the gateway injects `X-Consumer-Name: batch-worker` upstream and
applies that consumer's policies.

## Timestamp and nonce rules

- The timestamp must be within `max_clock_skew_secs` (default 300) of
  the gateway's clock, in either direction. Sign immediately before
  sending; do not pre-generate signed requests.
- The nonce must be unique per key for the replay window (twice the
  skew value). The simplest correct choice is a fresh random value per
  request, as in the example. A valid request's nonce is remembered by
  the gateway for the whole window; sending it again in that period is
  rejected.
- Replay protection is per gateway instance. If you run several
  gateway instances behind one address without sticky routing, a
  replayed request may land on an instance that has not seen the
  nonce. Pin signed traffic to one instance, or treat the window as
  best-effort until a shared nonce store ships.

## Failure modes

Every rejection below is a `401` with the standard JSON error envelope
(`error.code` `unauthorized`) and the challenge
`WWW-Authenticate: Dwara-HMAC-SHA256 realm="dwara"`:

| Trigger | What happened |
| --- | --- |
| Any of the five headers missing or malformed | including a nonce shorter than 16 bytes, a non-numeric timestamp, or a signature that is not 64 hex characters |
| Timestamp outside the skew window | rejected before any signature work |
| Unknown `X-Dwara-Key-Id` | same 401 shape and timing as a wrong signature, so key ids cannot be probed |
| Wrong secret, or any signed element altered after signing | method, path, query, timestamp, nonce, or digest header changed on the way in |
| Body does not match `X-Dwara-Body-Sha256` | the gateway hashes the body while streaming it upstream and aborts the transfer the moment the digests disagree — a tampered body never reaches the upstream complete |
| Nonce already seen for this key within the window | replay rejection; a request with a fresh nonce on the same key succeeds |

Rate limiting still applies: a signed request over its consumer's
limit answers `429` like any other credential family.

Two boundaries worth knowing: the signature does not cover the
`Host` header (it is a routing input — serve signers over TLS so no
party between signer and gateway can retarget a signed request to a
different host-matched route), and requests that resolve to a
redirect or direct-response action forward no body upstream, so the
body-digest check does not run for them.

## Tuning the skew window

`hmac_auth.max_clock_skew_secs` (default 300, range 1..=3600) is a
trade-off between clock-drift tolerance and the replay window: a
timestamp is acceptable for at most one full window, and nonces are
retained for twice that. Tighten it when your signers' clocks are
well-synchronized (same [NTP](https://en.wikipedia.org/wiki/Network_Time_Protocol) (Network Time Protocol — clock synchronization) fleet) and you want a shorter exposure
window; loosen it for signers with unreliable clocks. Values below a
few seconds will reject requests from any host with modest drift.

The exact field shapes are in the
[configuration schema](../reference/configuration-schema); consumer
and credential configuration is covered in
[Configuration](./configuration).
