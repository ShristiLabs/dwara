# Implementation notes

Read the entries for any area you are about to change.

## Hot reload

Swaps an atomic `Snapshot` (+ upstream registry, TLS material, auth state).
In-flight requests keep their old generation. Listener bind set is
restart-only. Counters/gauges survive reloads.

## State store

Opt-in via `DWARA_STATE_DB`. Auto-migrates on open and writes a `.bak-*`
backup before migrating. Schema changes go through `migrations.rs`
(forward-only, transactional, tracked in `PRAGMA user_version`).

## Credential hashing

API keys stored as `sha256:<hex>` (legacy) or `hmac-sha256:<hex>` (when
`DWARA_CREDENTIAL_PEPPER` is set). Constant-time compare in both modes.
Legacy rows re-hash to peppered format on successful verification. Peppered
rows fail closed without pepper (401 + ERROR log). Store-managed Basic
credentials use argon2id PHC hashes. `DWARA_CREDENTIAL_PEPPER_PREVIOUS`
enables seamless pepper rotation.

## Request smuggling

hyper 1.x does not reject CL+TE requests. The pre-parse sniff in
`hardening.rs` is the real defense (first head only). The proxy rebuilds
every forwarded request from parsed parts so framing cannot desync.

## Outbound TLS trust

Per entity (#121): a `trusted_ca_file` PEM bundle on an upstream or JWT
provider REPLACES the webpki public roots for that entity only. Active https
health probes inherit their upstream's roots. Bundle paths are NOT
file-watched: rotation needs SIGHUP or config change.

## Listener supervision

`listeners.rs`: panicked accept loops respawned on the SAME bound socket
(cap 8 per listener), then given up with ERROR log. Socket stays behind
`Arc`; shutdown flush uses `poll_accept` with no-op waker (not `into_std`).

## SNI passthrough

`tls.rs`: reassembles ClientHellos fragmented across TLS records, bounded at
64 KiB (`MAX_HELLO_BYTES`). Peek never consumes bytes; original hello is
replayed to upstream.

## Zero-downtime upgrade

DW-049: `dwara upgrade` sends SIGUSR2 to a running gateway. New process
binds same port via SO_REUSEPORT; old drains. PID from
`--pid`/`--pid-file`/`DWARA_PID_FILE`.

## Concurrency testing

arc-swap has no loom support. Swap paths covered by real-thread stress tests
in `tests/swap_stress.rs`. The `loom` feature covers the rest.

## Extension points

Swappable subsystem traits in `dwara-core::extensions`: `RateLimiter`,
`ConfigSource`, `CacheStore`, `AnalyticsSink`, `SecretSource` (async,
dyn-compatible). Local in-memory/file/env impls ship in-tree; Redis + Vault
are ent-only. `LicenseGate` is the edition boundary (stub in OSS, Ed25519
verification in ent).
