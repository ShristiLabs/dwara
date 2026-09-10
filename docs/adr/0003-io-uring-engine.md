# ADR-0003: io_uring engine experiment (DW-096, PERF-13 #245)

- **Status:** Experiment (scaffold + decision: defer adoption, tokio remains default; PERF-13 revived the L4 thread-per-core + splice(2) seams)
- **Date:** 2026-09-06
- **Tracking:** DW-096, PERF-13 (#245)

## Context

dwara's dataplane runs on the tokio multi-threaded runtime: hyper drives
the HTTP proxy, tokio-rustls drives TLS, and the upstream connector pools
TCP connections. This is the portable, battle-tested default. The
question this experiment addresses: would a thread-per-core, io_uring-backed
engine deliver materially better throughput or tail latency for the
gateway's workload profile?

The relevant comparison points:

- **tokio (current):** a work-stealing thread pool that multiplexes
  async tasks across N worker threads. Excellent for mixed I/O + CPU
  workloads, portable (Linux, macOS, Windows), and the ecosystem hyper /
  tokio-rustls / quinn target. The cost is cross-thread wakeups and
  cache-line migration under high connection churn.

- **monoio:** a thread-per-core async runtime built on io_uring (Linux
  5.1+). Each worker thread owns its event loop and connections; no
  work-stealing. Designed for Pingora-class efficiency (Cloudflare's
  proxy runtime, which monoio explicitly models). The cost is a Linux-only
  requirement, a different `AsyncRead`/`AsyncWrite` ecosystem (not
  tokio's), and a smaller library ecosystem.

- **tokio-uring:** a tokio-affiliated io_uring runtime. Simpler than
  monoio (reuses tokio's task model) but single-threaded by design —
  horizontal scaling is via process replication (SO_REUSEPORT), not
  within-process parallelism. Less suited to a gateway that already
  manages multi-listener, multi-protocol concurrency within one process.

The DW-096 issue scopes this as explicitly an *experiment*: the
deliverable is a decision memo with benchmark numbers, not a commitment
to ship. The issue's "Done when" is: "Decision memo: adopt as opt-in
engine or close, with benchmark numbers vs the tokio engine."

## Decision

**Defer adoption. tokio remains the default and only engine.**

The scaffold crate (`crates/dwara-uring`) defines the engine-selection
trait and documents the integration point, but no io_uring runtime is
linked. The decision is deferred (not "closed forever") because:

1. **The ecosystem gap is the binding constraint, not raw throughput.**
   hyper, tokio-rustls, quinn, hickory, and tonic all target tokio's
   `AsyncRead`/`AsyncWrite` traits. monoio has its own buffered I/O
   traits (`AsyncReadRent`/`AsyncWriteRent`) and a compatibility shim,
   but the shim is lossy (it buffers where tokio would zero-copy) and
   the upstream libraries have not ported. A gateway that cannot reuse
   hyper, tokio-rustls, or quinn is effectively a from-scratch proxy —
   the cost dwarfs any throughput gain.

2. **The benchmark cannot be run on the current CI matrix.** io_uring
   requires Linux 5.1+ and is unavailable on macOS (the primary dev/CI
   platform). A meaningful benchmark needs a Linux CI lane with a
   kernel that supports the io_uring operations monoio uses
   (registered files, fixed buffers, multishot accept). The DW-024
   macro bench rig (`scripts/bench-macro.sh`) runs on the existing CI
   matrix; adding a Linux+io_uring lane is a CI investment this
   experiment does not justify on its own.

3. **The workload profile does not favor thread-per-core strongly
   enough.** dwara's hot path is TLS terminate -> route -> proxy: the
   CPU cost is dominated by TLS (aws-lc-rs) and HTTP framing (hyper),
   not by the syscall interface. io_uring's win is largest when
   syscalls per request are high and context-switch cost dominates
   (e.g. a raw L4 proxy with minimal per-connection work). For an L7
   gateway doing TLS + HTTP parsing + routing, the syscall savings are
   a smaller fraction of total cost.

4. **Pingora's results are not directly transferable.** Cloudflare's
   Pingora (the reference for monoio's design) reports significant
   throughput gains, but Pingora is a from-scratch proxy built
   end-to-end on the thread-per-core model — it does not wrap an
   existing tokio-based HTTP stack. The gains come from the *whole*
   architecture, not from swapping the runtime under an existing
   tokio-native proxy.

## Revisit triggers

This decision should be revisited when any of the following changes:

- **hyper (or a fork) ships a monoio-compatible HTTP stack.** If the
  ecosystem bridges the trait gap, the cost of adoption drops
  dramatically and the throughput comparison becomes the deciding
  factor.
- **A Linux CI lane with io_uring support is added for another reason**
  (e.g. DW-104 eBPF, which is also Linux-only). If the CI investment
  is already made, running the benchmark is cheap.
- **A concrete throughput or tail-latency SLA is missed by the tokio
  engine in production.** A measured gap, not a theoretical one, is
  the right trigger.
- **tokio itself adds an io_uring backend.** tokio has discussed io_uring
  support; if it ships as an opt-in reactor, the portability and
  ecosystem concerns dissolve and the experiment reduces to a config
  knob.

## Scaffold

The `crates/dwara-uring` crate (excluded from the workspace, like
`dwara-ebpf`) defines:

- [`Engine`] — the engine selection enum (`Tokio` today; `IoUring`
  reserved for the future).
- [`EngineAdapter`] — the trait an engine adapter implements so the
  dataplane boundary (`crates/dwara-bin/src/listeners.rs`) can select
  an engine at startup without the core depending on the runtime.
- Documentation of the integration point: when this advances from
  scaffold to implementation, the adapter lives behind a `uring` cargo
  feature on `dwara-bin`, the `monoio` dependency is added under a
  Linux-only target gate, and the engine selection is an env/build knob
  (no config schema change, per the issue's implementation notes).

No `monoio` or `tokio-uring` dependency is added in this scaffold. The
crate compiles with no new dependencies and the default workspace build
is unaffected.

## PERF-13 (#245): L4 thread-per-core + splice(2) revival

The PERF-13 issue revived the io_uring experiment as an L4-first
research scaffold. The prerequisite (PERF-06 benchmark harness,
`scripts/bench-macro.sh`) is in place, so the revival adds the
trait-based seams a future monoio adapter would consume:

- [`ThreadPerCoreAcceptConfig`] — the config for a thread-per-core
  accept loop (one worker per core, SO_REUSEPORT, no work-stealing).
- [`ThreadPerCoreAccept`] — the accept-loop trait. The tokio fallback
  (`TokioAccept`) documents that the real accept loop lives in
  `dataplane::l4`; a future monoio adapter would replace it.
- [`SpliceAdapter`] — the L4 splice trait. The tokio fallback
  (`TokioSplice`) uses `tokio::io::copy_bidirectional` (user-space
  copy); a future monoio adapter would use `splice(2)` via io_uring
  (kernel-space pipe, zero-copy).
- [`engine_from_env`] — reads `DWARA_ENGINE` at startup (tokio
  default; uring falls back to tokio on non-Linux).

No `monoio` dependency is added; the seams are trait-based and the
tokio fallbacks are no-ops that document where the real implementation
lives. The L7 path (hyper, TLS) stays on tokio until the ecosystem
bridges the trait gap (see the Decision section above).

## Consequences

- tokio remains the sole runtime; no `uring` feature is added to the
  workspace `Cargo.toml`.
- The scaffold crate is excluded from the workspace (like `dwara-ebpf`)
  so `cargo build --workspace` and the macOS CI lane never touch it.
- The decision is recorded; a future revisit reopens this ADR with
  benchmark numbers from a Linux CI lane.
- PERF-13 (#245) added the L4 thread-per-core + splice(2) seams; the
  L7 path is unchanged.
