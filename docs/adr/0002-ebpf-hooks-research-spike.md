# ADR-0002: eBPF hooks research spike

- **Status:** Research (not yet accepted for production)
- **Date:** 2025-09-02
- **Tracking:** DW-104

## Context

dwara currently observes network behavior entirely from userspace: the
dataplane records access logs, metrics, and analytics as requests flow
through the proxy action, and the resilience domain tracks passive
health from response outcomes. There is a class of signal the gateway
cannot see from userspace: kernel-level connection state transitions,
retransmits, drops, and the L4 steering decisions the kernel makes
before a connection ever reaches the listener's accept loop.

eBPF hooks would let dwara observe those kernel-level network events
directly. The intended vehicle is [aya](https://github.com/aya-rs/aya),
a pure-Rust eBPF toolkit (no libbpf C dependency, no clang/bpfcc
toolchain) that compiles eBPF programs with the same Rust toolchain the
workspace already pins. aya's CO-RE (Compile Once, Run Everywhere)
story depends on the kernel exposing BTF (BPF Type Format), which
constrains the floor to Linux 5.4+.

eBPF is, by definition, Linux-only. The macOS development and CI
environments cannot run eBPF programs (no kernel BPF subsystem), so any
eBPF integration is necessarily gated behind a Linux-only build and CI
lane. This rules out making eBPF a default-on capability of the gateway.

The potential value, ordered by the feature work each hook would
enable:

- **Connection tracing** — observe `inet_sock_set_state` transitions
  to produce connection-level observability (open/close/retransmit/drop
  per upstream) that the userspace access log cannot see. This is the
  substrate for richer health and anomaly signals.
- **XDP packet steering** — steer packets at the earliest kernel
  ingress point (before the socket layer) for L4 acceleration and
  DoS mitigation. High value for performance, but the available hooks
  are kernel-version sensitive (XDP program types and helpers vary
  across 5.4 -> 6.x).
- **SO_REUSEPORT load balancing** — attach a `sk_reuseport` BPF
  program to influence which socket the kernel hands a connection to
  when multiple listeners share a port. Overlaps with the existing
  userspace load balancer (`dataplane/balance.rs`) and the
  SO_REUSEPORT socket setup already used for zero-downtime upgrade
  (DW-049); marginal incremental value.
- **Ambient mesh redirect (iptables/TPROXY)** — transparently redirect
  traffic to dwara without per-application sidecar configuration via
  TPROXY + iptables/mark rules driven by eBPF. This is the enabling
  mechanism for DW-107 (ambient mesh). Highest value because it opens
  a new deployment model, but also the most complex: it couples the
  gateway to the host's networking stack and requires privileged
  deployment.

This ADR records the research analysis and the scaffold decision only.
No working eBPF programs are shipped.

## Decision

Research spike. Scaffold the companion crate structure
(`crates/dwara-ebpf/`) and document which kernel hooks would deliver
value, but do NOT ship working eBPF programs yet.

The companion crate is:

- **Standalone**, not a workspace member. It is added to the workspace
  `exclude` list so `cargo build --workspace` and the CI matrix never
  touch it.
- **Linux-only by construction.** Its `Cargo.toml` gates any future
  aya dependency behind `[target.'cfg(target_os = "linux")'.dependencies]`,
  and its module docs state the kernel 5.4+ (BTF/CO-RE) requirement.
- **A scaffold only.** It defines the `EbpfSignal` enum and the
  `EbpfEventConsumer` trait that a future implementation would feed,
  but contains no eBPF programs, no aya dependency, and no build
  integration.

## Hooks analyzed

### Connection tracing (tracepoint: `sockinet/inet_sock_set_state`)

- **Mechanism.** Attach a tracepoint program to the
  `sockinet/inet_sock_set_state` tracepoint, which fires on every TCP
  state transition (ESTABLISHED, FIN_WAIT, CLOSE, etc.). The program
  emits the 4-tuple, old/new state, and the owning PID/cookie to a
  ring buffer.
- **Value.** Connection-level observability the userspace access log
  cannot see: retransmits, kernel-side drops, half-open connections,
  and the latency between kernel accept and the userspace request
  handler picking the connection up. Feeds directly into the resilience
  domain's passive health signals and the anomaly scorer (DW-090).
- **Risk.** Lowest of the four. Tracepoints are a stable, read-only
  observation surface; the program does not alter packet flow, so a
  bug or a verifier rejection degrades to "no signal" rather than
  "broken networking." No privileged network configuration required
  beyond `CAP_BPF`/`CAP_PERFMON` to load the program.
- **Kernel sensitivity.** Low. The tracepoint has been stable since
  4.16; the CO-RE field layout is well-covered by BTF on 5.4+.

### XDP packet steering

- **Mechanism.** Attach an XDP program to a network interface's
  ingress path. The program inspects packet headers and can
  `XDP_DROP`, `XDP_PASS`, `XDP_REDIRECT`, or `XDP_TX` before the
  packet enters the kernel's receive stack.
- **Value.** Highest raw performance (packets are handled before
  socket allocation), making it attractive for L4 acceleration and
  volumetric DoS mitigation (drop malicious flows at line rate).
- **Risk.** High. An XDP program is in the fast path of every packet
  on the interface; a bug drops or misroutes production traffic. XDP
  also requires driver support (native XDP vs. generic XDP) and
  privileged deployment.
- **Kernel sensitivity.** High. Available program types, helpers, and
  driver support vary materially across 5.4 -> 6.x. A program that
  loads on a 6.x development kernel may not load on a 5.4 production
  kernel, and vice versa for newer helpers.

### SO_REUSEPORT load balancing

- **Mechanism.** Attach a `sk_reuseport` BPF program that selects
  which receiving socket gets a given connection when multiple
  listeners share a port via `SO_REUSEPORT`.
- **Value.** Marginal. dwara already load-balances in userspace
  (`dataplane/balance.rs`) and already uses `SO_REUSEPORT` for
  zero-downtime upgrade (DW-049, `socket2` sets the socket option so
  the kernel spreads accepts across the old and new process). A
  `sk_reuseport` program would let the gateway influence the kernel's
  socket selection, but the gateway already owns endpoint selection
  at L7; the kernel-level selection only matters for the accept
  distribution across processes, which the existing DW-049 path
  already handles adequately.
- **Risk.** Medium. The program runs on every connection to a
  reuseport group; a bug starves a listener. Requires the gateway to
  own the reuseport group, which it does not today outside the upgrade
  window.
- **Kernel sensitivity.** Medium. `sk_reuseport` programs are
  available from 4.14, but the helper set for socket selection has
  grown across kernel versions.

### Ambient redirect (iptables/TPROXY)

- **Mechanism.** Use TPROXY + iptables `mark`/`mangle` rules
  (potentially driven by eBPF) to transparently redirect traffic to
  dwara's listener without per-application sidecar configuration. The
  gateway binds the TPROXY socket and the kernel hands it redirected
  flows preserving the original destination.
- **Value.** Highest. This is the enabling mechanism for DW-107
  (ambient mesh): it lets dwara intercept traffic for applications
  that are not explicitly configured to proxy through it, which is the
  core premise of an ambient (non-sidecar) service mesh.
- **Risk.** Highest. It couples the gateway to the host's networking
  stack: iptables rules, routing table entries, and the TPROXY socket
  semantics must all be correct or the host loses connectivity. It
  requires privileged deployment (root or `CAP_NET_ADMIN` +
  `CAP_NET_RAW`). The operational surface (rule lifecycle on reload,
  cleanup on crash, interaction with the host firewall) is the
  largest of the four hooks.
- **Kernel sensitivity.** Medium. TPROXY itself is old (4.0+), but
  the eBPF-driven rule management and the interaction with
  connection-tracking state vary across kernel versions.

## Recommendation

Connection tracing is the first hook to implement if this research
spike advances to implementation.

Rationale:

- It is the lowest-risk hook (read-only observation, no packet-flow
  alteration), so it is the safest way to prove out the aya toolchain,
  the BTF/CO-RE build path, and the ring-buffer-to-userspace pipeline
  in production.
- It delivers immediately useful signal (connection-level
  observability) that feeds existing consumers (resilience passive
  health, anomaly scoring) without requiring new config surface or a
  new deployment model.
- It establishes the `EbpfSignal` / `EbpfEventConsumer` contract (the
  scaffold in `crates/dwara-ebpf/`) against a real producer, so the
  XDP and ambient-redirect hooks can layer on the same ingestion path
  later without redesigning the seam.

XDP and ambient redirect should follow only after connection tracing
has proven the toolchain and the ingestion seam in production.
SO_REUSEPORT LB is not recommended for implementation: the overlap
with the existing userspace LB and the DW-049 upgrade path makes the
incremental value too low to justify the kernel-coupling cost.

## Minimum kernel version

Linux 5.4+. The floor is set by the BTF/CO-RE requirement: aya's
compile-once-run-everywhere story depends on the kernel exposing BTF
(BPF Type Format) for field layout resolution at load time. BTF was
merged in 4.18 but was not enabled in mainstream distribution kernels
until the 5.4 LTS cycle. Kernels older than 5.4, or 5.4+ kernels
built with `CONFIG_DEBUG_INFO_BTF=n`, cannot load CO-RE programs and
are out of scope.

## Risks

- **Linux-only.** eBPF cannot run on macOS, so the development
  environment and the macOS CI lane cannot exercise any eBPF code.
  The companion crate is excluded from the default workspace build and
  the CI matrix; a dedicated Linux CI lane would be required if this
  advances to implementation.
- **Kernel fragmentation.** Even within the 5.4+ floor, available
  program types, helpers, and BTF coverage vary across distribution
  kernels. A program that loads on one 5.4 kernel may be rejected by
  the verifier on another. This is the classic eBPF portability
  problem; CO-RE mitigates but does not eliminate it.
- **Research may not produce a shippable feature.** This is a spike.
  The analysis may conclude that the kernel-coupling and
  Linux-only-CI costs outweigh the observability and steering value
  for dwara's deployment profile, in which case the scaffold stays a
  scaffold and no implementation follows.
- **Privileged deployment.** Loading eBPF programs requires
  capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` depending
  on hook) that the gateway does not currently require. Any
  implementation must document the capability requirements and the
  container/host implications.

## Follow-up

If the value justifies moving from research to implementation:

1. Land the companion crate (`crates/dwara-ebpf/`) behind a dedicated
   Linux CI lane (separate from the macOS/default matrix), with the
   aya dependency added under
   `[target.'cfg(target_os = "linux")'.dependencies]`.
2. Implement connection tracing as the first hook, feeding
   `EbpfSignal` into the existing resilience/analytics consumers via
   the `EbpfEventConsumer` trait.
3. Re-evaluate XDP steering and ambient redirect (DW-107) once the
   ingestion seam and the aya build path are proven in production.
4. Do not implement SO_REUSEPORT LB unless a concrete gap in the
   existing userspace LB / DW-049 upgrade path emerges.

## References

- DW-107 — ambient mesh redirect (the highest-value downstream hook).
- DW-049 — zero-downtime upgrade via SO_REUSEPORT (the existing
  kernel-coupling precedent this spike builds on).
- DW-090 — anomaly scoring (a consumer of connection-tracing signal).
- [aya](https://github.com/aya-rs/aya) — the pure-Rust eBPF toolkit
  this spike targets.
- `crates/dwara-ebpf/` — the companion crate scaffold (this ADR's
  deliverable).
