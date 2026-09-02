//! eBPF companion crate for dwara (DW-104, research spike).
//!
//! This crate is a RESEARCH SCAFFOLD -- it contains trait definitions
//! and documentation for future eBPF integration, but no working
//! eBPF programs. See docs/adr/0002-ebpf-hooks-research-spike.md
//! for the research analysis and recommendations.
//!
//! Linux-only: eBPF requires kernel 5.4+ (BTF/CO-RE). This crate
//! is excluded from the default workspace build and CI matrix.

/// A kernel-level network signal emitted by an eBPF program.
///
/// The variants model the connection-level events a connection-tracing
/// tracepoint (`sockinet/inet_sock_set_state`) would produce as the
/// first hook if this spike advances to implementation (see ADR-0002).
/// Future hooks (XDP steering, ambient redirect) would extend this enum
/// with packet-level and redirect events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EbpfSignal {
    /// A TCP connection entered the ESTABLISHED state.
    ConnectionOpen,
    /// A TCP connection transitioned to a closed state (CLOSE /
    /// CLOSE_WAIT / TIME_WAIT).
    ConnectionClose,
    /// A retransmit was observed on a tracked connection.
    Retransmit,
    /// A packet was dropped on a tracked connection (kernel-side,
    /// before the userspace handler saw it).
    Drop,
}

/// Consumer of [`EbpfSignal`] events.
///
/// A future eBPF program loaded via aya would push signals through a
/// ring buffer; the userspace side drains the buffer and forwards each
/// signal to every registered consumer. The resilience domain's
/// passive health tracker and the anomaly scorer (DW-090) are the
/// intended first consumers of connection-tracing signals.
///
/// This is a scaffold trait only -- no implementation is shipped in
/// this spike.
pub trait EbpfEventConsumer {
    /// Ingest a single eBPF signal.
    fn ingest(&self, signal: &EbpfSignal);
}
