# eBPF hooks (research spike)

Dwara is investigating [eBPF](https://en.wikipedia.org/wiki/EBPF) hooks
as a path to ambient mesh integration -- observing and steering traffic
at the Linux kernel layer without an explicit sidecar per workload. This
page records the current state of that investigation and the direction
it points, so operators can see what is on the roadmap and what is not
yet available.

## When to use this

You would use eBPF hooks when they exist to get traffic observability,
L4 redirect, and policy enforcement for workloads that do not run a
dwara sidecar -- the ambient mesh model. Today there is nothing to use:
the work is a research spike, not a shipped feature. This page exists to
set expectations and document the decision.

## Current state

The investigation produced a scaffold crate (`dwara-ebpf`) that sketches
the kernel-hook surface: a set of eBPF programs attached to socket and
cgroup hooks, a userspace loader, and the contract for exchanging
metadata with the gateway's dataplane. The crate compiles and the loader
attaches the programs on a test kernel, but no traffic is steered or
observed in production yet -- the programs are probes, not a working
dataplane.

## The decision

The spike concluded with an architecture decision record (ADR) recording
the direction: pursue eBPF as the basis for an ambient mesh integration,
where the gateway's control plane programs kernel hooks on each node and
the dataplane observes traffic without a per-pod sidecar. The ADR weighs
kernel-version sensitivity (eBPF program types and helpers vary across
distros), the operational complexity of a privileged loader, and the
benefit of removing the sidecar resource tax. The decision is to invest
in the eBPF path as a longer-term enterprise feature, not to ship it in
the OSS edition.

## Roadmap

The roadmap, in order, is:

1. Replace the probe programs with a minimal working observer
   (per-connection metadata to the gateway's analytics).
2. Add L4 redirect so ambient traffic can be steered to a gateway
   instance without a sidecar.
3. Wire the observer and redirect into the control plane as an
   enterprise feature, behind the editions gate.

None of these are scheduled for a specific release. The scaffold crate
and the ADR are the deliverables of the spike; the implementation is future.
