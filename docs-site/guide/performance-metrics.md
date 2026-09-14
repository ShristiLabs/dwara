# Performance metrics

Dwara's benchmark and soak harnesses capture a set of system and
gateway-level metrics that describe throughput, latency, resource
usage, and stability under load. This page explains what each metric
means, how it is measured, and how to interpret it for capacity
planning and troubleshooting.

## Memory

### RSS (Resident Set Size)

The amount of physical RAM the gateway process currently occupies.
This is the single most important memory metric for a long-running
gateway because it catches leaks.

- **What it includes:** code segment, heap allocations, stack,
  memory-mapped files, and all loaded shared libraries that are paged
  in.
- **What it excludes:** swapped-out pages and shared libraries that are
  mapped but never touched.
- **Why it matters:** a memory leak shows as RSS that grows
  monotonically and never plateaus. The soak test asserts RSS stays
  below a ceiling (256 MB default) over a sustained run. Normal warmup
  (connection pool fill, allocator arenas) causes RSS to rise and then
  stabilize — that is expected, not a leak.
- **How it is measured:** `/proc/<pid>/status` on Linux (`VmRSS`
  field), `ps -o rss` on macOS. Reported in KB.

### Heap vs RSS

RSS is the OS-level view. The heap (what the Rust allocator manages) is
a subset. A gateway can have stable heap usage but growing RSS if it
is memory-mapping large files or if the allocator does not return freed
memory to the OS (fragmentation). For leak detection, RSS is the
practical signal because it reflects actual memory pressure on the
host.

## File descriptors

### fd_count (File Descriptor Count)

The number of open file descriptors the process holds. Every socket,
every open file, every pipe is a file descriptor on Unix.

- **What contributes to it in a gateway:**
  - **Listening sockets** — one per listener (TLS, plaintext, admin).
  - **Inbound connections** — one fd per connected client.
  - **Outbound connections** — one fd per upstream connection (active
    plus idle pooled).
  - **Internal runtime fds** — eventfd, timerfd, epoll handles used by
    the async runtime.
  - **Persistent fds** — log files, SQLite database, config file.
- **Why it matters:** the OS imposes a per-process limit (`ulimit -n`).
  On Linux CI runners the hard limit is typically 65536; on production
  hosts it is often raised to 1M+. If the gateway exhausts its fd
  budget, new connections fail with `EMFILE` or `ENFILE`. The
  100k-connection benchmark requires `ulimit -n 1048576`.
- **How it is measured:** count entries in `/proc/<pid>/fd/` on Linux,
  `lsof -p <pid>` on macOS.
- **Expected behavior:** fd_count scales roughly linearly with
  concurrent connections (two fds per connection pair: inbound plus
  outbound). A stable workload should show a stable fd_count. A leak
  (fds never closed) shows as unbounded growth.

## CPU

### cpu_pct (CPU Utilization Percentage)

The percentage of CPU time the process consumed, normalized to 100%
equaling one full core.

- **How to read it:** on a 4-core machine, 400% means all 4 cores are
  saturated. A CI runner with 2 cores showing 190% CPU means the
  gateway is using roughly 1.9 of 2 available cores, leaving little
  headroom for the echo upstream and load generator.
- **Why it matters:** CPU saturation is the primary throughput limiter
  for a proxy. When `cpu_pct` plateaus at `cores * 100%` while RPS
  stops scaling, the gateway is CPU-bound. At that point, raising
  concurrency or connection counts will not increase throughput — it
  will only increase latency.
- **How it is measured:** sampling `/proc/<pid>/stat` (utime plus stime)
  over a window, or `ps -o %cpu` on macOS.
- **Caveat for shared environments:** `cpu_pct` is noisy on shared
  runners because the VM's CPU is time-sliced with other tenants. The
  regression gate compares RPS and p99 only — CPU% is display-only, not
  a gate criterion.

## Latency

### p50, p90, p99, p999 (Percentiles)

Latency percentiles measured per request, from send to response
received.

| Percentile | Meaning |
| --- | --- |
| p50 (median) | Half of requests are faster than this. |
| p90 | 90% of requests are faster; 10% are slower. |
| p99 | 99% are faster; the tail — 1 in 100 requests is slower. |
| p999 | 99.9% are faster; 1 in 1000 is slower. |

- **Why percentiles, not averages:** averages hide tail latency. A
  gateway with a 0.5 ms average but a 50 ms p99 is unacceptable for
  latency-sensitive workloads, even though the average looks fine.
- **p99 is the primary regression gate metric** because it is the most
  sensitive to contention, GC pauses, lock contention, and scheduling
  jitter. A regression in p99 (for example, from 0.7 ms to 1.5 ms)
  signals a real problem even if p50 is unchanged.
- **p99 drift (soak-specific):** the soak test compares "early p99"
  (median of the first 3 sample windows) versus "late p99" (median of
  the last 3 windows). A drift above 50% means latency is degrading
  over time — a sign of resource exhaustion (memory pressure causing
  allocator slowdown, connection pool bloat, or scheduler thrashing).

### err_p99_ns

The p99 latency of error responses only. In a healthy run with zero
errors, this is 0. If errors occur, this tells you whether errors are
fast (for example, immediate 503 from rate limiting) or slow (for
example, timeout after 30 seconds). It helps distinguish "errors from
fast rejection" from "errors from slow failure."

## Throughput

### RPS (Requests Per Second)

The headline throughput metric: completed requests per second.

- **How it is measured:** `total_requests / duration_seconds`. The
  load generator sends requests at a target rate (or unbounded if
  rate is 0) and counts completed responses.
- **What affects it:** per-request CPU cost (parsing, routing,
  proxying, writing), connection setup overhead, upstream latency, lock
  contention, and system saturation.
- **Interpreting the number:** RPS on a shared CI runner is lower than
  on a dedicated host because the runner's CPU is shared with other
  tenants and the load generator plus echo upstream compete for the
  same cores. Compare RPS only between runs on the same machine class.

### Rate (Target RPS)

The load generator's configured send rate. `rate=0` means "send as fast
as possible" (unbounded). A non-zero rate caps the send rate to test
whether the gateway can sustain a target throughput without latency
degradation. The rate-sweep benchmark sweeps target rates to find the
"saturation knee" — the point where actual RPS stops tracking the
target.

## Connections

### connections (Concurrent Connections)

The number of persistent (keep-alive) connections the load generator
holds open to the gateway simultaneously.

- **Low (1-10):** measures pure per-request latency. The bottleneck is
  single-threaded request processing speed, not concurrency.
- **Medium (100):** starts to exercise connection pooling, upstream
  multiplexing, and concurrent request handling.
- **High (1000+):** stresses the connection pool, file descriptor
  budget, and scheduler. This is where lock contention and memory
  growth become visible.
- **Very high (100k):** the NFR (non-functional requirement) bar. Tests
  fd budget exhaustion, connection acceptance rate, and memory under
  extreme concurrency. Fails by design on standard CI runners —
  requires a dedicated host with a raised fd limit.

## How the metrics relate

```
connections  ->  fd_count   (each connection = 1 fd)
            ->  cpu_pct    (more concurrent work = more CPU)
            ->  rps        (throughput, limited by CPU or contention)
            ->  p99        (latency, degrades under contention/saturation)
            ->  rss        (memory, grows with pool size and connections)
```

The soak test ties them together: sustained load at fixed RPS and
connections, watching RSS (leak detection) and p99 drift (latency
degradation detection). The macro sweep varies connections to find the
throughput ceiling. The micro benchmarks isolate per-primitive cost
(routing, parsing, balancing) in nanoseconds to catch regressions in
individual hot-path components.

## Interpreting benchmark output

The macro benchmark harness prints a table like this:

```
CONNECTIONS    REQUESTS        RPS     ERRORS    P50(us)    P90(us)    P99(us) P999(us)
------------------------------------------------------------------------------------
10               617881      30849          0        302        432        609        966
100              940963      47024          0       2064       2898       3768       4628
1000             773739      38630          0      25424      36070      46208      55742
```

Read it as follows:

- **ERRORS must be 0** for the run to pass. Any non-zero error count
  indicates a problem — upstream saturation, fd exhaustion, or a
  gateway bug.
- **RPS rises then falls** as connections increase. The peak RPS is
  the throughput ceiling for this machine and config. Beyond the peak,
  added concurrency only increases latency.
- **p50 and p99 diverge** as connections increase. A small gap (p99 is
  2-3x p50) means predictable latency. A large gap (p99 is 50x p50)
  means high tail latency — some requests are hitting contention or
  scheduling delays.

The soak harness prints per-window samples:

```
T_S            RSS_KB         P99_NS          RPS     ERRORS   REQUESTS
----------------------------------------------------------------------
0               28220        2027289         1000          0      30000
30              29404        2040920         1000          0      30000
...
570             31380        1957350         1000          0      30000
```

Read it as follows:

- **RSS should stabilize.** Initial growth is warmup (pool fill,
  allocator arenas). After warmup, RSS should plateau. If it keeps
  climbing, there is a leak.
- **P99 should be stable** across windows. A rising p99 means latency
  degradation — the gateway is getting slower under sustained load.
- **ERRORS must be 0** throughout. Any error in a soak window is a
  failure.

## See also

- [Operations](./operations) — runtime tuning knobs that affect these
  metrics.
- [Environment variables](../reference/environment-variables) —
  `DWARA_WORKER_THREADS`, `DWARA_POOL_SHARDS`, and other controls.
- [Observability](./observability) — Prometheus metrics and access
  logs for runtime monitoring.
