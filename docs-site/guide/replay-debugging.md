# Replay debugging

Dwara can record the routing decisions it makes for a window of traffic and
replay them offline, so you can reproduce a "why did this request go there?"
question against the exact config and request set that produced it -- without
re-running the live gateway or guessing which route matched. This is
time-travel debugging for routing: capture, then replay.

## When to use this

Use replay debugging when a request reached the wrong upstream, a canary
split sent traffic somewhere unexpected, a retry or timeout fired
mysteriously, or a config change produced a different match set than you
expected. Capture a trace window while the issue is happening (or reproduce
it under load), then replay the trace offline to inspect every decision the
gateway made -- the matched route, the evaluated policies, the upstream
selected, and the response status -- without touching production again.

## Capturing a trace

Capture is a CLI subcommand that talks to the running gateway over the admin
API. It records a bounded ring buffer of decision records in memory and
flushes them to a file on demand.

```sh
dwara replay capture --duration 60s --output /tmp/trace.dwara
```

Each record contains: the request method, path, headers that influenced
routing (host, authority, x-forwarded-*), the matched route name, the
evaluated policy verdicts (authn, authz, rate limit, quota), the selected
upstream and load-balancer pick, the retry/timeout decisions, and the final
response status and latency. Sensitive headers (authorization, cookies,
api-key) are redacted by default; opt into full capture with
`--include-secrets` only in a controlled environment.

The capture duration is bounded to keep the ring buffer finite; the default
is 60 seconds and the maximum is 10 minutes. A capture that hits the buffer
cap before the duration elapses drops the oldest records -- capture is a
sliding window, not an exhaustive log.

## Replaying a trace

Replay runs the recorded decisions back through the config compiler and
policy engine, offline, against a config file you point it at. This lets you
diff "what the live config did" against "what a candidate config would do"
for the same request set.

```sh
dwara replay run --trace /tmp/trace.dwara --config /etc/dwara/config.yaml
```

By default replay uses the config snapshot embedded in the trace file (the
gateway stamps the trace with the config hash at capture time), so a bare
replay reproduces the live decisions exactly. Pass `--config` to replay
against a different config and compare: the output is a table of
request-id, the original decision, the replayed decision, and a `MATCH` or
`DIVERGENCE` marker.

```sh
dwara replay run --trace /tmp/trace.dwara --config candidate.yaml --diff
```

A divergence report names the field that changed -- the route that matched,
the upstream that was picked, the policy that flipped from allow to deny --
so you can trace a config change's blast radius before shipping it.

## Notes

- Capture and replay are read-only against the gateway: capture reads the
  in-memory decision buffer, replay runs entirely offline. Neither sends
  traffic to upstreams.
- The trace format is versioned against the gateway build; a trace captured
  on one version may not replay on another if the decision record schema
  changed. The CLI reports the mismatch rather than silently mis-replaying.
- Trace files contain redacted request metadata, not bodies, so they are
  safe to share for support -- but they still name routes and upstreams, so
  treat them as internal.
