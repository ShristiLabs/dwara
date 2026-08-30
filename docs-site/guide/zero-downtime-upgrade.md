# Zero-downtime binary upgrade

Dwara supports swapping the gateway binary under load with zero failed
requests and zero reset connections. The mechanism is a SO_REUSEPORT
hand-off triggered by `SIGUSR2`: the old process spawns a new copy of
itself, both bind the same ports, the new process starts accepting, and
the old process drains and exits.

## How it works

1. Every listening socket is bound with `SO_REUSEPORT` (in addition to
   `SO_REUSEADDR`). This allows a second process to bind the same port
   while the first is still listening. On Linux the kernel
   load-balances accepts across both sockets; on macOS both sockets may
   accept (the hand-off still works).
2. On `SIGUSR2`, the old process spawns a new copy of the binary (the
   same path by default, or `DWARA_UPGRADE_BINARY`). The child inherits
   the environment (`DWARA_CONFIG`, `DWARA_BIND`, ...), so it serves the
   same listeners.
3. The new process binds its listeners (SO_REUSEPORT lets it bind
   alongside the old), spawns its accept tasks, then signals `READY` to
   the old process over a Unix domain socket.
4. The old process receives `READY` and runs the same drain sequence as
   `SIGTERM`: stop accepting, flush kernel backlogs, drain HTTP
   connections within the shutdown budget, exit 0. Because the new
   process is already accepting, no connection is refused and no
   in-flight connection is reset.
5. If the new process fails to start or does not signal `READY` within
   the timeout, the old process logs the error and **keeps running** —
   a failed upgrade never takes the gateway down.

## Triggering an upgrade

### With the CLI

Start the gateway with `DWARA_PID_FILE` set so the CLI can find it:

```sh
DWARA_PID_FILE=/run/dwara.pid dwara --config /etc/dwara/dwara.yaml
```

Install the new binary (replace the file on disk), then:

```sh
dwara-cli upgrade
```

The CLI reads the PID from the PID file and sends `SIGUSR2`. You can
also pass the PID explicitly:

```sh
dwara-cli upgrade --pid 12345
dwara-cli upgrade --pid-file /run/dwara.pid
```

The command only delivers the signal — the hand-off is asynchronous.
Watch the gateway logs to confirm:

```
upgrade_initiated  SIGUSR2 received: spawning new binary ...
upgrade_child_spawned  upgrade child spawned; waiting for READY signal
upgrade_ready  new process signaled READY; the old process will drain and exit
drained, exiting
```

### With kill directly

```sh
kill -USR2 $(cat /run/dwara.pid)
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DWARA_PID_FILE` | unset | Write the process PID here on startup. The `dwara upgrade` CLI reads it to find the process to signal. The new process overwrites it after signaling READY. |
| `DWARA_UPGRADE_BINARY` | current executable | Path to the new binary for an upgrade. Override to swap in a different binary. |
| `DWARA_UPGRADE_READY_TIMEOUT_SECS` | `30` | How long the old process waits for the new process to signal READY before giving up (and keeping the old process running). |

## systemd

For a systemd-managed gateway, the upgrade is operator-driven (not
auto-restarted by systemd). Set `DWARA_PID_FILE` in the unit and run
`dwara-cli upgrade` (or `kill -USR2`) after replacing the binary. The
old process exits 0; systemd may restart it depending on
`Restart=` — to avoid a double-start, set `Restart=on-failure` (exit 0
does not trigger a restart) or use `Type=exec` with `ExecReload` wired
to the upgrade signal.

## Limitations

- **Passthrough splices** are not drained (the same documented
  limitation as SIGTERM): a raw TLS byte splice has no drain signaling.
  In-flight passthrough connections run until the old process exits.
- The **listener bind set** is fixed at startup (address/port). An
  upgrade inherits the same listeners; changing the bind set still
  requires a full restart.
- `SO_REUSEPORT` is available on Linux and macOS. The hand-off is
  portable across both; Linux's load-balancing is more even.
