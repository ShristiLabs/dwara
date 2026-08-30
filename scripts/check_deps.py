#!/usr/bin/env python3
"""Dependency-direction guard for dwara-core's bounded contexts.

The facade (crates/dwara-core/src/lib.rs) documents a strictly downward
dependency order. This script makes a violation a CI failure instead of
a review comment:

    config          depends on nothing
    extensions      <- config
    observability   <- nothing
    events          <- config, observability
    snapshot        <- config, events
    state           <- config
    analytics       <- config, observability, extensions
    security        <- config, state, observability
    resilience      <- config, snapshot, extensions, observability, events
    dataplane       <- everything

Placement decisions this enforces (see lib.rs's dependency table):

- active health probing is a DATAPLANE module (dataplane/active.rs) — it
  drives the upstream registry's balancer trackers, which is dataplane
  lifecycle, so resilience stays free of dataplane imports;
- the trusted-proxy IP/CIDR grammar (config/net.rs), the schema
  validation limits (config/limits.rs), and the credential hash formats
  (config/credentials.rs) live in config so validation and every runtime
  consumer agree without upward imports;
- observability exposes plain setters only — the state-gauge walk lives
  in dataplane (upstream.rs), so observability depends on nothing;
- the event bus sits in its own domain BELOW snapshot (DW-044) because
  the config publish pipeline emits config_published/config_rejected
  while resilience's breaker/health emit transitions; snapshot cannot
  import resilience, so the bus lives lower than both and the two
  publish/emit into it. The webhook deliverer reads config types and
  counts outcomes in observability — hence events' two downward deps.
- the embedded analytics store (DW-043) is its own domain beside state:
  it consumes the AccessRecord type (observability), the analytics
  config block (config — which is why the retention defaults live in
  config, the lowest consumer), and the M1 sink contract
  (extensions::analytics::AnalyticsSink, which it implements), while
  the dataplane only CALLS its record method and the admin crate only
  reads its queries. Like state, it owns a SQLite file and pulls
  rusqlite; promotion to a crate would be a git mv, not a rewrite.

Usage: python3 scripts/check_deps.py [path-to-dwara-core-src]
Exits 1 listing every upward import.
"""

import re
import sys
from pathlib import Path

ALLOWED = {
    "config": set(),
    "extensions": {"config"},
    "observability": set(),
    "events": {"config", "observability"},
    "snapshot": {"config", "events"},
    "state": {"config"},
    "analytics": {"config", "observability", "extensions"},
    "security": {"config", "state", "observability"},
    "resilience": {"config", "snapshot", "extensions", "observability", "events"},
    "dataplane": {
        "config",
        "extensions",
        "snapshot",
        "observability",
        "events",
        "state",
        "analytics",
        "security",
        "resilience",
    },
}

USE_RE = re.compile(r"crate::([a-z_]+)")

violations = []
src = Path(sys.argv[1] if len(sys.argv) > 1 else "crates/dwara-core/src")

for domain, allowed in ALLOWED.items():
    for path in sorted(src.glob(f"{domain}/**/*.rs")) + sorted(src.glob(f"{domain}.rs")):
        text = path.read_text()
        for dep in sorted(set(USE_RE.findall(text))):
            if dep == domain or dep in allowed:
                continue
            if dep not in ALLOWED:
                # not a domain (e.g. a sibling non-domain module); the
                # facade owns the module list, so anything unknown here
                # is a new top-level module -- flag it for triage
                violations.append(
                    f"{path}: imports crate::{dep} which is not a known domain"
                )
                continue
            violations.append(
                f"{path}: imports crate::{dep} but {domain} may only "
                f"depend on: {sorted(allowed) or '(nothing)'}"
            )

if violations:
    print("Dependency-direction check FAILED:", file=sys.stderr)
    for v in violations:
        print(f"  {v}", file=sys.stderr)
    sys.exit(1)

print("Dependency-direction check OK: no upward imports in dwara-core.")
