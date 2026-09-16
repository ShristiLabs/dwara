#!/usr/bin/env python3
"""Mock decision service for the per-request-decision demo.

The external system that computes a per-request verdict: entitlements,
experiment buckets, fraud scores -- here a table plus a slow user that
stands in for an overloaded decider. Every /decide hit is counted per
user so the demo can prove the plugin's TTL cache suppresses them.

- GET /decide?user=X  -> 200 + x-verdict: allow|deny header
       user "mallory" is denied; everyone else is allowed.
       user "slow" sleeps 1.5s first (longer than the plugin's 400ms
       callout timeout: the gateway fails that request closed).
- GET /counts         -> {"user": hits, ...} (the demo's oracle)

Usage: decision-service.py [port]   (default 18262)
"""

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COUNTS = {}
LOCK = threading.Lock()
DENIED = {"mallory"}
SLOW = {"slow"}
SLOW_SECS = 1.5


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/counts":
            with LOCK:
                body = json.dumps(COUNTS, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path != "/decide":
            self.send_error(404)
            return

        user = ""
        if "?" in self.path:
            for pair in self.path.split("?", 1)[1].split("&"):
                if pair.startswith("user="):
                    user = pair[len("user="):]
        with LOCK:
            COUNTS[user] = COUNTS.get(user, 0) + 1
        if user in SLOW:
            time.sleep(SLOW_SECS)

        verdict = "deny" if user in DENIED else "allow"
        body = json.dumps(
            {"user": user, "verdict": verdict}, separators=(",", ":")
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("x-verdict", verdict)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        # Quiet: the harness owns the console.
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18262
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"decision-service listening on 127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
