#!/usr/bin/env python3
"""Mock entitlement microservice for the user-subset migration demo.

The business system that decides WHO migrates: it owns the allow-list
and serves it over HTTP. It never talks to the gateway directly --
the publisher (publish.sh) pulls the list and materializes it into the
plugin's config on change. That decoupling is the point of Option A:
the gateway has zero per-request dependency on this service.

- GET  /entitlements -> {"allowed_users": [...], "revision": N}
- POST /entitlements (body {"allowed_users": [...]})
       replaces the list wholesale, bumps the revision.

The revision exists so the demo can show freshness (each publish picks
up the newest revision; there is no caching anywhere).

Usage: entitlement.py [port]   (default 18203)
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = {"allowed_users": ["user-42"], "revision": 1}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = json.dumps(STATE).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.split("?")[0] != "/entitlements":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length))
            users = payload["allowed_users"]
            if not isinstance(users, list) or not all(
                isinstance(u, str) for u in users
            ):
                raise ValueError("allowed_users must be a list of strings")
        except (ValueError, KeyError) as error:
            body = json.dumps({"error": str(error)}).encode()
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        STATE["allowed_users"] = users
        STATE["revision"] += 1
        body = json.dumps({"ok": True, **STATE}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        # Quiet: the harness owns the console.
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18203
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"entitlement service listening on 127.0.0.1:{port}", flush=True)
    print(f"initial allow-list: {STATE['allowed_users']}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
