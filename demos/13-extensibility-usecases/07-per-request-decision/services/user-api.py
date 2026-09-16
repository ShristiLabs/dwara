#!/usr/bin/env python3
"""Mock user API for the per-request-decision demo.

The protected upstream: it answers whatever the gateway forwards and
echoes the entitlement headers the plugin stamped, so the demo can
assert the plugin's decision reached the origin (the recipe's whole
point -- the verdict rides the request, not a side channel).

Usage: user-api.py [port]   (default 18263)
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = json.dumps(
            {
                "path": self.path,
                "user": self.headers.get("x-user"),
                "entitlement": self.headers.get("x-entitlement"),
                "entitlement_source": self.headers.get("x-entitlement-source"),
            },
            separators=(",", ":"),
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        # Quiet: the harness owns the console.
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18263
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"user-api listening on 127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
