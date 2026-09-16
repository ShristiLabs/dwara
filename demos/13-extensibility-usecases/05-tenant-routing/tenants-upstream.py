#!/usr/bin/env python3
"""Per-tenant mock upstream for the tenant-routing demo.

The gateway's plugin rewrites the proxy-wasm :path
(/portal/<rest> -> /tenant/<tenant>/<rest>) and the host applies that
rewrite to the FORWARDED request, so this mock sees -- and keys on --
the rewritten path itself: the /tenant/<t>/ prefix IS the per-tenant
routing decision, standing in for per-tenant upstream pools. The
tenant is decoded from the path prefix, and the x-tenant request
header the plugin stamped is echoed separately (proving the tagging
half of the recipe).

Usage: tenants-upstream.py [port]   (default 18242)
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

TENANT_HEADER = "x-tenant"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = self.path.split("?")[0]
        # The tenant the rewrite selected: the path prefix. Anything
        # off the /tenant/<t>/ shape reads as "unrouted" (only the
        # readiness probe lands here).
        parts = path.split("/")
        tenant = parts[2] if len(parts) > 3 and parts[1] == "tenant" else "unrouted"
        body = json.dumps(
            {
                "tenant": tenant,
                "path": path,
                "seen_tenant_header": self.headers.get(TENANT_HEADER),
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
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18242
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"tenants-upstream listening on 127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
