#!/usr/bin/env python3
"""Echo server: reflects the request as JSON.

Returns method, path, query params, headers, and body so test scripts
can verify what the gateway sent to the upstream.
"""
import json
import http.server
import os
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("PORT", "8080"))
INSTANCE = os.environ.get("INSTANCE_NAME", "echo")


class EchoHandler(http.server.BaseHTTPRequestHandler):
    def _respond(self):
        parsed = urlparse(self.path)
        body = b""
        if self.command in ("POST", "PUT", "PATCH"):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
        resp = {
            "instance": INSTANCE,
            "method": self.command,
            "path": self.path,
            "parsed_path": parsed.path,
            "query": parse_qs(parsed.query),
            "headers": dict(self.headers),
            "body": body.decode("utf-8", errors="replace"),
        }
        payload = json.dumps(resp, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Echo-Instance", INSTANCE)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def do_PUT(self):
        self._respond()

    def do_PATCH(self):
        self._respond()

    def do_DELETE(self):
        self._respond()

    def do_HEAD(self):
        self._respond()

    def do_OPTIONS(self):
        self._respond()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", PORT), EchoHandler)
    print(f"echo server [{INSTANCE}] listening on :{PORT}", flush=True)
    server.serve_forever()
