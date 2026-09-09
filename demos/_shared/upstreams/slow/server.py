#!/usr/bin/env python3
"""Slow server: adds a configurable delay before responding.

Path-based control: /slow/500 delays 500ms.
Default delay is 200ms.
"""
import json
import time
import http.server
import os
from urllib.parse import urlparse

PORT = int(os.environ.get("PORT", "8080"))


class SlowHandler(http.server.BaseHTTPRequestHandler):
    def _respond(self):
        parsed = urlparse(self.path)
        parts = parsed.path.split("/")
        delay_ms = 200
        if len(parts) >= 3 and parts[1] == "slow":
            try:
                delay_ms = int(parts[2])
            except ValueError:
                pass
        time.sleep(delay_ms / 1000.0)
        payload = json.dumps({"ok": True, "delay_ms": delay_ms}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", PORT), SlowHandler)
    print(f"slow server listening on :{PORT}", flush=True)
    server.serve_forever()
