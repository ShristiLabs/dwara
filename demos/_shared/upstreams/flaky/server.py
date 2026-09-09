#!/usr/bin/env python3
"""Flaky server: returns 500 on a configurable percentage of requests.

Path-based control: /flaky/30 returns 500 for 30% of requests.
Default error rate is 50%.
"""
import json
import random
import http.server
import os
from urllib.parse import urlparse

PORT = int(os.environ.get("PORT", "8080"))


class FlakyHandler(http.server.BaseHTTPRequestHandler):
    def _respond(self):
        parsed = urlparse(self.path)
        parts = parsed.path.split("/")
        error_rate = 50
        if len(parts) >= 3 and parts[1] == "flaky":
            try:
                error_rate = int(parts[2])
            except ValueError:
                pass
        if random.randint(1, 100) <= error_rate:
            payload = json.dumps({"error": "flaky_500", "rate": error_rate}).encode()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            payload = json.dumps({"ok": True, "rate": error_rate}).encode()
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
    server = http.server.HTTPServer(("0.0.0.0", PORT), FlakyHandler)
    print(f"flaky server listening on :{PORT}", flush=True)
    server.serve_forever()
