#!/usr/bin/env python3
"""Webhook receiver: collects webhook events and analytics-stream batches.

Stores received events in /tmp/events.jsonl for test assertions.
Prints each event to stdout for debugging.
"""
import json
import http.server
import os
from datetime import datetime

PORT = int(os.environ.get("PORT", "8080"))
EVENTS_FILE = "/tmp/events.jsonl"


class WebhookHandler(http.server.BaseHTTPRequestHandler):
    def _respond(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "path": self.path,
            "method": self.command,
            "headers": dict(self.headers),
            "body": json.loads(body) if body else None,
        }
        print(json.dumps(entry, indent=2), flush=True)
        with open(EVENTS_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"received": true}')

    def do_POST(self):
        self._respond()

    def do_GET(self):
        if self.path == "/events":
            try:
                with open(EVENTS_FILE) as f:
                    lines = f.readlines()
            except FileNotFoundError:
                lines = []
            payload = json.dumps([json.loads(l) for l in lines]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    if os.path.exists(EVENTS_FILE):
        os.remove(EVENTS_FILE)
    server = http.server.HTTPServer(("0.0.0.0", PORT), WebhookHandler)
    print(f"webhook-receiver listening on :{PORT}", flush=True)
    server.serve_forever()
