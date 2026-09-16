#!/usr/bin/env python3
"""Echo upstream for the plugin example harness.

A deliberate non-Rust upstream so the harness depends on nothing but
python3 (already required by the repo's tooling):

- GET /statement* answers a JSON body that carries Luhn-valid card
  numbers (dashed and spaced), an invalid-checksum control number,
  and a literal secret -- everything the response-body-redact example
  must scrub.
- any other path echoes the method, path, and received headers as
  JSON, so request-side plugin effects (stamped headers, short
  circuits) are observable in the response body.

Usage: echo-upstream.py [port]   (default 18102)
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.startswith("/statement"):
            payload = json.dumps(
                {
                    "account": "acct-2211",
                    "card_dashed": "4111-1111-1111-1111",
                    "card_spaced": "5555 5555 5555 4444",
                    "not_a_card": "1234567812345678",
                    "note": "pin is sk-live-12345 for the demo",
                }
            ).encode()
        else:
            headers = {key: value for key, value in self.headers.items()}
            payload = json.dumps(
                {
                    "method": self.command,
                    "path": self.path,
                    "headers": headers,
                }
            ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        # Quiet: the harness owns the console.
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18102
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"echo-upstream listening on 127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
