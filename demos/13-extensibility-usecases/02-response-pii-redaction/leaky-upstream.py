#!/usr/bin/env python3
"""Leaky upstream for the response PII-redaction demo.

Deliberately non-compliant backend: it leaks payment card numbers and
a literal API key into otherwise innocent JSON. Two endpoints:

- GET /api/account -- buffered JSON carrying
    * a spaced Luhn-valid test card (4111 1111 1111 1111) that MUST
      be masked keep-last-4 by the response-body-redact plugin,
    * an innocent 16-digit order reference (1234567812345678) that
      fails the Luhn checksum and MUST pass through untouched,
    * a literal secret (sk-live-12345) the plugin config stars out.
- GET /api/stream -- the same leak over text/event-stream with no
  framing (Connection: close). Streaming responses SKIP the
  response_body phase by contract, so the card streams through
  UNMASKED -- the demo proves both the masking and the documented
  streaming carve-out.

Usage: leaky-upstream.py [port]   (default 18212)
"""

import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

STATEMENT = (
    '{"account":"acct-99","card":"4111 1111 1111 1111",'
    '"order_ref":"1234567812345678","note":"pin is sk-live-12345"}'
)

SSE_LINES = [
    b"event: statement\n",
    b'data: {"card":"4111 1111 1111 1111","order_ref":"1234567812345678"}\n',
    b"\n",
    b"event: done\n",
    b"data: [DONE]\n",
    b"\n",
]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            for line in SSE_LINES:
                self.wfile.write(line)
                self.wfile.flush()
                time.sleep(0.05)
            # No Content-Length anywhere: the body ends at connection
            # close, which is what makes this response streaming.
            self.close_connection = True
            return
        body = STATEMENT.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        # Quiet: the harness owns the console.
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18212
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"leaky-upstream listening on 127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
