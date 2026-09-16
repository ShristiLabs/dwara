#!/usr/bin/env python3
"""Protected upstream for the custom-auth demo.

Echoes the method, path, and received headers as JSON so the demo can
prove an AUTHENTICATED request actually reached the backend, and that
denied requests never did (they are short-circuited at the edge).

Usage: protected-upstream.py [port]   (default 18222)
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "headers": {k: v for k, v in self.headers.items()},
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
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18222
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"protected-upstream listening on 127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
