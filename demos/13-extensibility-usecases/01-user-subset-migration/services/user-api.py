#!/usr/bin/env python3
"""Mock user API for the user-subset migration demo (use case 1).

One service, two API versions -- exactly the shape the recipe assumes:
the enhancements "land as a new endpoint /v2/user" on the same API
while the old endpoint stays untouched. The version that answered is
observable in the response body:

- the /v1/user handler  -> {"api":"v1","endpoint":"/v1/user",...}
- the /v2/user handler  -> {"api":"v2","endpoint":"/v2/user",...,
                            "enhancement":"parallel-previews"}

Which handler answers is decided by the request's own path: the
gateway's plugin rewrites the proxy-wasm :path for migrated users, and
the host applies that rewrite to the FORWARDED request (after route
resolution, before the dial -- no route re-match), so the /v2/user
request arrives here directly.

Any non-user path echoes the method, path, and received headers as
JSON (the control-channel shape: the plugin-less /public/ route lands
here, proving it was never rewritten).

Usage: user-api.py [port]   (default 18202)
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        effective = self.path.split("?")[0]
        user = self.headers.get("x-user-id")
        if effective == "/v1/user":
            payload = {"api": "v1", "endpoint": effective, "user": user}
        elif effective == "/v2/user":
            payload = {
                "api": "v2",
                "endpoint": effective,
                "user": user,
                "enhancement": "parallel-previews",
            }
        else:
            payload = {
                "method": self.command,
                "path": self.path,
                "headers": {k: v for k, v in self.headers.items()},
            }
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        # Quiet: the harness owns the console.
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18202
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"user-api listening on 127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
