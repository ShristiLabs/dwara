#!/usr/bin/env python3
"""Mock identity provider for dwara demos (image dwara-demo/idp-mock).

A single-container stand-in for an external IdP so the demo test
scripts never need crypto tooling on the host. Python stdlib ONLY —
there is no RSA in the stdlib, so the RSA keypair is generated with
the openssl CLI at container start and JWTs are signed with
`openssl dgst -sha256 -sign`.

Why RS256 and not HS256: dwara's JWT authn rejects symmetric
algorithms outright (`none` and `HS*` are never allowed in
`jwt_providers[].algorithms` — the gateway holds no shared secrets
with issuers), so a mock that wants its tokens verified MUST sign
with an asymmetric key.

Endpoints
---------
- GET  /jwks.json                        the public key as a JWKS (RS256)
- GET  /issue?sub=<name>&scope=a,b       mint a signed RS256 JWT for the
                                         subject and return it as text
       &format=opaque                    mint an unstructured token
                                         instead (for OIDC introspection)
- GET  /.well-known/openid-configuration discovery document pointing at
                                         this server's own endpoints
- POST /introspect                       {"active": true, ...} for tokens
                                         minted here, {"active": false}
                                         otherwise (RFC 7662)
- POST /token                            OAuth2 client-credentials token
                                         response (RFC 6749 section 4.4)
- GET  /last-token                       the last /token issuance, for
                                         test assertions
- GET  /stats                            issuance/introspection counters
- POST /revoke                           RFC 7009 revocation (no-op mark)
- GET  /healthz                          readiness probe

Environment
-----------
- ISSUER   the issuer URL embedded in tokens and the discovery doc
           (default http://idp-mock:8080 — the in-network service name,
           which is how the gateway reaches this server).
- AUDIENCE the `aud` claim value (default dwara-demo).
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("PORT", "8080"))
ISSUER = os.environ.get("ISSUER", "http://idp-mock:8080").rstrip("/")
AUDIENCE = os.environ.get("AUDIENCE", "dwara-demo")
KEY_FILE = os.environ.get("KEY_FILE", "/tmp/idp-mock-key.pem")

TOKEN_TTL_S = 3600

# --------------------------------------------------------------------------
# RSA key material via the openssl CLI
# --------------------------------------------------------------------------

KID = None          # key id (stable per keypair)


def b64url(raw: bytes) -> str:
    """Base64url without padding (JWS general convention)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def int_to_bytes(value: int) -> bytes:
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, "big")


def generate_keypair():
    """Generate the RSA keypair and derive the JWKS n/e values."""
    subprocess.run(
        ["openssl", "genrsa", "-out", KEY_FILE, "2048"],
        check=True,
        capture_output=True,
    )
    modulus_hex = subprocess.run(
        ["openssl", "rsa", "-in", KEY_FILE, "-noout", "-modulus"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not modulus_hex.startswith("Modulus="):
        raise RuntimeError(f"unexpected openssl modulus output: {modulus_hex!r}")
    modulus_n = int(modulus_hex[len("Modulus="):], 16)

    rsa_text = subprocess.run(
        ["openssl", "rsa", "-in", KEY_FILE, "-noout", "-text"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    match = re.search(r"Exponent:\s*(\d+)", rsa_text)
    if match is None:
        raise RuntimeError("could not parse RSA exponent from openssl output")
    exponent_e = int(match.group(1))

    # Stable key id derived from the public modulus.
    kid = hashlib.sha256(modulus_hex.encode("ascii")).hexdigest()[:16]
    return modulus_n, exponent_e, kid


def sign_rs256(message: bytes) -> bytes:
    """RS256 signature over `message` with the generated private key."""
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", KEY_FILE],
        input=message,
        check=True,
        capture_output=True,
    )
    return result.stdout


MODULUS_N, EXPONENT_E, KID = generate_keypair()


def jwks_document() -> dict:
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KID,
                "n": b64url(int_to_bytes(MODULUS_N)),
                "e": b64url(int_to_bytes(EXPONENT_E)),
            }
        ]
    }


# --------------------------------------------------------------------------
# Issued-token bookkeeping (introspection answers from memory)
# --------------------------------------------------------------------------

STATE_LOCK = threading.Lock()
# token string -> claims record (JWTs and opaque tokens alike)
ISSUED_TOKENS = {}
# monotonic counters for /stats
COUNTERS = {
    "jwt_issued": 0,
    "opaque_issued": 0,
    "client_credentials_issued": 0,
    "introspections": 0,
    "introspections_active": 0,
    "introspections_inactive": 0,
    "revocations": 0,
}
# the most recent client-credentials grant, for /last-token
LAST_TOKEN = {}


def mint_jwt(sub: str, scope: str) -> str:
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    claims = {
        "iss": ISSUER,
        "sub": sub,
        "aud": AUDIENCE,
        "scope": scope,
        "iat": now,
        "nbf": now,
        "exp": now + TOKEN_TTL_S,
        "jti": uuid.uuid4().hex,
    }
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(claims, separators=(",", ":")).encode())
    )
    signature = sign_rs256(signing_input.encode("ascii"))
    token = signing_input + "." + b64url(signature)
    with STATE_LOCK:
        ISSUED_TOKENS[token] = claims
        COUNTERS["jwt_issued"] += 1
    return token


def mint_opaque(sub: str, scope: str) -> str:
    now = int(time.time())
    token = f"mock-opaque-{uuid.uuid4().hex}"
    claims = {
        "iss": ISSUER,
        "sub": sub,
        "scope": scope,
        "iat": now,
        "exp": now + TOKEN_TTL_S,
        "token_type": "opaque",
    }
    with STATE_LOCK:
        ISSUED_TOKENS[token] = claims
        COUNTERS["opaque_issued"] += 1
    return token


def introspect(token: str):
    """The RFC 7662 view of a token: a claims dict when active."""
    with STATE_LOCK:
        COUNTERS["introspections"] += 1
        record = ISSUED_TOKENS.get(token)
        if record is None or record.get("revoked"):
            COUNTERS["introspections_inactive"] += 1
            return None
        COUNTERS["introspections_active"] += 1
        return record


def issue_client_credentials(basic_user: str, form: dict) -> dict:
    with STATE_LOCK:
        COUNTERS["client_credentials_issued"] += 1
        sequence = COUNTERS["client_credentials_issued"]
    access_token = f"mock-token-{sequence}"
    scope = " ".join(form.get("scope", []))
    record = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL_S,
        "client_id": basic_user,
        "scope": scope,
        "issued_at": int(time.time()),
    }
    with STATE_LOCK:
        # Record the access token so it would introspect as active too.
        ISSUED_TOKENS[access_token] = {
            "iss": ISSUER,
            "sub": basic_user,
            "scope": scope,
            "exp": record["issued_at"] + TOKEN_TTL_S,
            "token_type": "client_credentials",
        }
        LAST_TOKEN.clear()
        LAST_TOKEN.update(record)
    return record


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------


class IdpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # --- helpers -----------------------------------------------------------

    def _send(self, status: int, payload, content_type: str):
        if isinstance(payload, (dict, list)):
            body = json.dumps(payload, indent=2).encode()
        elif isinstance(payload, str):
            body = payload.encode()
        else:
            body = payload
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload, status: int = 200):
        self._send(status, payload, "application/json")

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _basic_user(self):
        """The username of the HTTP Basic Authorization header, if any."""
        auth = self.headers.get("Authorization", "")
        if not auth.lower().startswith("basic "):
            return None
        try:
            decoded = base64.b64decode(auth[6:].strip()).decode("utf-8")
            return decoded.split(":", 1)[0]
        except Exception:
            return None

    def log_message(self, fmt, *args):
        pass

    # --- GET ----------------------------------------------------------------

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/jwks.json":
            self._send_json(jwks_document())
            return

        if parsed.path == "/issue":
            sub = query.get("sub", ["demo-user"])[0]
            scope = query.get("scope", [""])[0].replace(",", " ").strip()
            while "  " in scope:
                scope = scope.replace("  ", " ")
            if query.get("format", ["jwt"])[0] == "opaque":
                token = mint_opaque(sub, scope)
            else:
                token = mint_jwt(sub, scope)
            self._send(200, token + "\n", "text/plain")
            return

        if parsed.path == "/.well-known/openid-configuration":
            self._send_json(
                {
                    "issuer": ISSUER,
                    "jwks_uri": f"{ISSUER}/jwks.json",
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "introspection_endpoint": f"{ISSUER}/introspect",
                    "revocation_endpoint": f"{ISSUER}/revoke",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                }
            )
            return

        if parsed.path == "/last-token":
            with STATE_LOCK:
                snapshot = dict(LAST_TOKEN)
            self._send_json(snapshot if snapshot else {"error": "no token issued yet"})
            return

        if parsed.path == "/stats":
            with STATE_LOCK:
                snapshot = dict(COUNTERS)
            self._send_json(snapshot)
            return

        if parsed.path == "/healthz":
            self._send(200, "ok\n", "text/plain")
            return

        self._send_json({"error": "not found"}, 404)

    # --- POST ---------------------------------------------------------------

    def do_POST(self):
        parsed = urlparse(self.path)
        body = self._read_body()
        try:
            form = parse_qs(body.decode("utf-8"))
        except Exception:
            form = {}

        if parsed.path == "/introspect":
            token = form.get("token", [""])[0]
            record = introspect(token)
            if record is None:
                self._send_json({"active": False})
            else:
                self._send_json(
                    {
                        "active": True,
                        "sub": record.get("sub"),
                        "scope": record.get("scope", ""),
                        "iss": record.get("iss", ISSUER),
                        "aud": record.get("aud"),
                        "exp": record.get("exp"),
                        "iat": record.get("iat"),
                        "client_id": self._basic_user(),
                        "token_type": record.get("token_type", "Bearer"),
                    }
                )
            return

        if parsed.path == "/token":
            grant = form.get("grant_type", [""])[0]
            if grant != "client_credentials":
                self._send_json(
                    {
                        "error": "unsupported_grant_type",
                        "error_description": f"grant_type '{grant}' is not supported; use client_credentials",
                    },
                    400,
                )
                return
            record = issue_client_credentials(self._basic_user(), form)
            self._send_json(
                {
                    "access_token": record["access_token"],
                    "token_type": record["token_type"],
                    "expires_in": record["expires_in"],
                    "scope": record["scope"],
                }
            )
            return

        if parsed.path == "/revoke":
            token = form.get("token", [""])[0]
            with STATE_LOCK:
                record = ISSUED_TOKENS.get(token)
                if record is not None:
                    record["revoked"] = True
                COUNTERS["revocations"] += 1
            # RFC 7009: 200 regardless (the client is not told whether
            # the token existed).
            self._send(200, b"", "application/octet-stream")
            return

        self._send_json({"error": "not found"}, 404)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), IdpHandler)
    print(
        f"idp-mock listening on :{PORT} (issuer {ISSUER}, kid {KID})",
        flush=True,
    )
    server.serve_forever()
