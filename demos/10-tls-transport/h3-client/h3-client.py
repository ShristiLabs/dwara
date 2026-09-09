#!/usr/bin/env python3
"""Minimal HTTP/3 (QUIC) GET client for the TLS demo.

Usage:
    python3 h3-client.py --cafile /certs/server.crt \
        [--server-name localhost] https://dwara:8445/healthz

Prints "<status> <body>" on success. Built on aioquic (the pure-Python
QUIC/H3 implementation) because macOS's bundled curl — and the stock
curl docker images — have no HTTP/3 support. Used by
test-07-http3.sh to exercise the gateway's QUIC listener end to end.

Docker Desktop does not reliably forward QUIC through published UDP
ports, so the client dials the gateway's docker-network address
directly (--network <demo net>); --server-name then keeps certificate
verification against the demo cert's localhost SAN.
"""
import argparse
import asyncio
import os
import ssl
import sys
from typing import Optional

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, QuicEvent


class H3GetProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._status: Optional[str] = None
        self._body = b""
        self._terminated = False

    async def get(self, url: str, timeout: float = 10.0) -> tuple:
        """Issue one GET and return (status, body) once complete.

        Completion is polled rather than event-driven: aioquic's h3
        layer emits the final DataReceived with stream_ended=False when
        the FIN rides the same QUIC STREAM frame as the data (the
        fragment shortcut returns early and never re-runs for the lone
        FIN), so a strictly event-driven waiter would hang on this
        framing. Headers + a non-empty body, or the connection's clean
        close, mark the exchange complete.
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        authority = parsed.netloc
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", (parsed.path or "/").encode()),
            ],
            end_stream=True,
        )
        self.transmit()
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if self._status is not None and self._body:
                break
            if self._terminated:
                break
            await asyncio.sleep(0.05)
        return self._status, self._body

    def quic_event_received(self, event: QuicEvent) -> None:
        if os.environ.get("H3_DEBUG"):
            print(f"quic: {event}", file=sys.stderr)
        for http_event in self._http.handle_event(event):
            if os.environ.get("H3_DEBUG"):
                print(f"event: {http_event}", file=sys.stderr)
            if isinstance(http_event, HeadersReceived):
                for name, value in http_event.headers:
                    if name == b":status":
                        self._status = value.decode()
            elif isinstance(http_event, DataReceived):
                self._body += http_event.data
        # The gateway closes the connection (NO_ERROR) after the
        # response; treat that as completion for a pending GET.
        if isinstance(event, ConnectionTerminated):
            self._terminated = True


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--cafile", help="CA bundle to verify the server cert")
    parser.add_argument("--server-name", help="TLS SNI / verification name "
                        "(defaults to the URL host; e.g. verify the demo cert's "
                        "'localhost' SAN while dialing the docker service name)")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    from urllib.parse import urlparse

    parsed = urlparse(args.url)
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.cafile:
        configuration.load_verify_locations(args.cafile)
    if args.server_name:
        configuration.server_name = args.server_name

    async with connect(
        parsed.hostname,
        parsed.port,
        configuration=configuration,
        create_protocol=H3GetProtocol,
        wait_connected=True,
    ) as client:
        status, body = await client.get(args.url)
    print(f"{status} {body.decode('utf-8', errors='replace')}")
    return 0 if status and status.startswith("2") else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
