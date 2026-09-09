#!/usr/bin/env python3
"""WebSocket echo server.

Accepts WebSocket connections and echoes back any message received.
Used by the WebSocket proxying demo.
"""
import asyncio
import os

import websockets

PORT = int(os.environ.get("PORT", "8080"))


async def echo_handler(websocket):
    async for message in websocket:
        await websocket.send(f"echo: {message}")


async def main():
    print(f"ws-echo server listening on :{PORT}", flush=True)
    async with websockets.serve(echo_handler, "0.0.0.0", PORT):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
