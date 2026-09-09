#!/usr/bin/env python3
"""OpenAI-compatible mock AI provider.

Implements:
  POST /v1/chat/completions        - OpenAI chat completions (streaming + non-streaming)
  POST /v1/messages                - Anthropic messages API (streaming + non-streaming)
  POST /v1/embeddings              - fixed-dimension embeddings

Special model names:
  rate-limit-test  - returns 429 (for failover/quarantine tests)
  error-test       - returns 500 (for circuit breaker tests)
  delay-test       - adds 2s delay (for timeout tests)
"""
import json
import time
import uuid
import http.server
import os

PORT = int(os.environ.get("PORT", "8080"))


def make_completion(model, content):
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }


def make_embedding(model, text):
    dim = 128
    return {
        "object": "list",
        "model": model,
        "data": [
            {
                "index": 0,
                "embedding": [hash(text + str(i)) % 1000 / 1000.0 for i in range(dim)],
            }
        ],
        "usage": {"prompt_tokens": 5, "total_tokens": 5},
    }


def make_anthropic_message(model, content):
    """An Anthropic messages-API response (non-streaming)."""
    return {
        "id": f"msg-{uuid.uuid4().hex[:12]}",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": content}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 20},
    }


def extract_anthropic_prompt(body):
    """Extract the last user turn's text from an Anthropic messages body.

    The `content` of a turn may be a plain string or a list of content
    blocks ({"type": "text", "text": "..."}). Returns the first 100
    chars of the last user message's text, or the joined system prompt
    if there are no user turns.
    """
    messages = body.get("messages", [])
    text = ""
    for m in messages:
        if m.get("role") != "user":
            continue
        c = m.get("content", "")
        if isinstance(c, str):
            text = c
        elif isinstance(c, list):
            parts = [
                b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text"
            ]
            if parts:
                text = "".join(parts)
    return text[:100]


class AiMockHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        path = self.path
        model = body.get("model", "unknown")
        stream = body.get("stream", False)

        if model == "rate-limit-test":
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            err = json.dumps({"error": {"message": "Rate limit exceeded", "type": "rate_limit_error"}}).encode()
            self.send_header("Content-Length", str(len(err)))
            self.end_headers()
            self.wfile.write(err)
            return

        if model == "error-test":
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            err = json.dumps({"error": {"message": "Internal server error", "type": "server_error"}}).encode()
            self.send_header("Content-Length", str(len(err)))
            self.end_headers()
            self.wfile.write(err)
            return

        if model == "delay-test":
            time.sleep(2)

        if path == "/v1/embeddings":
            text = body.get("input", "")
            resp = make_embedding(model, text)
            payload = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        # Anthropic messages API: POST /v1/messages. The gateway's
        # anthropic provider adapter translates OpenAI-style chat
        # requests to this endpoint and parses the Anthropic response
        # shape back to the canonical form.
        if path == "/v1/messages":
            prompt = extract_anthropic_prompt(body)
            content = f"Mock response from model '{model}'. You said: {prompt}"
            if stream:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                msg_id = f"msg-{uuid.uuid4().hex[:12]}"
                self.wfile.write(
                    f"event: message_start\ndata: {json.dumps({'type': 'message_start', 'message': {'id': msg_id, 'type': 'message', 'role': 'assistant', 'model': model, 'content': [], 'stop_reason': None, 'usage': {'input_tokens': 10, 'output_tokens': 0}}})}\n\n".encode()
                )
                self.wfile.flush()
                self.wfile.write(
                    f"event: content_block_start\ndata: {json.dumps({'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text', 'text': ''}})}\n\n".encode()
                )
                self.wfile.flush()
                self.wfile.write(
                    f"event: content_block_delta\ndata: {json.dumps({'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': content}})}\n\n".encode()
                )
                self.wfile.flush()
                self.wfile.write(
                    f"event: content_block_stop\ndata: {json.dumps({'type': 'content_block_stop', 'index': 0})}\n\n".encode()
                )
                self.wfile.flush()
                self.wfile.write(
                    f"event: message_delta\ndata: {json.dumps({'type': 'message_delta', 'delta': {'stop_reason': 'end_turn', 'stop_sequence': None}, 'usage': {'output_tokens': 20}})}\n\n".encode()
                )
                self.wfile.flush()
                self.wfile.write(
                    f"event: message_stop\ndata: {json.dumps({'type': 'message_stop'})}\n\n".encode()
                )
                self.wfile.flush()
            else:
                resp = make_anthropic_message(model, content)
                payload = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            return

        content = f"Mock response from model '{model}'. You said: {body.get('messages', [{}])[-1].get('content', '')[:100]}"

        if stream:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            chunk = {
                "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}],
            }
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.flush()
            final = {
                "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
            self.wfile.write(f"data: {json.dumps(final)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        else:
            resp = make_completion(model, content)
            payload = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", PORT), AiMockHandler)
    print(f"ai-mock server listening on :{PORT}", flush=True)
    server.serve_forever()
