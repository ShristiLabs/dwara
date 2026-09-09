#!/usr/bin/env python3
"""OpenAI-compatible mock AI provider.

Implements:
  POST /v1/chat/completions        - OpenAI chat completions (streaming + non-streaming)
  POST /v1/messages                - Anthropic messages API (streaming + non-streaming)
  POST /v1/embeddings              - fixed-dimension embeddings (deterministic,
                                     semantically similar for similar prompts)
  POST /tasks/submit               - A2A task-submit (JSON-RPC 2.0, agent demo)

Special model names:
  rate-limit-test  - returns 429 (for failover/quarantine tests)
  error-test       - returns 500 (for circuit breaker tests)
  delay-test       - adds 2s delay (for timeout tests)
"""
import hashlib
import json
import re
import time
import uuid
import http.server
import os

PORT = int(os.environ.get("PORT", "8080"))

# --- Deterministic semantic embeddings -------------------------------------
#
# The gateway's AI semantic cache (DW-083) calls POST /v1/embeddings with the
# prompt text and cosine-compares the returned vectors. For the demo to show
# real semantic-cache hits, the mock must return DETERMINISTIC vectors where
# paraphrased prompts land near each other. Scheme: tokenize the text, map
# each distinct token to a fixed pseudo-random vector derived from md5
# (Python's builtin hash() is per-process randomized -- never usable here),
# and average the token vectors with content words weighted 1.0 and common
# stopwords 0.1. Two prompts sharing their content words therefore have
# cosine similarity ~= 0.99, while unrelated prompts land near 0.
EMBEDDING_DIM = 128

_STOPWORDS = frozenset(
    """
    the a an is are was were of to in on at for with and or but what whats
    which who whom how why when where do does did can could should would will
    shall may might you your yours i me my we our us it its this that these
    those there here tell please give show say said write make about into
    """.split()
)


def _token_vector(token):
    """Deterministic pseudo-random vector for one token (md5-seeded)."""
    return [
        (int.from_bytes(hashlib.md5(f"{token}#{i}".encode()).digest()[:4], "big") / 2**32) * 2.0 - 1.0
        for i in range(EMBEDDING_DIM)
    ]


def semantic_embedding(text):
    """Token-set-hashed embedding: similar prompts -> near-identical vectors."""
    tokens = {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 1} or {"<empty>"}
    vec = [0.0] * EMBEDDING_DIM
    for t in tokens:
        weight = 0.1 if t in _STOPWORDS else 1.0
        tv = _token_vector(t)
        for i in range(EMBEDDING_DIM):
            vec[i] += weight * tv[i]
    return vec


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
    if not isinstance(text, str):
        text = " ".join(text) if isinstance(text, list) else str(text)
    return {
        "object": "list",
        "model": model,
        "data": [
            {
                "index": 0,
                "embedding": semantic_embedding(text),
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

        # A2A task-submit (JSON-RPC 2.0 over HTTP): the gateway's a2a
        # provider adapter (DW-114) folds a canonical chat request into
        # {"jsonrpc":"2.0","method":"tasks/submit","params":{"model",
        # "message":{role,content},...}} and parses the answer back from
        # result.message. Echo the task text so tests can prove the
        # request traversed the A2A adapter, and report a completed
        # terminal task state with OpenAI-shaped usage.
        if path == "/tasks/submit":
            params = body.get("params", {})
            task_model = params.get("model", "unknown")
            message = params.get("message", {})
            if isinstance(message, dict):
                content = message.get("content", "")
                if isinstance(content, list):
                    content = "".join(
                        b.get("text", "") for b in content if isinstance(b, dict)
                    )
            else:
                content = str(message)
            resp = {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {
                    "message": {
                        "role": "assistant",
                        "content": f"A2A mock agent reply to: {str(content)[:100]}",
                    },
                    "model": task_model,
                    "state": "completed",
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 20,
                        "total_tokens": 30,
                    },
                },
            }
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
