# Minimal HTTP/3 client for the TLS demo (aioquic-based GET).
#
# macOS's bundled curl and the stock curl docker images lack HTTP/3,
# so the demo carries its own tiny h3 client to exercise the QUIC
# listener end to end. Build it (one-time) with:
#
#   docker compose -f docker-compose.yml --profile tools build h3-client
#
# It is never started by `docker compose up -d` (tools profile); the
# test script runs it as a one-shot container against the published
# UDP port.
FROM python:3.12-slim

RUN pip install --no-cache-dir aioquic

COPY h3-client.py /app/h3-client.py

ENTRYPOINT ["python3", "/app/h3-client.py"]
