# gRPC demo upstream: the dwdemo.DemoService from protos/dwdemo.proto.
#
# The proto is compiled inside the image so no host toolchain is
# needed: grpcio-tools compiles it against the google.api annotations
# vendored by googleapis-common-protos. Reflection + the standard
# health service are enabled so `grpcurl -plaintext` works without
# local proto files.
FROM python:3.12-slim

RUN pip install --no-cache-dir \
      grpcio grpcio-tools grpcio-reflection grpcio-health-checking \
      googleapis-common-protos

WORKDIR /app
COPY protos/dwdemo.proto protos/
# The google.api annotations live inside site-packages, so the protoc
# include root is three dirnames up from annotations_pb2.py.
RUN PROTO_DIR=$(python -c 'import google.api.annotations_pb2 as m, os; print(os.path.dirname(os.path.dirname(os.path.dirname(m.__file__))))') && \
    python -m grpc_tools.protoc \
      -Iprotos -I"$PROTO_DIR" \
      --python_out=/app --grpc_python_out=/app \
      dwdemo.proto

COPY server.py /app/server.py
ENV PORT=8080
# 8080 plaintext (h2c prior knowledge); 8443 TLS + h2 ALPN when
# TLS_CERT_FILE/TLS_KEY_FILE are mounted (see server.py). The TLS
# listener is what the gateway's `protocol: http2` upstreams dial.
EXPOSE 8080 8443
CMD ["python3", "/app/server.py"]
