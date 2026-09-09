#!/usr/bin/env python3
"""gRPC demo upstream: dwdemo.DemoService.

Implements the RPCs from protos/dwdemo.proto with reflection and the
standard gRPC health service enabled, so grpcurl (and the gateway's
health probing) can talk to it without local proto files.
"""
import os
import sys
import time
from concurrent import futures

import grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

import dwdemo_pb2
import dwdemo_pb2_grpc

PORT = int(os.environ.get("PORT", "8080"))

# Optional second listener with TLS (for gateway `protocol: http2`
# upstreams, which dial TLS + ALPN h2 — plaintext h2c is not offered by
# the gateway). Backward compatible: when the cert/key files are absent
# the server serves plaintext only, exactly as before.
TLS_PORT = int(os.environ.get("TLS_PORT", "8443"))
TLS_CERT_FILE = os.environ.get("TLS_CERT_FILE", "/certs/server.crt")
TLS_KEY_FILE = os.environ.get("TLS_KEY_FILE", "/certs/server.key")


class DemoService(dwdemo_pb2_grpc.DemoServiceServicer):
    def SayHello(self, request, context):
        return dwdemo_pb2.HelloReply(greeting=f"hello, {request.name}!")

    def ToUpper(self, request, context):
        return dwdemo_pb2.UpperReply(text=request.text.upper())

    def Count(self, request, context):
        for i in range(int(request.to), 0, -1):
            yield dwdemo_pb2.CountReply(value=i)
            time.sleep(0.05)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    dwdemo_pb2_grpc.add_DemoServiceServicer_to_server(DemoService(), server)

    # Health service (serving) + server reflection for grpcurl.
    health_servicer = health.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    health_servicer.set(health_pb2.HealthCheckResponse.SERVING, "")
    reflection.enable_server_reflection(
        ("dwdemo.DemoService", health_pb2.DESCRIPTOR.services_by_name["Health"].full_name,
         reflection.SERVICE_NAME),
        server,
    )

    server.add_insecure_port(f"[::]:{PORT}")

    # Optional TLS listener (same servicers, same executor): added only
    # when both cert and key exist AND the port differs from the
    # plaintext port. A missing file logs and continues plaintext-only
    # so the image keeps working without a certs mount.
    if TLS_PORT != PORT and os.path.isfile(TLS_CERT_FILE) and os.path.isfile(TLS_KEY_FILE):
        with open(TLS_KEY_FILE, "rb") as f:
            private_key = f.read()
        with open(TLS_CERT_FILE, "rb") as f:
            certificate_chain = f.read()
        server_credentials = grpc.ssl_server_credentials(
            ((private_key, certificate_chain),)
        )
        bound = server.add_secure_port(f"[::]:{TLS_PORT}", server_credentials)
        if bound == 0:
            print(f"warning: failed to bind TLS port {TLS_PORT}", flush=True)
        else:
            print(
                f"dwdemo grpc server TLS listening on {TLS_PORT} "
                f"(cert={TLS_CERT_FILE})",
                flush=True,
            )
    else:
        print(
            "TLS listener not enabled (certs missing or TLS_PORT == PORT); "
            "plaintext only",
            flush=True,
        )

    server.start()
    print(f"dwdemo grpc server listening on {PORT}", flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    sys.exit(serve())
