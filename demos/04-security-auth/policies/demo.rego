# Demo Rego policy for the OPA authorization demo (test-20).
#
# Rego v1 syntax (OPA 1.x). The gateway's target OPA integration
# (guide/opa-authz.md) POSTs the request context as `input`:
#
#   {
#     "input": {
#       "method": "GET",
#       "path": "/v1/opa/test",
#       "host": "localhost",
#       "consumer": "mobile-app",
#       "headers": {"x-api-key": "..."}
#     }
#   }
#
# and honors the boolean at /v1/data/demo/allow. Test the decisions
# directly:
#
#   curl -s -X POST localhost:8181/v1/data/demo/allow \
#     -d '{"input": {"method": "GET", "path": "/v1/opa/test"}}'
#
# Policy: allow the versioned API surface (/v1*), deny everything
# else, with a named-consumer bypass (opa-user is always allowed).
package demo

default allow := false

# Allow requests to the versioned API surface.
allow if {
	startswith(input.path, "/v1")
}

# The named consumer opa-user is always allowed.
allow if {
	input.consumer == "opa-user"
}
