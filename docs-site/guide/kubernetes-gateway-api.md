# Kubernetes Gateway API

dwara implements a Kubernetes Gateway API controller that reconciles
Gateway API v1 resources (Gateway, HTTPRoute, GatewayClass) and standard
Ingress resources into its config model. The controller watches the
Kubernetes API server, translates the watched resources into a dwara
config YAML, and publishes it to a file the gateway hot-reloads.

## Enabling

The Kubernetes Gateway API controller is feature-gated behind the `k8s`
cargo feature (default OFF):

```sh
cargo build --features k8s
```

## Deployment

Deploy the controller + gateway to a Kubernetes cluster:

```sh
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/gatewayclass.yaml
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/deployment.yaml
```

The deployment runs two containers in a pod:

- **controller**: the `dwara-k8s-controller` binary that watches K8s
  resources and writes the generated config to a shared volume.
- **gateway**: the `dwara` gateway binary that hot-reloads the generated
  config via file-watch (DW-054).

## Configuration

The controller reads configuration from environment variables (set via
the `dwara-controller-config` ConfigMap):

| Variable | Default | Purpose |
|---|---|---|
| `DWARA_K8S_CONTROLLER_NAME` | `shristilabs.com/dwara` | GatewayClass controller name |
| `DWARA_K8S_INGRESS_CLASS` | `dwara` | Ingress class to watch |
| `DWARA_K8S_OUTPUT_CONFIG` | `/etc/dwara/dwara.yaml` | Output config YAML path |
| `DWARA_K8S_NAMESPACE` | (empty = all) | Namespace to watch |

## Supported features

### Gateway API (standard channel v1.5)

- Protocols: HTTP, HTTPS, TLS
- TLS modes: Terminate, Passthrough, Reencrypt
- Path matches: Exact, PathPrefix, RegularExpression
- Header matches: Exact
- Query param matches: Exact
- Filters: RequestRedirect, RequestHeaderModifier,
  ResponseHeaderModifier, URLRewrite
- GatewayClass acceptance and status conditions
- Gateway status (Accepted, Programmed)
- HTTPRoute status (Accepted, ResolvedRefs)

### Ingress

- Path types: Prefix, Exact, ImplementationSpecific
- Host-based routing
- TLS (Terminate mode)
- defaultBackend
- IngressClass filtering

## Conformance

### Self-test suite

The conformance self-test suite validates the translator against
conformance-style test vectors. It is deterministic and requires no
cluster:

```sh
cargo test -p dwara-core --features k8s --test k8s_conformance
cargo test -p dwara-core --features k8s --test k8s_controller
```

### Conformance report

Generate the upstream Gateway API conformance report YAML:

```sh
dwara k8s conformance-report
```

### Running the upstream conformance suite

To earn the actual conformance badge, run the upstream Go conformance
suite against the deployed controller:

```sh
git clone https://github.com/kubernetes-sigs/gateway-api.git
cd gateway-api
go test ./conformance -ginkgo.focus="Core" \
  -gateway-class=dwara \
  -controller-name=shristilabs.com/dwara
```

Submit the resulting report to the Gateway API implementations page to
be listed on k8s.io.
