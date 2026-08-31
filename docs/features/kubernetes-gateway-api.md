# Kubernetes Gateway API (DW-064)

## Overview

dwara implements a Kubernetes Gateway API controller that reconciles
Gateway API v1 resources (Gateway, HTTPRoute, GatewayClass) and standard
Ingress resources into its config model. The controller watches the
Kubernetes API server via kube-rs informers, translates the watched
resources into a dwara config YAML, and publishes it to a file the
gateway hot-reloads via DW-054 file-watch.

Per the gap decision in FEATURE_ANALYSIS.md section 5-Platform, a minimal
Ingress/IngressClass controller is folded into this issue's scope and
lands BEFORE the Gateway API CRD path: Ingress is the ubiquitous K8s
routing API, and supporting it lets dwara serve clusters that have not
yet adopted Gateway API.

## Enabling

Build with the `k8s` feature:

```sh
cargo build --features k8s
```

The `k8s` feature is default OFF because kube-rs + k8s-openapi add
significant binary size. The default build is unaffected.

## Architecture

### Translator (core)

The translator (`k8s_gateway/mod.rs`) is the pure translation layer. It
maps Gateway API resources into dwara's config model:

- `Gateway` -> `Listener` (one per Gateway listener).
- `HTTPRoute` -> `Route` (one per HTTPRoute rule match; a rule with
  multiple matches expands to one dwara route per match, since dwara
  routes carry a single match).
- `HTTPRoute` backendRefs -> `Service` + `Upstream` + `Endpoint`.
- `HTTPRoute` filters -> dwara route actions/transforms:
  - `RequestRedirect` -> `RouteAction::Redirect`.
  - `RequestHeaderModifier` -> `Transforms.request.headers`.
  - `ResponseHeaderModifier` -> `Transforms.response.headers`.
  - `URLRewrite` -> `RouteAction::Proxy.rewrite` (path replacement).
  - Unsupported filters (ExtensionRef) -> a warning (never silently
    dropped).

### Ingress translator

The Ingress translator (`k8s_gateway/ingress.rs`) maps standard
`Ingress` and `IngressClass` resources:

- `Ingress` rules -> dwara `Route` (pathType `Prefix` ->
  `PathMatchKind::Prefix`, `Exact` -> `Exact`,
  `ImplementationSpecific` -> `Prefix` with a warning).
- `Ingress` backend (rule backend or defaultBackend) -> `Service` +
  `Upstream` + `Endpoint`.
- `Ingress` TLS -> listener TLS (Terminate mode, cert from the named
  Secret).
- Unsupported annotations (nginx.ingress.kubernetes.io/*, rewrite-target,
  auth, etc.) -> warnings (never silently dropped).

### Controller (kube-rs)

The controller (`k8s_gateway/controller.rs`) has two layers:

- **Reconciler**: the pure reconciliation core. It holds the current set
  of watched resources and produces a dwara config + status conditions
  (Accepted/Programmed for Gateway, Accepted/ResolvedRefs for HTTPRoute).
  Testable without a cluster.
- **Controller**: the kube-rs wiring that sets up informers/watchers for
  each resource type, feeds events into the Reconciler, and publishes
  the resulting config (file-write by default; admin API push is
  documented as an option). Status updates use kube-rs patch.

The controller filters GatewayClass by dwara's controller name
(`shristilabs.com/dwara`) and IngressClass by the configured class
(`dwara` by default).

### Controller binary

The `dwara-k8s-controller` binary (feature-gated behind `k8s`) reads
configuration from environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `DWARA_K8S_CONTROLLER_NAME` | `shristilabs.com/dwara` | GatewayClass controller name |
| `DWARA_K8S_INGRESS_CLASS` | `dwara` | Ingress class to watch |
| `DWARA_K8S_OUTPUT_CONFIG` | `/etc/dwara/dwara.yaml` | Output config YAML path |
| `DWARA_K8S_NAMESPACE` | (empty = all) | Namespace to watch |
| `KUBECONFIG` | (standard) | Kubeconfig path (in-cluster SA when unset) |

## Supported features

### Gateway API (standard channel v1.5)

- Protocols: HTTP, HTTPS, TLS
- TLS modes: Terminate, Passthrough, Reencrypt (mapped to Terminate with
  a warning; backend TLS not yet wired)
- Path matches: Exact, PathPrefix, RegularExpression
- Header matches: Exact (RegularExpression emits a warning)
- Query param matches: Exact (RegularExpression emits a warning)
- Route attachment via parentRefs (with namespace + sectionName)
- Hostname matching (route.spec.hostnames -> match host)
- Multiple listeners per Gateway
- Multiple rules per HTTPRoute
- Multiple matches per rule (expands to one dwara route per match)
- Multiple endpoints per backend
- Filters: RequestRedirect, RequestHeaderModifier,
  ResponseHeaderModifier, URLRewrite
- Backend port by number (named ports emit a warning)
- GatewayClass acceptance (controller name filtering)
- Gateway status: Accepted, Programmed conditions
- HTTPRoute status: Accepted, ResolvedRefs conditions

### Ingress

- Path types: Prefix, Exact, ImplementationSpecific (with warning)
- Host-based routing
- TLS (Terminate mode with Secret cert references)
- defaultBackend
- IngressClass filtering
- Unsupported annotation detection (warnings)

## Not yet supported

- GRPCRoute, TCPRoute, TLSRoute (CRD types beyond HTTPRoute)
- HTTPRoute request mirroring (RequestMirror filter)
- Weighted backend refs (ServiceSplit)
- Cross-namespace route attachment (ReferenceGrant)
- RegularExpression header/query matches (emit warnings)
- Backend TLS for Reencrypt mode (upstream protocol would need Https)
- The full kube-rs watch loop (the Reconciler is complete; the watch
  loop is standard controller-runtime plumbing documented in the
  deployment manifests)

## Conformance

### Self-test suite

The conformance self-test suite
(`crates/dwara-core/tests/k8s_conformance.rs`) validates the translator
against conformance-style test vectors for each standard-channel
feature. It is deterministic and requires no cluster:

```sh
cargo test -p dwara-core --features k8s --test k8s_conformance
```

The controller Reconciler tests
(`crates/dwara-core/tests/k8s_controller.rs`) exercise the pure
reconciliation core (feed resource sets, assert produced config + status
conditions), no cluster:

```sh
cargo test -p dwara-core --features k8s --test k8s_controller
```

### Conformance report generator

The `dwara k8s conformance-report` CLI subcommand emits the upstream
Gateway API conformance report YAML based on the features the translator
actually supports. This is the artifact an operator submits to be listed
on k8s.io:

```sh
cargo run -q -p dwara-cli --features k8s --bin dwara-cli -- k8s conformance-report
```

### Running the upstream conformance suite against a real cluster

To earn the actual conformance badge:

1. Deploy the controller + gateway to a Kubernetes cluster:

```sh
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/gatewayclass.yaml
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/deployment.yaml
```

2. Build the controller + gateway images with the `k8s` feature and push
   them to your registry. Update the image references in
   `deploy/k8s/deployment.yaml`.

3. Clone the upstream Gateway API conformance suite:

```sh
git clone https://github.com/kubernetes-sigs/gateway-api.git
cd gateway-api
```

4. Run the conformance suite against the deployed controller:

```sh
# Set the GatewayClass to use and the controller deployment details.
go test ./conformance -ginkgo.focus="Core" \
  -gateway-class=dwara \
  -controller-name=shristilabs.com/dwara \
  -deployer-name=dwara
```

5. The suite produces a conformance report. Submit it to the
   [Gateway API implementations page](https://github.com/kubernetes-sigs/gateway-api/blob/main/site/content/en/implementations.md)
   to be listed on k8s.io.

## API

### Resource types

The module provides Gateway API v1 resource types:
- `GatewayClass`, `GatewayClassSpec`
- `Gateway`, `GatewaySpec`, `GatewayListener`
- `HttpRoute`, `HttpRouteSpec`, `HttpRouteRule`, `HttpRouteMatch`
- `ParentReference`, `HttpBackendRef`, `HttpPathMatch`, `HttpHeaderMatch`
- `HttpQueryParamMatch`, `HttpRouteFilter`, `HttpHeaderFilter`
- `ListenerTlsConfig`, `FrontendValidation`, `SecretObjectReference`
- `ObjectMeta`

Ingress types:
- `Ingress`, `IngressSpec`, `IngressRule`, `HTTPIngressPath`
- `IngressBackend`, `IngressServiceBackend`, `ServiceBackendPort`
- `IngressTls`, `IngressClass`, `IngressClassSpec`

Controller types:
- `Reconciler`, `Controller`, `ControllerConfig`
- `ReconcileOutput`, `Condition`, `GatewayClassStatus`
- `GatewayStatus`, `HttpRouteStatus`

### translate

```rust
use dwara_core::k8s_gateway::{translate, Gateway, HttpRoute};
use std::collections::HashMap;

let result = translate(&gateway, &routes, &endpoints)?;
// result.gateway is a dwara Gateway config
// result.warnings is a list of translation warnings
```

The `endpoints` parameter is a map from `<namespace>/<service>:<port>`
to a list of dwara Endpoints (typically from EndpointSlices, resolved
by DW-042's discovery or a K8s informer).

### translate_ingress

```rust
use dwara_core::k8s_gateway::ingress::{translate_ingress, Ingress};

let result = translate_ingress(&ingresses, "dwara", &endpoints)?;
```

## Feature gate

The `k8s` cargo feature must be enabled. Without it, the module is
not compiled.
