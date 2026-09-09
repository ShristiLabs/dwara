# dwara Helm chart

A Helm chart for deploying the Dwara Kubernetes Gateway API controller
and gateway data plane, plus the supporting Service, HPA, PDB,
NetworkPolicy, and ServiceMonitor objects.

## Install

```sh
helm install dwara deploy/helm/dwara --namespace dwara-system --create-namespace
```

## Values

Key values (see `values.yaml` for the full list):

| Key | Default | Description |
|---|---|---|
| `controller.image` | `ghcr.io/shristilabs/dwara-k8s-controller:latest` | Controller image |
| `gateway.image` | `ghcr.io/shristilabs/dwara:latest` | Gateway image |
| `gateway.ports.http` | `8080` | HTTP container port |
| `gateway.ports.https` | `8443` | HTTPS container port |
| `service.type` | `ClusterIP` | Service type |
| `hpa.enabled` | `true` | Enable HorizontalPodAutoscaler |
| `hpa.minReplicas` | `2` | Minimum replicas |
| `hpa.maxReplicas` | `10` | Maximum replicas |
| `pdb.enabled` | `true` | Enable PodDisruptionBudget |
| `networkPolicy.enabled` | `false` | Enable NetworkPolicy |
| `serviceMonitor.enabled` | `false` | Enable ServiceMonitor (needs Prometheus Operator) |
| `gatewayClass.enabled` | `true` | Create the GatewayClass |
| `rbac.enabled` | `true` | Create ServiceAccount + ClusterRole/Binding |

## Lint and render

```sh
helm lint deploy/helm/dwara
helm template dwara deploy/helm/dwara --namespace dwara-system
```

## TLS

Mount an existing TLS secret into the gateway container:

```yaml
gateway:
  tls:
    enabled: true
    secretName: dwara-tls
    mountPath: /etc/dwara/certs
```

## Production example

```sh
helm install dwara deploy/helm/dwara --namespace dwara-system \
  --set service.type=LoadBalancer \
  --set hpa.maxReplicas=20 \
  --set serviceMonitor.enabled=true \
  --set networkPolicy.enabled=true \
  --set gateway.image.tag=v0.1.0
```
