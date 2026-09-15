# Terraform state and Kubernetes Gateway API

## dwara-cli tf

A Terraform-compatible state layer over the admin API. Not a Terraform
provider - it gives Terraform-shaped workflows (export/plan/apply) against
the live gateway, with state stored as a tfstate JSON file.

```sh
dwara-cli tf export --admin https://gw:2019 \
                    --out-state dwara.tfstate --out-hcl dwara.tf
dwara-cli tf plan   --admin https://gw:2019 --state dwara.tfstate
dwara-cli tf apply  --admin https://gw:2019 --state dwara.tfstate [--config desired.yaml]
dwara-cli tf apply-crud --admin https://gw:2019 --state dwara.tfstate
```

| Command | Behavior |
| --- | --- |
| `export` | Fetch config from the admin API; write tfstate JSON + HCL `.tf` (the state-import step) |
| `plan` | Diff local tfstate vs running gateway. Exit 0 = no drift, 1 = diff |
| `apply` | Push desired config via **full-document `PATCH /config`**. Desired = `--config` file or derived from tfstate |
| `apply-crud` | Per-entity CRUD (`POST/PUT/DELETE /routes`, `/services`, ...) for routes, services, upstreams, consumers, policies - **listeners excluded** (file/PATCH-managed) |

Resource types: `dwara_listener`, `dwara_route`, `dwara_service`,
`dwara_upstream`, `dwara_consumer`.

Operational notes:

- Pick **one source of truth** per environment. Full-doc PATCH (file or
  `tf apply`) and entity CRUD (admin console, `apply-crud`) race;
  reconciliation is `export` + `plan` + decide.
- Secrets in state: config echoes redact secrets; the tfstate derives from
  the same redacted surface - treat tfstate as semi-sensitive anyway, and
  keep real secrets in `${ENV}`/`${file:}` references resolved at gateway
  start, not in HCL.
- mTLS client-certificate flags for the CLI are a documented follow-up
  (`--ca`/`--client-cert`/`--client-key` reserved) - today, run `tf`
  against a dev-mode admin (`DWARA_ADMIN_DEV=1`, loopback) or front the
  admin endpoint with a TLS-terminating proxy for the CLI host.
- CI recipe: nightly `tf plan`; non-zero exit = drift alert.

## Kubernetes Gateway API translation

The translator (compiled into the OSS build) watches the API server and
reconciles into a Dwara config file that the gateway hot-reloads.

Supported: Gateway API v1 standard channel - `GatewayClass`, `Gateway`,
`HTTPRoute` (v1.5), plus legacy `Ingress`.

Deployment pattern (two containers, one pod):

```text
dwara-k8s-controller   watches Gateway/HTTPRoute/Ingress -> writes the
                       translated config to a shared volume file
dwara                  gateway with DWARA_K8S_OUTPUT_CONFIG watching that
                       file (file-watch hot reload picks up every reconcile)
```

Environment:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DWARA_K8S_CONTROLLER_NAME` | `shristilabs.com/dwara` | GatewayClass controllerRef to claim |
| `DWARA_K8S_INGRESS_CLASS` | `dwara` | Ingress class filter |
| `DWARA_K8S_OUTPUT_CONFIG` | `/etc/dwara/dwara.yaml` | Translated config path (shared volume) |
| `DWARA_K8S_NAMESPACE` | - | Restrict watching to one namespace |

RBAC needed: read on `gatewayclasses`, `gateways`, `httproutes`,
`ingresses`; write on the output config path (volume), not the API server -
translation is read-only against Kubernetes.

Conformance reporting:

```sh
dwara-cli k8s conformance-report   # emits Gateway API conformance YAML
```

Availability of the subcommand can depend on your CLI build - probe with
`dwara-cli k8s --help` before scripting around it.

## Choosing a management model

| Model | Use when |
| --- | --- |
| File + hot reload (gitops) | Config reviewed as YAML in git; reload via watch/SIGHUP |
| Admin API CRUD / console | Interactive ops, small edits, day-2 changes |
| `tf export/plan/apply` | Terraform habits, drift detection in CI |
| K8s translator | The gateway should obey Kubernetes objects as source of truth |

They compose across environments but should not overlap within one: two
writers to the same config race (full-doc PATCH vs CRUD vs file).
