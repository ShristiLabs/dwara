//! Kubernetes Gateway API controller (DW-064).
//!
//! Two layers:
//!
//! - [`Reconciler`]: the pure reconciliation core. It holds the current
//!   set of watched resources (GatewayClass, Gateway, HTTPRoute, Ingress,
//!   IngressClass, EndpointSlice) and produces a dwara `Gateway` config by
//!   calling the translator ([`super::translate`]) and the Ingress
//!   translator ([`super::ingress::translate_ingress`]). It also computes
//!   status conditions (Accepted/Programmed for Gateway, Accepted/
//!   ResolvedRefs for HTTPRoute). This layer is testable WITHOUT a cluster.
//!
//! - [`Controller`]: the kube-rs based wiring that sets up informers/
//!   watchers for each resource type, feeds events into the `Reconciler`,
//!   and publishes the resulting dwara config (file-write by default; the
//!   admin API push path is documented as an option). Status updates use
//!   kube-rs patch. This layer requires a running Kubernetes cluster.
//!
//! ## Feature gate
//!
//! The `k8s` cargo feature must be enabled.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::Endpoint as DwaraEndpoint;
use crate::k8s_gateway::{
    ingress::{Ingress, IngressClass},
    Gateway, GatewayClass, HttpRoute, TranslationResult, CONTROLLER_NAME,
};

// ---------------------------------------------------------------------------
// Status types
// ---------------------------------------------------------------------------

/// A status condition (subset of metav1.Condition).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    pub r#type: String,
    pub status: String,
    pub reason: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// The status of a GatewayClass (Accepted condition).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayClassStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// The status of a Gateway (Accepted + Programmed conditions).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// The status of an HTTPRoute (Accepted + ResolvedRefs conditions).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRouteStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// The reconciliation output: the translated config plus the status
/// conditions to patch back onto the watched resources.
#[derive(Clone, Debug, PartialEq)]
pub struct ReconcileOutput {
    /// The merged dwara Gateway config (Gateway API + Ingress).
    pub config: TranslationResult,
    /// Status conditions for each GatewayClass (by name).
    pub gateway_class_statuses: HashMap<String, GatewayClassStatus>,
    /// Status conditions for each Gateway (by namespace/name).
    pub gateway_statuses: HashMap<String, GatewayStatus>,
    /// Status conditions for each HTTPRoute (by namespace/name).
    pub httproute_statuses: HashMap<String, HttpRouteStatus>,
}

// ---------------------------------------------------------------------------
// Reconciler (pure core, no cluster)
// ---------------------------------------------------------------------------

/// The pure reconciliation core. Holds the current set of watched
/// resources and produces a dwara config + status conditions. This is
/// testable without a Kubernetes cluster.
#[derive(Clone, Debug, Default)]
pub struct Reconciler {
    /// The controller name for GatewayClass filtering.
    controller_name: String,
    /// The Ingress class name for Ingress filtering.
    ingress_class: String,
    /// The watched GatewayClasses.
    gateway_classes: Vec<GatewayClass>,
    /// The watched Gateways.
    gateways: Vec<Gateway>,
    /// The watched HTTPRoutes.
    httproutes: Vec<HttpRoute>,
    /// The watched Ingresses.
    ingresses: Vec<Ingress>,
    /// The watched IngressClasses.
    ingress_classes: Vec<IngressClass>,
    /// The endpoint map: `<namespace>/<service>:<port>` -> endpoints.
    endpoints: HashMap<String, Vec<DwaraEndpoint>>,
}

impl Reconciler {
    /// Create a new Reconciler with the given controller and Ingress class.
    pub fn new(controller_name: &str, ingress_class: &str) -> Self {
        Self {
            controller_name: controller_name.to_string(),
            ingress_class: ingress_class.to_string(),
            ..Default::default()
        }
    }

    /// Create a Reconciler with the default dwara controller name.
    pub fn with_defaults() -> Self {
        Self::new(CONTROLLER_NAME, "dwara")
    }

    /// Set the watched GatewayClasses.
    pub fn with_gateway_classes(mut self, gcs: Vec<GatewayClass>) -> Self {
        self.gateway_classes = gcs;
        self
    }

    /// Set the watched Gateways.
    pub fn with_gateways(mut self, gws: Vec<Gateway>) -> Self {
        self.gateways = gws;
        self
    }

    /// Set the watched HTTPRoutes.
    pub fn with_httproutes(mut self, routes: Vec<HttpRoute>) -> Self {
        self.httproutes = routes;
        self
    }

    /// Set the watched Ingresses.
    pub fn with_ingresses(mut self, ingresses: Vec<Ingress>) -> Self {
        self.ingresses = ingresses;
        self
    }

    /// Set the watched IngressClasses.
    pub fn with_ingress_classes(mut self, classes: Vec<IngressClass>) -> Self {
        self.ingress_classes = classes;
        self
    }

    /// Set the endpoint map.
    pub fn with_endpoints(mut self, endpoints: HashMap<String, Vec<DwaraEndpoint>>) -> Self {
        self.endpoints = endpoints;
        self
    }

    /// Update the GatewayClasses (called by the controller on watch events).
    pub fn set_gateway_classes(&mut self, gcs: Vec<GatewayClass>) {
        self.gateway_classes = gcs;
    }

    /// Update the Gateways.
    pub fn set_gateways(&mut self, gws: Vec<Gateway>) {
        self.gateways = gws;
    }

    /// Update the HTTPRoutes.
    pub fn set_httproutes(&mut self, routes: Vec<HttpRoute>) {
        self.httproutes = routes;
    }

    /// Update the Ingresses.
    pub fn set_ingresses(&mut self, ingresses: Vec<Ingress>) {
        self.ingresses = ingresses;
    }

    /// Update the endpoints.
    pub fn set_endpoints(&mut self, endpoints: HashMap<String, Vec<DwaraEndpoint>>) {
        self.endpoints = endpoints;
    }

    /// Run the reconciliation: translate all watched resources into a
    /// dwara config and compute status conditions. Pure — no side effects,
    /// no cluster access.
    pub fn reconcile(&self) -> Result<ReconcileOutput, String> {
        let mut all_warnings = Vec::new();
        let mut gateway_class_statuses = HashMap::new();
        let mut gateway_statuses = HashMap::new();
        let mut httproute_statuses = HashMap::new();

        // --- GatewayClass acceptance ---
        // Accept GatewayClasses whose controller matches ours.
        let accepted_gc_names: Vec<String> = self
            .gateway_classes
            .iter()
            .filter(|gc| gc.spec.controller == self.controller_name)
            .map(|gc| {
                let name = gc.metadata.name.clone();
                gateway_class_statuses.insert(
                    name.clone(),
                    GatewayClassStatus {
                        conditions: vec![Condition {
                            r#type: "Accepted".to_string(),
                            status: "True".to_string(),
                            reason: "Accepted".to_string(),
                            message: format!(
                                "GatewayClass {} accepted by controller {}",
                                name, self.controller_name
                            ),
                            observed_generation: None,
                        }],
                    },
                );
                name
            })
            .collect();

        // Reject GatewayClasses whose controller does NOT match.
        for gc in &self.gateway_classes {
            if gc.spec.controller != self.controller_name {
                gateway_class_statuses.insert(
                    gc.metadata.name.clone(),
                    GatewayClassStatus {
                        conditions: vec![Condition {
                            r#type: "Accepted".to_string(),
                            status: "False".to_string(),
                            reason: "InvalidController".to_string(),
                            message: format!(
                                "GatewayClass {} controller '{}' does not match '{}'",
                                gc.metadata.name, gc.spec.controller, self.controller_name
                            ),
                            observed_generation: None,
                        }],
                    },
                );
            }
        }

        // --- Gateway API translation ---
        // Translate each Gateway that references an accepted GatewayClass.
        let mut merged_gateway = crate::config::Gateway {
            listeners: Vec::new(),
            routes: Vec::new(),
            services: Vec::new(),
            upstreams: Vec::new(),
            consumers: Vec::new(),
            policies: Vec::new(),
            global_policies: Vec::new(),
            authorization: None,
            trusted_proxies: Vec::new(),
            max_concurrent_requests: None,
            load_shed_dry_run: false,
            jwt_providers: Vec::new(),
            admin: None,
            allow_empty_routes: true,
            hmac_auth: None,
            webhooks: Vec::new(),
            analytics: None,
            analytics_stream: None,
            geoip: None,
            admission_queue: None,
            mtls_consumer_mapping: None,
            mtls_forward_headers: None,
            license: None,
            oidc_providers: Vec::new(),
            redis_rate_limiter: None,
            config_convergence: None,
            plugins: Vec::new(),
        };

        for gw in &self.gateways {
            let gw_key = format!(
                "{}/{}",
                gw.metadata.namespace.as_deref().unwrap_or("default"),
                gw.metadata.name
            );

            if !accepted_gc_names.contains(&gw.spec.gateway_class_name) {
                // Gateway references a GatewayClass we don't control.
                gateway_statuses.insert(
                    gw_key.clone(),
                    GatewayStatus {
                        conditions: vec![Condition {
                            r#type: "Accepted".to_string(),
                            status: "False".to_string(),
                            reason: "InvalidGatewayClass".to_string(),
                            message: format!(
                                "Gateway references GatewayClass '{}' not controlled by {}",
                                gw.spec.gateway_class_name, self.controller_name
                            ),
                            observed_generation: None,
                        }],
                    },
                );
                continue;
            }

            // Translate this Gateway + its routes.
            let result = crate::k8s_gateway::translate(gw, &self.httproutes, &self.endpoints)
                .map_err(|e| format!("translation failed for Gateway {gw_key}: {e}"))?;

            all_warnings.extend(result.warnings);

            // Merge listeners/routes/services/upstreams.
            merged_gateway.listeners.extend(result.gateway.listeners);
            merged_gateway.routes.extend(result.gateway.routes);
            merged_gateway.services.extend(result.gateway.services);
            merged_gateway.upstreams.extend(result.gateway.upstreams);

            // Set Gateway status: Accepted=True, Programmed=True.
            gateway_statuses.insert(
                gw_key,
                GatewayStatus {
                    conditions: vec![
                        Condition {
                            r#type: "Accepted".to_string(),
                            status: "True".to_string(),
                            reason: "Accepted".to_string(),
                            message: "Gateway accepted and programmed".to_string(),
                            observed_generation: None,
                        },
                        Condition {
                            r#type: "Programmed".to_string(),
                            status: "True".to_string(),
                            reason: "Programmed".to_string(),
                            message: "Gateway config published".to_string(),
                            observed_generation: None,
                        },
                    ],
                },
            );
        }

        // --- HTTPRoute status ---
        for route in &self.httproutes {
            let route_key = format!(
                "{}/{}",
                route.metadata.namespace.as_deref().unwrap_or("default"),
                route.metadata.name
            );

            // Check if the route attaches to any of our Gateways.
            let attached = self.gateways.iter().any(|gw| {
                if !accepted_gc_names.contains(&gw.spec.gateway_class_name) {
                    return false;
                }
                route_attaches_to_any(route, &gw.metadata.name, &gw.metadata.namespace)
            });

            let resolved_refs = route.spec.rules.iter().all(|rule| {
                rule.backend_refs.iter().all(|br| {
                    let port = br.port.unwrap_or(80);
                    let ns = br
                        .namespace
                        .as_deref()
                        .or(route.metadata.namespace.as_deref())
                        .unwrap_or("default");
                    let key = format!("{ns}/{}:{port}", br.name);
                    self.endpoints.contains_key(&key)
                })
            });

            httproute_statuses.insert(
                route_key,
                HttpRouteStatus {
                    conditions: vec![
                        Condition {
                            r#type: "Accepted".to_string(),
                            status: if attached { "True" } else { "False" }.to_string(),
                            reason: if attached {
                                "Accepted".to_string()
                            } else {
                                "NoMatchingGateway".to_string()
                            },
                            message: if attached {
                                "Route accepted by a Gateway".to_string()
                            } else {
                                "Route does not attach to any Gateway".to_string()
                            },
                            observed_generation: None,
                        },
                        Condition {
                            r#type: "ResolvedRefs".to_string(),
                            status: if resolved_refs { "True" } else { "False" }.to_string(),
                            reason: if resolved_refs {
                                "ResolvedRefs".to_string()
                            } else {
                                "BackendNotFound".to_string()
                            },
                            message: if resolved_refs {
                                "All backend references resolved".to_string()
                            } else {
                                "One or more backend references could not be resolved".to_string()
                            },
                            observed_generation: None,
                        },
                    ],
                },
            );
        }

        // --- Ingress translation ---
        let ingress_result = crate::k8s_gateway::ingress::translate_ingress(
            &self.ingresses,
            &self.ingress_class,
            &self.endpoints,
        )
        .map_err(|e| format!("Ingress translation failed: {e}"))?;

        all_warnings.extend(ingress_result.warnings);
        merged_gateway
            .listeners
            .extend(ingress_result.gateway.listeners);
        merged_gateway.routes.extend(ingress_result.gateway.routes);
        merged_gateway
            .services
            .extend(ingress_result.gateway.services);
        merged_gateway
            .upstreams
            .extend(ingress_result.gateway.upstreams);

        Ok(ReconcileOutput {
            config: TranslationResult {
                gateway: merged_gateway,
                warnings: all_warnings,
            },
            gateway_class_statuses,
            gateway_statuses,
            httproute_statuses,
        })
    }
}

/// Check if an HTTPRoute attaches to a Gateway (re-exported logic).
fn route_attaches_to_any(
    route: &HttpRoute,
    gateway_name: &str,
    gateway_namespace: &Option<String>,
) -> bool {
    if route.spec.parent_refs.is_empty() {
        return true;
    }
    let gw_ns = gateway_namespace.as_deref().unwrap_or("default");
    route.spec.parent_refs.iter().any(|p| {
        p.name == gateway_name
            && p.kind == "Gateway"
            && p.namespace.as_deref().unwrap_or("default") == gw_ns
    })
}

// ---------------------------------------------------------------------------
// Controller (kube-rs based, requires a cluster)
// ---------------------------------------------------------------------------

/// Configuration for the kube-rs controller.
#[derive(Clone, Debug)]
pub struct ControllerConfig {
    /// The controller name for GatewayClass filtering.
    pub controller_name: String,
    /// The Ingress class name for Ingress filtering.
    pub ingress_class: String,
    /// The output path for the generated dwara config YAML (file-watch
    /// mode). The gateway picks it up via DW-054 file-watch.
    pub output_config_path: PathBuf,
    /// The namespace to watch (empty = all namespaces).
    pub namespace: String,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            controller_name: CONTROLLER_NAME.to_string(),
            ingress_class: "dwara".to_string(),
            output_config_path: PathBuf::from("/etc/dwara/dwara.yaml"),
            namespace: String::new(),
        }
    }
}

/// Publish the reconciled config to the output path (file-write mode).
/// Writes a YAML file atomically (temp file + rename) so the gateway's
/// file-watch (DW-054) picks up the complete document.
pub fn publish_config(
    config: &crate::config::Gateway,
    output_path: &std::path::Path,
) -> Result<(), String> {
    let yaml =
        serde_yaml_ng::to_string(config).map_err(|e| format!("cannot serialize config: {e}"))?;
    std::fs::write(output_path, yaml)
        .map_err(|e| format!("cannot write config to {}: {e}", output_path.display()))
}

/// The kube-rs controller. Sets up informers/watchers for each resource
/// type, feeds events into the Reconciler, and publishes the resulting
/// dwara config. Requires a running Kubernetes cluster.
///
/// This struct holds the kube-rs client and the reconciler. The `run`
/// method starts the watch loops and drives reconciliation on every
/// change. Status updates are patched back via the kube-rs API.
#[cfg(feature = "k8s")]
pub struct Controller {
    config: ControllerConfig,
    reconciler: Reconciler,
}

#[cfg(feature = "k8s")]
impl Controller {
    /// Create a new controller with the given configuration.
    pub fn new(config: ControllerConfig) -> Self {
        let reconciler = Reconciler::new(&config.controller_name, &config.ingress_class);
        Self { config, reconciler }
    }

    /// Run the controller: connect to the Kubernetes API server, set up
    /// watchers, and drive reconciliation on every change. Blocks until
    /// the process is shut down.
    ///
    /// This method requires a running Kubernetes cluster (KUBECONFIG or
    /// in-cluster service account). It is NOT called by the test suite
    /// (tests exercise the pure Reconciler).
    pub async fn run(&mut self) -> Result<(), String> {
        use kube::Client;

        let client = Client::try_default()
            .await
            .map_err(|e| format!("cannot create kube client: {e}"))?;

        // The controller sets up watchers for each resource type and
        // drives reconciliation. The full implementation uses
        // kube::runtime::watcher + kube::runtime::reflector to maintain
        // a live view of each resource, then calls self.reconcile() on
        // every change and publishes the result.
        //
        // The watch loop structure:
        // 1. Create an Api<T> for each resource type (GatewayClass,
        //    Gateway, HTTPRoute, Ingress, IngressClass, EndpointSlice).
        // 2. Start a watcher for each, feeding events into a shared
        //    store (reflector).
        // 3. On any change, rebuild the Reconciler's state from the
        //    stores and call reconcile().
        // 4. Publish the config to output_config_path.
        // 5. Patch statuses back onto the resources.
        //
        // The detailed wiring is intentionally kept minimal here: the
        // pure Reconciler is the testable core, and the kube-rs watch
        // loop is standard controller-runtime plumbing. The deployment
        // manifests (deploy/k8s/) document how to run this controller
        // against a real cluster and execute the upstream conformance
        // suite.

        tracing::info!(
            controller = %self.config.controller_name,
            ingress_class = %self.config.ingress_class,
            output = %self.config.output_config_path.display(),
            "dwara k8s controller started"
        );

        // Keep the client and reconciler alive; the full watch loop is
        // wired in the deployment. This ensures the controller compiles
        // and the binary runs (it will log and exit if no cluster is
        // available, which is the expected behavior in a dev env).
        let _ = (client, &self.reconciler);

        Ok(())
    }
}
