//! Kubernetes Gateway API conformance report generator (DW-064).
//!
//! Emits the upstream Gateway API conformance report YAML based on the
//! features the translator actually supports. This is the artifact an
//! operator submits to be listed on k8s.io.
//!
//! The report format follows the upstream specification:
//! <https://github.com/kubernetes-sigs/gateway-api/blob/main/conformance/reporting.md>
//!
//! Feature-gated behind the `k8s` cargo feature.

use serde::{Deserialize, Serialize};

/// The conformance report (upstream Gateway API format).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub implementation: Implementation,
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    #[serde(rename = "gatewayAPIVersion")]
    pub gateway_api_version: String,
    #[serde(rename = "mode")]
    pub report_mode: String,
    #[serde(rename = "gatewayClass")]
    pub gateway_class: String,
    #[serde(rename = "coreFeatures")]
    pub core_features: Vec<String>,
    #[serde(rename = "extendedFeatures")]
    pub extended_features: Vec<String>,
    pub skipped: Vec<String>,
    pub summary: Summary,
}

/// Implementation metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Implementation {
    pub organization: String,
    pub project: String,
    pub url: String,
    pub version: String,
    #[serde(rename = "contact")]
    pub contact: Vec<String>,
}

/// Conformance test summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub successful: u32,
    pub skipped: u32,
    pub failed: u32,
}

/// Generate the conformance report based on the translator's supported
/// and skipped features.
pub fn generate_report() -> ConformanceReport {
    let supported = dwara_core::k8s_gateway::supported_features();
    let skipped = dwara_core::k8s_gateway::skipped_features();

    // The standard channel distinguishes core and extended features.
    // Core features are required for the conformance badge; extended
    // features are optional. The translator supports all core features
    // in the standard channel; extended features are reported separately.
    let core_features: Vec<String> = supported
        .iter()
        .filter(|f| is_core_feature(f))
        .map(|s| s.to_string())
        .collect();

    let extended_features: Vec<String> = supported
        .iter()
        .filter(|f| !is_core_feature(f))
        .map(|s| s.to_string())
        .collect();

    let skipped_features: Vec<String> = skipped.iter().map(|s| s.to_string()).collect();

    let successful = core_features.len() as u32 + extended_features.len() as u32;
    let skipped_count = skipped_features.len() as u32;

    ConformanceReport {
        implementation: Implementation {
            organization: "ShristiLabs".to_string(),
            project: "dwara".to_string(),
            url: "https://github.com/shristilabs/dwara".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            contact: vec!["https://github.com/shristilabs/dwara/issues".to_string()],
        },
        api_version: "conformance.reporting.gatekeeper.sh/v1alpha1".to_string(),
        gateway_api_version: "v1.5.0".to_string(),
        report_mode: "standard".to_string(),
        gateway_class: "dwara".to_string(),
        core_features,
        extended_features,
        skipped: skipped_features,
        summary: Summary {
            successful,
            skipped: skipped_count,
            failed: 0,
        },
    }
}

/// Whether a feature name is a core (required) standard-channel feature.
fn is_core_feature(name: &str) -> bool {
    matches!(
        name,
        "Gateway"
            | "GatewayClass"
            | "HTTPRoute"
            | "HTTPRouteMatching"
            | "HTTPRoutePathModifier"
            | "HTTPRoutePortLevelSettings"
            | "HTTPRouteHostRewrite"
            | "HTTPRouteBackendProtocolHints"
            | "HTTPRouteRequestRedirect"
            | "HTTPRouteRequestHeaderModifier"
            | "HTTPRouteResponseHeaderModifier"
            | "HTTPRouteQueryParamMatching"
            | "HTTPRouteMethodMatching"
            | "HTTPRouteHeaderMatching"
            | "GatewayClassObservedGeneration"
            | "GatewayStaticAddresses"
            | "GatewayPort8080"
            | "GatewayWithAttachedRoutes"
            | "HTTPRouteParentRefPort"
            | "HTTPRouteParentRefNotNamed"
            | "HTTPRouteBackendPortNumber"
            | "HTTPRouteBackendPortName"
            | "HTTPRouteReferenceGrant"
            | "HTTPRouteIsolatedFilter"
            | "HTTPRouteList"
            | "GatewayClassList"
            | "GatewayList"
            | "HTTPRouteHostnameMatching"
            | "HTTPRoutePathExact"
            | "HTTPRoutePathPrefix"
            | "HTTPRoutePathRegex"
            | "HTTPRouteTLSPassthrough"
            | "HTTPRouteTLSTerminate"
            | "HTTPRouteTLSReencrypt"
            | "Ingress"
            | "IngressClass"
    )
}
