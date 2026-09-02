//! Integration tests for the service mesh mode scaffold (DW-107).
//!
//! Covers sidecar config parsing, SPIFFE config parsing, SpiffeIdentity
//! parsing and validation, snapshot validation (valid config, missing
//! trust_domain, same inbound/outbound port), the feature-gate behavior
//! (the block is accepted but inert without the `mesh` cargo feature),
//! and the ent-gate behavior (warn when mesh is configured without the
//! `ent` feature). The sidecar redirect bootstrap and the SPIRE
//! Workload API calls are STUBBED pending production hardening -- the
//! scaffold tests assert the documented no-op contract.

use dwara_core::config::mesh::{MeshConfig, MeshMode, MeshSidecarConfig, MeshSpiffeConfig};
use dwara_core::config::parse_gateway;
use dwara_core::snapshot::validate;

/// A minimal gateway YAML with the `mesh` block injected. The gateway
/// carries `allow_empty_routes: true` so the zero-route guard (#129)
/// does not fire (these configs are mesh-only fixtures).
fn mesh_gateway_yaml(mesh_block: &str) -> String {
    format!(
        "allow_empty_routes: true\n\
         upstreams:\n\
         \x20 - name: up\n\
         \x20   endpoints:\n\
         \x20     - address: 127.0.0.1\n\
         \x20       port: 9000\n\
         {mesh_block}"
    )
}

// --- Sidecar config parsing ----------------------------------------------

#[test]
fn sidecar_config_parses_with_defaults() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 sidecar:\n\
         \x20   inbound_port: 15006\n\
         \x20   outbound_port: 15001\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let mesh = gateway.mesh.as_ref().expect("mesh block present");
    assert!(mesh.enabled);
    assert_eq!(mesh.mode, MeshMode::Sidecar);
    let sidecar = mesh.sidecar.as_ref().expect("sidecar present");
    assert_eq!(sidecar.inbound_port, 15006);
    assert_eq!(sidecar.outbound_port, 15001);
    assert_eq!(sidecar.redirect_mode, "iptables");
    let spiffe = mesh.spiffe.as_ref().expect("spiffe present");
    assert_eq!(spiffe.trust_domain, "example.org");
    assert_eq!(
        spiffe.workload_api_socket,
        "/tmp/spire-agent/public/api.sock"
    );
    // Default refresh interval is 300s.
    assert_eq!(spiffe.svid_refresh_interval_secs, 300);
}

#[test]
fn sidecar_config_parses_tproxy_redirect_mode() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 sidecar:\n\
         \x20   inbound_port: 15006\n\
         \x20   outbound_port: 15001\n\
         \x20   redirect_mode: tproxy\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let mesh = gateway.mesh.as_ref().expect("mesh block present");
    let sidecar = mesh.sidecar.as_ref().expect("sidecar present");
    assert_eq!(sidecar.redirect_mode, "tproxy");
}

#[test]
fn sidecar_config_uses_default_ports_when_omitted() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 sidecar: {}\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let mesh = gateway.mesh.as_ref().expect("mesh block present");
    let sidecar = mesh.sidecar.as_ref().expect("sidecar present");
    // Defaults: 15006 / 15001 / iptables.
    assert_eq!(sidecar.inbound_port, 15006);
    assert_eq!(sidecar.outbound_port, 15001);
    assert_eq!(sidecar.redirect_mode, "iptables");
}

#[test]
fn mesh_config_disabled_by_default() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 mode: sidecar\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let mesh = gateway.mesh.as_ref().expect("mesh block present");
    assert!(!mesh.enabled);
}

#[test]
fn mesh_config_rejects_unknown_mode() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: node\n",
    );
    let err = parse_gateway(&yaml).unwrap_err();
    // serde rejects the unknown enum variant.
    assert!(err.message.contains("unknown variant") || err.message.contains("node"));
}

#[test]
fn mesh_config_rejects_unknown_field() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 bogus: true\n",
    );
    let err = parse_gateway(&yaml).unwrap_err();
    assert!(err.message.contains("unknown field") || err.message.contains("bogus"));
}

// --- SPIFFE config parsing -----------------------------------------------

#[test]
fn spiffe_config_parses_custom_refresh_interval() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 spiffe:\n\
         \x20   trust_domain: prod.example.org\n\
         \x20   workload_api_socket: /run/spire/agent.sock\n\
         \x20   svid_refresh_interval_secs: 600\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let mesh = gateway.mesh.as_ref().expect("mesh block present");
    let spiffe = mesh.spiffe.as_ref().expect("spiffe present");
    assert_eq!(spiffe.trust_domain, "prod.example.org");
    assert_eq!(spiffe.workload_api_socket, "/run/spire/agent.sock");
    assert_eq!(spiffe.svid_refresh_interval_secs, 600);
}

// --- SpiffeIdentity parsing and validation -------------------------------

#[cfg(feature = "mesh")]
#[test]
fn spiffe_identity_parses_valid_uri() {
    use dwara_core::mesh::SpiffeIdentity;
    let id = SpiffeIdentity::parse("spiffe://example.org/ns/default/sa/my-svc")
        .expect("valid URI parses");
    assert_eq!(id.trust_domain, "example.org");
    assert_eq!(id.path, "/ns/default/sa/my-svc");
    assert!(id.is_valid());
    assert_eq!(id.to_uri(), "spiffe://example.org/ns/default/sa/my-svc");
}

#[cfg(feature = "mesh")]
#[test]
fn spiffe_identity_parse_rejects_wrong_scheme() {
    use dwara_core::mesh::SpiffeIdentity;
    assert!(SpiffeIdentity::parse("https://example.org/x").is_none());
    assert!(SpiffeIdentity::parse("spiffe://").is_none());
}

#[cfg(feature = "mesh")]
#[test]
fn spiffe_identity_parse_rejects_empty_trust_domain() {
    use dwara_core::mesh::SpiffeIdentity;
    // "spiffe:///path" splits into trust_domain="" -> rejected.
    assert!(SpiffeIdentity::parse("spiffe:///path").is_none());
}

#[cfg(feature = "mesh")]
#[test]
fn spiffe_identity_new_normalizes_path() {
    use dwara_core::mesh::SpiffeIdentity;
    let id = SpiffeIdentity::new("example.org", "ns/default/sa/x");
    assert_eq!(id.path, "/ns/default/sa/x");
    assert!(id.is_valid());
    // A path that already starts with '/' is left as-is.
    let id2 = SpiffeIdentity::new("example.org", "/ns/default/sa/y");
    assert_eq!(id2.path, "/ns/default/sa/y");
}

#[cfg(feature = "mesh")]
#[test]
fn spiffe_identity_display_round_trips() {
    use dwara_core::mesh::SpiffeIdentity;
    let id = SpiffeIdentity::new("example.org", "/sa/svc");
    let s = id.to_string();
    assert_eq!(s, "spiffe://example.org/sa/svc");
    let parsed = SpiffeIdentity::parse(&s).expect("round-trips");
    assert_eq!(parsed, id);
}

// --- Snapshot validation -------------------------------------------------

#[test]
fn valid_mesh_config_passes_validation() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 sidecar:\n\
         \x20   inbound_port: 15006\n\
         \x20   outbound_port: 15001\n\
         \x20   redirect_mode: iptables\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n\
         \x20   svid_refresh_interval_secs: 300\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    // Filter to mesh-field issues only (the fixture may produce other
    // warnings unrelated to the mesh block).
    let mesh_issues: Vec<_> = issues
        .iter()
        .filter(|i| i.field.starts_with("mesh"))
        .collect();
    // The feature-gate and ent-gate warnings are expected when those
    // features are off; the field-level checks (ports, trust_domain,
    // socket, refresh interval) must all pass for a valid config.
    let field_issues: Vec<_> = mesh_issues
        .iter()
        .filter(|i| i.field.starts_with("mesh.sidecar.") || i.field.starts_with("mesh.spiffe."))
        .copied()
        .collect();
    assert!(
        field_issues.is_empty(),
        "expected no mesh field-level validation issues for a valid config, got: {field_issues:?}"
    );
}

#[test]
fn validation_rejects_missing_trust_domain() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 spiffe:\n\
         \x20   trust_domain: ''\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "mesh.spiffe.trust_domain" && i.message.contains("non-empty")),
        "expected missing trust_domain issue, got: {issues:?}"
    );
}

#[test]
fn validation_rejects_missing_workload_api_socket() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: ''\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues.iter().any(
            |i| i.field == "mesh.spiffe.workload_api_socket" && i.message.contains("non-empty")
        ),
        "expected missing workload_api_socket issue, got: {issues:?}"
    );
}

#[test]
fn validation_rejects_zero_svid_refresh_interval() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n\
         \x20   svid_refresh_interval_secs: 0\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "mesh.spiffe.svid_refresh_interval_secs"
                && i.message.contains("> 0")),
        "expected zero refresh interval issue, got: {issues:?}"
    );
}

#[test]
fn validation_rejects_same_inbound_outbound_port() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 sidecar:\n\
         \x20   inbound_port: 15006\n\
         \x20   outbound_port: 15006\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "mesh.sidecar.inbound_port"
                && i.message.contains("must be different")),
        "expected same-port issue, got: {issues:?}"
    );
}

#[test]
fn validation_rejects_zero_inbound_port() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 sidecar:\n\
         \x20   inbound_port: 0\n\
         \x20   outbound_port: 15001\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "mesh.sidecar.inbound_port" && i.message.contains("> 0")),
        "expected zero inbound_port issue, got: {issues:?}"
    );
}

#[test]
fn validation_rejects_unknown_redirect_mode() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 sidecar:\n\
         \x20   inbound_port: 15006\n\
         \x20   outbound_port: 15001\n\
         \x20   redirect_mode: ebpf\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "mesh.sidecar.redirect_mode" && i.message.contains("ebpf")),
        "expected unknown redirect_mode issue, got: {issues:?}"
    );
}

#[test]
fn validation_skips_field_checks_when_disabled() {
    // A disabled mesh block with invalid fields should NOT produce
    // field-level issues (validation returns early when !enabled).
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: false\n\
         \x20 mode: sidecar\n\
         \x20 sidecar:\n\
         \x20   inbound_port: 15006\n\
         \x20   outbound_port: 15006\n\
         \x20 spiffe:\n\
         \x20   trust_domain: ''\n\
         \x20   workload_api_socket: ''\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    let field_issues: Vec<_> = issues
        .iter()
        .filter(|i| i.field.starts_with("mesh.sidecar.") || i.field.starts_with("mesh.spiffe."))
        .collect();
    assert!(
        field_issues.is_empty(),
        "expected no mesh field-level issues for a disabled block, got: {field_issues:?}"
    );
}

// --- Feature gate: without mesh feature, config is accepted but inert ---

#[test]
fn mesh_block_accepted_without_mesh_feature() {
    // The config schema is always present, so the block parses
    // regardless of the mesh cargo feature.
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    assert!(gateway.mesh.is_some());
}

#[cfg(not(feature = "mesh"))]
#[test]
fn validation_warns_mesh_inert_without_feature() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues.iter().any(|i| i.field == "mesh"
            && i.message.contains("inert")
            && i.message.contains("--features mesh")),
        "expected inert-without-feature warning, got: {issues:?}"
    );
}

#[cfg(feature = "mesh")]
#[test]
fn validation_does_not_warn_inert_with_feature() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 sidecar:\n\
         \x20   inbound_port: 15006\n\
         \x20   outbound_port: 15001\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        !issues
            .iter()
            .any(|i| i.field == "mesh" && i.message.contains("inert")),
        "expected no inert warning with the mesh feature on, got: {issues:?}"
    );
}

// --- Ent gate: without ent feature, warn --------------------------------

#[cfg(not(feature = "ent"))]
#[test]
fn validation_warns_mesh_without_ent_feature() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues.iter().any(|i| i.field == "mesh"
            && i.message.contains("ent")
            && i.message.contains("enterprise")),
        "expected ent-gate warning, got: {issues:?}"
    );
}

#[cfg(feature = "ent")]
#[test]
fn validation_does_not_warn_ent_with_feature() {
    let yaml = mesh_gateway_yaml(
        "mesh:\n\
         \x20 enabled: true\n\
         \x20 mode: sidecar\n\
         \x20 sidecar:\n\
         \x20   inbound_port: 15006\n\
         \x20   outbound_port: 15001\n\
         \x20 spiffe:\n\
         \x20   trust_domain: example.org\n\
         \x20   workload_api_socket: /tmp/spire-agent/public/api.sock\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        !issues
            .iter()
            .any(|i| i.field == "mesh" && i.message.contains("enterprise")),
        "expected no ent-gate warning with the ent feature on, got: {issues:?}"
    );
}

// --- Scaffold contract (mesh feature only) -------------------------------

#[cfg(feature = "mesh")]
#[test]
fn sidecar_controller_exposes_listeners() {
    use dwara_core::mesh::{SidecarConfig, SidecarController, SidecarMode, SidecarRedirectMode};
    let cfg = MeshSidecarConfig {
        inbound_port: 15006,
        outbound_port: 15001,
        redirect_mode: "tproxy".to_string(),
    };
    let resolved = SidecarConfig::from_config(&cfg);
    let controller = SidecarController::new(resolved);
    let (mode, port, redirect) = controller.inbound_listener();
    assert_eq!(mode, SidecarMode::Inbound);
    assert_eq!(port, 15006);
    assert_eq!(redirect, SidecarRedirectMode::Tproxy);
    let (mode, port, _) = controller.outbound_listener();
    assert_eq!(mode, SidecarMode::Outbound);
    assert_eq!(port, 15001);
    // install_redirects is a documented no-op (must not panic).
    controller.install_redirects();
}

#[cfg(feature = "mesh")]
#[test]
fn spiffe_client_fetch_svid_is_stubbed() {
    use dwara_core::mesh::{SpiffeClient, SpiffeConfig, SpiffeError};
    let cfg = MeshSpiffeConfig {
        trust_domain: "example.org".to_string(),
        workload_api_socket: "/tmp/spire-agent/public/api.sock".to_string(),
        svid_refresh_interval_secs: 300,
    };
    let resolved = SpiffeConfig::from_config(&cfg);
    let client = SpiffeClient::new(resolved);
    let err = client.fetch_svid().expect_err("stubbed fetch errors");
    assert_eq!(err, SpiffeError::WorkloadApiStubbed);
    // The trust bundle fetch is also stubbed.
    let err = client
        .fetch_trust_bundle()
        .expect_err("stubbed fetch errors");
    assert_eq!(err, SpiffeError::WorkloadApiStubbed);
    // The workload identity is built from the trust domain + path.
    let id = client.workload_identity("/ns/default/sa/svc");
    assert_eq!(id.trust_domain, "example.org");
    assert_eq!(id.path, "/ns/default/sa/svc");
}

#[cfg(feature = "mesh")]
#[test]
fn spiffe_svid_seconds_until_expiry_clamps() {
    use dwara_core::mesh::SpiffeSvid;
    let svid = SpiffeSvid {
        x509_cert: vec![vec![0u8; 10]],
        private_key: vec![0u8; 32],
        expires_at: 1000,
    };
    assert_eq!(svid.seconds_until_expiry(900), 100);
    assert_eq!(svid.seconds_until_expiry(1000), 0);
    assert_eq!(svid.seconds_until_expiry(2000), 0);
}

#[cfg(feature = "mesh")]
#[test]
fn spiffe_config_from_config_resolves_socket_path() {
    use dwara_core::mesh::SpiffeConfig;
    let cfg = MeshSpiffeConfig {
        trust_domain: "example.org".to_string(),
        workload_api_socket: "/run/spire/agent.sock".to_string(),
        svid_refresh_interval_secs: 120,
    };
    let resolved = SpiffeConfig::from_config(&cfg);
    assert_eq!(resolved.trust_domain, "example.org");
    assert_eq!(
        resolved.workload_api_socket.to_string_lossy(),
        "/run/spire/agent.sock"
    );
    assert_eq!(resolved.svid_refresh_interval.as_secs(), 120);
}

// --- MeshConfig direct construction (schema round-trip) ------------------

#[test]
fn mesh_config_round_trips_through_serde() {
    let cfg = MeshConfig {
        enabled: true,
        mode: MeshMode::Sidecar,
        sidecar: Some(MeshSidecarConfig {
            inbound_port: 15006,
            outbound_port: 15001,
            redirect_mode: "iptables".to_string(),
        }),
        spiffe: Some(MeshSpiffeConfig {
            trust_domain: "example.org".to_string(),
            workload_api_socket: "/tmp/spire-agent/public/api.sock".to_string(),
            svid_refresh_interval_secs: 300,
        }),
    };
    let s = serde_yaml_ng::to_string(&cfg).expect("serializes");
    let back: MeshConfig = serde_yaml_ng::from_str(&s).expect("deserializes");
    assert_eq!(cfg, back);
}

#[test]
fn mesh_config_rejects_unknown_field_serde() {
    let yaml = "enabled: true\nmode: sidecar\nbogus: 1\n";
    let err = serde_yaml_ng::from_str::<MeshConfig>(yaml);
    assert!(err.is_err());
}
