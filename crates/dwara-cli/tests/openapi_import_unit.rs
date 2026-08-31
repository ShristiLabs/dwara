//! Unit tests for the OpenAPI import module (`dwara_cli::import`).
//!
//! These tests exercise the public API of the `import` module:
//! `import_openapi`, `is_json_spec`, and `ImportResult`. They parse
//! OpenAPI 3.x specs (YAML and JSON), generate Dwara config YAML, and
//! verify the generated config round-trips through `parse_gateway`.

use dwara_cli::import::{import_openapi, is_json_spec};
use dwara_core::config::{parse_gateway, PathMatchKind};

const PETSTORE_YAML: &str = r#"
openapi: 3.0.0
info:
  title: Petstore
  version: 1.0.0
paths:
  /pets:
    get:
      operationId: listPets
      summary: List all pets
      tags: [pets]
    post:
      operationId: createPet
      summary: Create a pet
      tags: [pets]
  /pets/{id}:
    get:
      operationId: showPetById
      summary: Info for a specific pet
      tags: [pets]
    delete:
      operationId: deletePet
      summary: Delete a pet
"#;

#[test]
fn import_yaml_petstore() {
    let result = import_openapi(PETSTORE_YAML, false).unwrap();
    // 2 unique paths -> 2 routes (methods combined per path).
    assert_eq!(result.route_count, 2);
    // Verify the generated YAML parses back.
    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes.len(), 2);
    assert_eq!(gateway.upstreams.len(), 1);
    assert_eq!(gateway.upstreams[0].name, "openapi-backend");
    assert_eq!(gateway.upstreams[0].endpoints.len(), 1);
    assert_eq!(gateway.upstreams[0].endpoints[0].port, 9000);
    assert_eq!(gateway.services.len(), 1);
    assert_eq!(
        gateway.services[0].upstream.as_deref(),
        Some("openapi-backend")
    );
}

#[test]
fn import_preserves_path_params() {
    let result = import_openapi(PETSTORE_YAML, false).unwrap();
    let gateway = parse_gateway(&result.yaml).unwrap();
    let pet_by_id = gateway
        .routes
        .iter()
        .find(|r| r.openapi.as_ref().map(|m| m.path.as_str()) == Some("/pets/{id}"))
        .expect("/pets/{id} route exists");
    assert_eq!(pet_by_id.r#match.path.value, "/pets/{id}");
    assert_eq!(pet_by_id.r#match.path.kind, PathMatchKind::Exact);
}

#[test]
fn import_json_spec() {
    let json = r#"{"openapi":"3.0.0","info":{"title":"Test","version":"1.0.0"},"paths":{"/hello":{"get":{"operationId":"hello"}}}}"#;
    let result = import_openapi(json, true).unwrap();
    assert_eq!(result.route_count, 1);
    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes[0].name, "hello");
}

#[test]
fn import_detects_json() {
    assert!(is_json_spec("  {\"openapi\": \"3.0\"}"));
    assert!(!is_json_spec("openapi: 3.0"));
    assert!(is_json_spec("\u{feff}{\"openapi\": \"3.0\"}"));
}

#[test]
fn import_fallback_name_without_operation_id() {
    let yaml = r#"
openapi: 3.0.0
info:
  title: Test
  version: 1.0.0
paths:
  /items:
    get: {}
"#;
    let result = import_openapi(yaml, false).unwrap();
    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes[0].name, "get-items");
}

#[test]
fn import_unique_names_on_collision() {
    let yaml = r#"
openapi: 3.0.0
info:
  title: Test
  version: 1.0.0
paths:
  /a:
    get:
      operationId: dup
  /b:
    get:
      operationId: dup
"#;
    let result = import_openapi(yaml, false).unwrap();
    let gateway = parse_gateway(&result.yaml).unwrap();
    let names: Vec<&str> = gateway.routes.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"dup"));
    assert!(names.contains(&"dup-2"));
}
