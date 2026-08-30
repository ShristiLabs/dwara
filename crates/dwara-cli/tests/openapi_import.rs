//! OpenAPI import integration tests (DW-047).
//!
//! Exercises the `dwara_cli::import` module: parsing OpenAPI 3.x specs
//! (YAML and JSON), generating Dwara config YAML, and verifying the
//! generated config round-trips through `parse_gateway` + validation.

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

const PETSTORE_JSON: &str = r#"{
  "openapi": "3.0.0",
  "info": { "title": "Petstore", "version": "1.0.0" },
  "paths": {
    "/pets": {
      "get": { "operationId": "listPets", "summary": "List all pets", "tags": ["pets"] },
      "post": { "operationId": "createPet", "summary": "Create a pet", "tags": ["pets"] }
    },
    "/pets/{id}": {
      "get": { "operationId": "showPetById", "summary": "Info for a specific pet", "tags": ["pets"] },
      "delete": { "operationId": "deletePet", "summary": "Delete a pet" }
    }
  }
}"#;

#[test]
fn import_yaml_generates_valid_config() {
    let result = import_openapi(PETSTORE_YAML, false).expect("YAML import succeeds");
    // 2 unique paths -> 2 routes (methods are combined per path).
    assert_eq!(result.route_count, 2);
    let gateway = parse_gateway(&result.yaml).expect("generated config parses");
    assert_eq!(gateway.routes.len(), 2);
    assert_eq!(gateway.services.len(), 1);
    assert_eq!(gateway.upstreams.len(), 1);
}

#[test]
fn import_json_generates_valid_config() {
    let result = import_openapi(PETSTORE_JSON, true).expect("JSON import succeeds");
    assert_eq!(result.route_count, 2);
    let gateway = parse_gateway(&result.yaml).expect("generated config parses");
    assert_eq!(gateway.routes.len(), 2);
}

#[test]
fn import_preserves_path_params() {
    let result = import_openapi(PETSTORE_YAML, false).unwrap();
    let gateway = parse_gateway(&result.yaml).unwrap();
    // /pets/{id} path -> showPetById is the first operation -> route name "showpetbyid".
    let pet_by_id = gateway
        .routes
        .iter()
        .find(|r| r.openapi.as_ref().map(|m| m.path.as_str()) == Some("/pets/{id}"))
        .expect("/pets/{id} route exists");
    assert_eq!(pet_by_id.r#match.path.value, "/pets/{id}");
    assert_eq!(pet_by_id.r#match.path.kind, PathMatchKind::Exact);
    // Both GET and DELETE methods are on this route.
    assert!(pet_by_id.r#match.methods.contains(&"GET".to_string()));
    assert!(pet_by_id.r#match.methods.contains(&"DELETE".to_string()));
}

#[test]
fn import_preserves_openapi_metadata() {
    let result = import_openapi(PETSTORE_YAML, false).unwrap();
    let gateway = parse_gateway(&result.yaml).unwrap();
    // /pets path -> listPets is the first operation -> route name "listpets".
    let list_pets = gateway
        .routes
        .iter()
        .find(|r| r.openapi.as_ref().map(|m| m.path.as_str()) == Some("/pets"))
        .expect("/pets route exists");
    let meta = list_pets.openapi.as_ref().expect("openapi metadata exists");
    assert_eq!(meta.operation_id.as_deref(), Some("listPets"));
    assert_eq!(meta.summary.as_deref(), Some("List all pets"));
    assert_eq!(meta.tags, vec!["pets"]);
    assert_eq!(meta.method, "GET");
    assert_eq!(meta.path, "/pets");
    // Both GET and POST methods are on this route.
    assert!(list_pets.r#match.methods.contains(&"GET".to_string()));
    assert!(list_pets.r#match.methods.contains(&"POST".to_string()));
}

#[test]
fn import_detects_json_by_content() {
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

#[test]
fn import_generated_config_validates() {
    let result = import_openapi(PETSTORE_YAML, false).unwrap();
    match dwara_cli::validate_config_text(&result.yaml) {
        dwara_cli::ValidateOutcome::Valid { routes } => assert_eq!(routes, 2),
        dwara_cli::ValidateOutcome::Invalid(issues) => {
            panic!("generated config should validate, got issues: {issues:?}");
        }
    }
}

#[test]
fn import_all_http_methods() {
    let yaml = r#"
openapi: 3.0.0
info:
  title: Test
  version: 1.0.0
paths:
  /resource:
    get: { operationId: rGet }
    post: { operationId: rPost }
    put: { operationId: rPut }
    delete: { operationId: rDelete }
    patch: { operationId: rPatch }
    options: { operationId: rOptions }
    head: { operationId: rHead }
"#;
    let result = import_openapi(yaml, false).unwrap();
    // 1 unique path -> 1 route with 7 methods.
    assert_eq!(result.route_count, 1);
    let gateway = parse_gateway(&result.yaml).unwrap();
    assert_eq!(gateway.routes.len(), 1);
    let methods = &gateway.routes[0].r#match.methods;
    assert!(methods.contains(&"GET".to_string()));
    assert!(methods.contains(&"POST".to_string()));
    assert!(methods.contains(&"PUT".to_string()));
    assert!(methods.contains(&"DELETE".to_string()));
    assert!(methods.contains(&"PATCH".to_string()));
    assert!(methods.contains(&"OPTIONS".to_string()));
    assert!(methods.contains(&"HEAD".to_string()));
}

#[test]
fn import_invalid_yaml_reports_error() {
    let result = import_openapi("not: valid: yaml: [", false);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("invalid"));
}

#[test]
fn import_invalid_json_reports_error() {
    let result = import_openapi("{not valid json", true);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("invalid"));
}

#[test]
fn import_empty_paths_produces_zero_routes() {
    let yaml = r#"
openapi: 3.0.0
info:
  title: Empty
  version: 1.0.0
paths: {}
"#;
    let result = import_openapi(yaml, false).unwrap();
    assert_eq!(result.route_count, 0);
    // The generated config has zero routes — it needs
    // allow_empty_routes to validate.
    let gateway = parse_gateway(&result.yaml).unwrap();
    assert!(gateway.allow_empty_routes);
    assert!(gateway.routes.is_empty());
}
