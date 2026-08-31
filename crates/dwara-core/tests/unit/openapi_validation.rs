//! Unit tests for `openapi` validation (relocated from src).

#![cfg(feature = "openapi_validation")]

use dwara_core::openapi::{ResponseKey, ResponseToValidate, ResponseValidator, ValidationResult};
use serde_json::json;
use std::collections::HashMap;

#[test]
fn empty_validator_returns_no_schema() {
    let validator = ResponseValidator::empty();
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 200,
        content_type: Some("application/json".to_string()),
        body: Some(json!({"id": 1})),
    };
    assert!(matches!(
        validator.validate(&response),
        ValidationResult::NoSchema
    ));
}

#[test]
fn valid_response_passes() {
    let mut schemas = HashMap::new();
    schemas.insert(
        ResponseKey {
            path: "/users".to_string(),
            method: "GET".to_string(),
            status: 200,
        },
        json!({
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"}
            },
            "required": ["id", "name"]
        }),
    );
    let validator = ResponseValidator::from_schemas(schemas).unwrap();
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 200,
        content_type: Some("application/json".to_string()),
        body: Some(json!({"id": 1, "name": "Alice"})),
    };
    assert!(matches!(
        validator.validate(&response),
        ValidationResult::Valid
    ));
}

#[test]
fn invalid_response_flagged() {
    let mut schemas = HashMap::new();
    schemas.insert(
        ResponseKey {
            path: "/users".to_string(),
            method: "GET".to_string(),
            status: 200,
        },
        json!({
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"}
            },
            "required": ["id", "name"]
        }),
    );
    let validator = ResponseValidator::from_schemas(schemas).unwrap();
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 200,
        content_type: Some("application/json".to_string()),
        body: Some(json!({"id": "not-an-integer"})),
    };
    match validator.validate(&response) {
        ValidationResult::Invalid(errors) => {
            assert!(!errors.is_empty());
        }
        _ => panic!("expected Invalid"),
    }
}

#[test]
fn missing_required_field_flagged() {
    let mut schemas = HashMap::new();
    schemas.insert(
        ResponseKey {
            path: "/users".to_string(),
            method: "GET".to_string(),
            status: 200,
        },
        json!({
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"}
            },
            "required": ["id", "name"]
        }),
    );
    let validator = ResponseValidator::from_schemas(schemas).unwrap();
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 200,
        content_type: Some("application/json".to_string()),
        body: Some(json!({"id": 1})),
    };
    match validator.validate(&response) {
        ValidationResult::Invalid(errors) => {
            assert!(!errors.is_empty());
        }
        _ => panic!("expected Invalid"),
    }
}

#[test]
fn no_schema_for_unknown_status() {
    let mut schemas = HashMap::new();
    schemas.insert(
        ResponseKey {
            path: "/users".to_string(),
            method: "GET".to_string(),
            status: 200,
        },
        json!({"type": "object"}),
    );
    let validator = ResponseValidator::from_schemas(schemas).unwrap();
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 404,
        content_type: Some("application/json".to_string()),
        body: Some(json!({"error": "not found"})),
    };
    assert!(matches!(
        validator.validate(&response),
        ValidationResult::NoSchema
    ));
}

#[test]
fn from_openapi_extracts_schemas() {
    let doc = json!({
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "integer"}
                                        },
                                        "required": ["id"]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    let validator = ResponseValidator::from_openapi(&doc).unwrap();
    assert_eq!(validator.schema_count(), 1);
    assert!(validator.has_schema("/users", "GET", 200));
}

#[test]
fn from_openapi_skips_non_json_content() {
    let doc = json!({
        "openapi": "3.0.0",
        "paths": {
            "/binary": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/octet-stream": {
                                    "schema": {"type": "string", "format": "binary"}
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    let validator = ResponseValidator::from_openapi(&doc).unwrap();
    assert_eq!(validator.schema_count(), 0);
}

#[test]
fn from_openapi_handles_multiple_methods() {
    let doc = json!({
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        }
                    }
                },
                "post": {
                    "responses": {
                        "201": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    let validator = ResponseValidator::from_openapi(&doc).unwrap();
    assert_eq!(validator.schema_count(), 2);
    assert!(validator.has_schema("/users", "GET", 200));
    assert!(validator.has_schema("/users", "POST", 201));
}

#[test]
fn from_openapi_skips_parameters_field() {
    let doc = json!({
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "parameters": [],
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    let validator = ResponseValidator::from_openapi(&doc).unwrap();
    assert_eq!(validator.schema_count(), 1);
}

#[test]
fn from_openapi_missing_paths_returns_error() {
    let doc = json!({"openapi": "3.0.0"});
    assert!(ResponseValidator::from_openapi(&doc).is_err());
}

#[test]
fn response_with_no_body_is_valid() {
    let mut schemas = HashMap::new();
    schemas.insert(
        ResponseKey {
            path: "/users".to_string(),
            method: "GET".to_string(),
            status: 204,
        },
        json!({"type": "null"}),
    );
    let validator = ResponseValidator::from_schemas(schemas).unwrap();
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 204,
        content_type: None,
        body: None,
    };
    assert!(matches!(
        validator.validate(&response),
        ValidationResult::Valid
    ));
}

#[test]
fn array_response_validation() {
    let mut schemas = HashMap::new();
    schemas.insert(
        ResponseKey {
            path: "/users".to_string(),
            method: "GET".to_string(),
            status: 200,
        },
        json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"}
                },
                "required": ["id"]
            }
        }),
    );
    let validator = ResponseValidator::from_schemas(schemas).unwrap();

    // Valid array.
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 200,
        content_type: Some("application/json".to_string()),
        body: Some(json!([{"id": 1}, {"id": 2}])),
    };
    assert!(matches!(
        validator.validate(&response),
        ValidationResult::Valid
    ));

    // Invalid array (missing required field).
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 200,
        content_type: Some("application/json".to_string()),
        body: Some(json!([{"id": 1}, {"name": "missing id"}])),
    };
    assert!(matches!(
        validator.validate(&response),
        ValidationResult::Invalid(_)
    ));
}
