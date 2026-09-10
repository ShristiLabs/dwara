//! Unit tests for `openapi` validation (relocated from src, #258).

use dwara_core::openapi::{
    ResponseKey, ResponseToValidate, ResponseValidator, StatusPattern, ValidationResult,
};
use serde_json::json;
use std::collections::HashMap;

fn key(path: &str, method: &str, status: u16) -> ResponseKey {
    ResponseKey {
        path: path.to_string(),
        method: method.to_string(),
        status: StatusPattern::Exact(status),
        content_type: "application/json".to_string(),
    }
}

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
        key("/users", "GET", 200),
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
        key("/users", "GET", 200),
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
        key("/users", "GET", 200),
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
    schemas.insert(key("/users", "GET", 200), json!({"type": "object"}));
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
fn from_openapi_skips_unsupported_content() {
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
    schemas.insert(key("/users", "GET", 204), json!({"type": "null"}));
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
        key("/users", "GET", 200),
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

// --- #258: wildcard status codes ---

#[test]
fn from_openapi_extracts_2xx_wildcard() {
    let doc = json!({
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "get": {
                    "responses": {
                        "2XX": {
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
    // 200 should match the 2XX wildcard.
    assert!(validator.has_schema("/users", "GET", 200));
    assert!(validator.has_schema("/users", "GET", 201));
    assert!(validator.has_schema("/users", "GET", 204));
    // 404 should not match 2XX.
    assert!(!validator.has_schema("/users", "GET", 404));
}

#[test]
fn from_openapi_extracts_default() {
    let doc = json!({
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "get": {
                    "responses": {
                        "default": {
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
    // Default matches any status.
    assert!(validator.has_schema("/users", "GET", 200));
    assert!(validator.has_schema("/users", "GET", 404));
    assert!(validator.has_schema("/users", "GET", 500));
}

#[test]
fn exact_status_preferred_over_wildcard() {
    let mut schemas = HashMap::new();
    schemas.insert(
        ResponseKey {
            path: "/users".to_string(),
            method: "GET".to_string(),
            status: StatusPattern::Exact(200),
            content_type: "application/json".to_string(),
        },
        json!({"type": "object", "properties": {"exact": {"type": "boolean"}}, "required": ["exact"]}),
    );
    schemas.insert(
        ResponseKey {
            path: "/users".to_string(),
            method: "GET".to_string(),
            status: StatusPattern::Family(2),
            content_type: "application/json".to_string(),
        },
        json!({"type": "object", "properties": {"family": {"type": "boolean"}}, "required": ["family"]}),
    );
    let validator = ResponseValidator::from_schemas(schemas).unwrap();

    // 200 should match the exact schema (requires "exact"), not the
    // family schema (requires "family").
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 200,
        content_type: Some("application/json".to_string()),
        body: Some(json!({"exact": true})),
    };
    assert!(matches!(
        validator.validate(&response),
        ValidationResult::Valid
    ));

    // 201 should fall through to the family schema (requires "family").
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 201,
        content_type: Some("application/json".to_string()),
        body: Some(json!({"family": true})),
    };
    assert!(matches!(
        validator.validate(&response),
        ValidationResult::Valid
    ));
}

#[test]
fn family_preferred_over_default() {
    let mut schemas = HashMap::new();
    schemas.insert(
        ResponseKey {
            path: "/users".to_string(),
            method: "GET".to_string(),
            status: StatusPattern::Family(4),
            content_type: "application/json".to_string(),
        },
        json!({"type": "object", "properties": {"err": {"type": "boolean"}}, "required": ["err"]}),
    );
    schemas.insert(
        ResponseKey {
            path: "/users".to_string(),
            method: "GET".to_string(),
            status: StatusPattern::Default,
            content_type: "application/json".to_string(),
        },
        json!({"type": "object", "properties": {"def": {"type": "boolean"}}, "required": ["def"]}),
    );
    let validator = ResponseValidator::from_schemas(schemas).unwrap();

    // 404 should match the 4XX family schema (requires "err").
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 404,
        content_type: Some("application/json".to_string()),
        body: Some(json!({"err": true})),
    };
    assert!(matches!(
        validator.validate(&response),
        ValidationResult::Valid
    ));

    // 500 should fall through to default (requires "def").
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 500,
        content_type: Some("application/json".to_string()),
        body: Some(json!({"def": true})),
    };
    assert!(matches!(
        validator.validate(&response),
        ValidationResult::Valid
    ));
}

// --- #258: additional content types ---

#[test]
fn from_openapi_extracts_problem_json() {
    let doc = json!({
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "get": {
                    "responses": {
                        "404": {
                            "content": {
                                "application/problem+json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "type": {"type": "string"},
                                            "title": {"type": "string"}
                                        },
                                        "required": ["type"]
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
    assert!(validator.has_schema("/users", "GET", 404));

    // Validate a problem+json response.
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 404,
        content_type: Some("application/problem+json".to_string()),
        body: Some(json!({"type": "about:blank", "title": "Not Found"})),
    };
    assert!(matches!(
        validator.validate(&response),
        ValidationResult::Valid
    ));
}

#[test]
fn from_openapi_extracts_text_plain() {
    let doc = json!({
        "openapi": "3.0.0",
        "paths": {
            "/health": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "text/plain": {
                                    "schema": {"type": "string"}
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
    assert!(validator.has_schema("/health", "GET", 200));
}

#[test]
fn from_openapi_extracts_xml() {
    let doc = json!({
        "openapi": "3.0.0",
        "paths": {
            "/data": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/xml": {
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
    // XML schema is registered (status-code validation works).
    assert_eq!(validator.schema_count(), 1);
    assert!(validator.has_schema("/data", "GET", 200));
}

#[test]
fn from_openapi_extracts_multiple_content_types() {
    let doc = json!({
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object", "properties": {"id": {"type": "integer"}}}
                                },
                                "application/problem+json": {
                                    "schema": {"type": "object", "properties": {"error": {"type": "string"}}}
                                },
                                "text/plain": {
                                    "schema": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    let validator = ResponseValidator::from_openapi(&doc).unwrap();
    // Three content types extracted for one (path, method, status).
    assert_eq!(validator.schema_count(), 3);
}

// --- #258: strict mode ---

#[test]
fn strict_mode_rejects_unknown_status() {
    let mut schemas = HashMap::new();
    schemas.insert(key("/users", "GET", 200), json!({"type": "object"}));
    let validator = ResponseValidator::from_schemas_strict(schemas, true).unwrap();
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 404,
        content_type: Some("application/json".to_string()),
        body: Some(json!({"error": "not found"})),
    };
    match validator.validate(&response) {
        ValidationResult::Invalid(_) => {}
        _ => panic!("expected Invalid in strict mode"),
    }
}

#[test]
fn strict_mode_rejects_unknown_content_type() {
    let mut schemas = HashMap::new();
    schemas.insert(key("/users", "GET", 200), json!({"type": "object"}));
    let validator = ResponseValidator::from_schemas_strict(schemas, true).unwrap();
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 200,
        content_type: Some("text/csv".to_string()),
        body: Some(json!("a,b,c")),
    };
    match validator.validate(&response) {
        ValidationResult::Invalid(_) => {}
        _ => panic!("expected Invalid in strict mode for unknown content type"),
    }
}

#[test]
fn strict_mode_accepts_known_response() {
    let mut schemas = HashMap::new();
    schemas.insert(key("/users", "GET", 200), json!({"type": "object"}));
    let validator = ResponseValidator::from_schemas_strict(schemas, true).unwrap();
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 200,
        content_type: Some("application/json".to_string()),
        body: Some(json!({"id": 1})),
    };
    assert!(matches!(
        validator.validate(&response),
        ValidationResult::Valid
    ));
}

#[test]
fn from_openapi_strict_mode() {
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
                }
            }
        }
    });
    let validator = ResponseValidator::from_openapi_strict(&doc, true).unwrap();
    assert!(validator.is_strict());

    // Unknown status in strict mode -> Invalid.
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 500,
        content_type: Some("application/json".to_string()),
        body: Some(json!({"error": "oops"})),
    };
    match validator.validate(&response) {
        ValidationResult::Invalid(_) => {}
        _ => panic!("expected Invalid in strict mode"),
    }
}

#[test]
fn content_type_with_charset_matches() {
    let mut schemas = HashMap::new();
    schemas.insert(key("/users", "GET", 200), json!({"type": "object"}));
    let validator = ResponseValidator::from_schemas(schemas).unwrap();
    // Content type with charset parameter should still match.
    let response = ResponseToValidate {
        path: "/users".to_string(),
        method: "GET".to_string(),
        status: 200,
        content_type: Some("application/json; charset=utf-8".to_string()),
        body: Some(json!({"id": 1})),
    };
    assert!(matches!(
        validator.validate(&response),
        ValidationResult::Valid
    ));
}
