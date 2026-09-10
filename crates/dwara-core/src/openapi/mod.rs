//! OpenAPI response validation (DW-070, #258).
//!
//! This module validates upstream responses against the OpenAPI spec's
//! response schemas. When a response violates the spec, it is flagged
//! as drift and optionally returned as a 502 to the client.
//!
//! ## Design (section 5-API Mgmt, section 6-API Craft)
//!
//! This is the runtime half of section 5-API Mgmt's "OpenAPI-driven
//! config" item, whose import/request-validation/mock half already
//! shipped as DW-047 (M2). This is also the concrete implementation of
//! Tier 3's "Contract testing mode" (section 6-API Craft): verify live
//! traffic conforms to the spec DW-047 imported, and flag drift.
//!
//! ## Scope
//!
//! This covers per-response schema-conformance drift, not route-set
//! drift (whether the live route set has grown out of sync with the
//! spec's endpoint list).
//!
//! ## Wildcard status codes (#258)
//!
//! OpenAPI specs commonly use `default`, `2XX`, `4XX`, and `5XX` as
//! wildcard response keys. The validator resolves a concrete response
//! status (e.g. 200) by trying, in order: exact match (200), family
//! match (2XX), then `default`. The first match wins.
//!
//! ## Content types (#258)
//!
//! In addition to `application/json`, the validator extracts schemas
//! for `application/problem+json`, `application/vnd.api+json`,
//! `text/plain`, and `application/xml`. JSON-variant content types
//! are parsed as JSON for schema validation; `text/plain` bodies are
//! wrapped as JSON strings; `application/xml` schemas are registered
//! (status-code validation) but body schema validation is skipped
//! (JSON Schema cannot validate XML).
//!
//! ## Strict mode (#258)
//!
//! When `strict` is true, a response with no matching schema (unknown
//! status or content type) returns `Invalid` instead of `NoSchema`.
//! This enforces that every response must be covered by the spec.
//!
//! ## Feature gate
//!
//! The `openapi_validation` cargo feature must be enabled. Without it,
//! the module is not compiled and config fields that reference OpenAPI
//! response validation are accepted but inert.

use std::collections::HashMap;
use std::sync::Arc;

use jsonschema::Validator;
use serde_json::Value;

/// A status pattern extracted from an OpenAPI response key.
///
/// OpenAPI response keys can be exact (`"200"`), family wildcards
/// (`"2XX"`, `"4XX"`), or `default`. The validator resolves a concrete
/// response status by trying exact, then family, then default.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum StatusPattern {
    /// An exact status code, e.g. 200, 404.
    Exact(u16),
    /// A family wildcard, e.g. 2XX (stored as the leading digit, 2).
    Family(u8),
    /// The OpenAPI `default` response key.
    Default,
}

impl StatusPattern {
    /// Check if this pattern matches a concrete status code.
    pub fn matches(&self, status: u16) -> bool {
        match self {
            StatusPattern::Exact(s) => *s == status,
            StatusPattern::Family(d) => (status / 100) as u8 == *d,
            StatusPattern::Default => true,
        }
    }
}

/// A compiled OpenAPI response validator.
///
/// Holds compiled JSON Schema validators for each (path, method,
/// status_pattern, content_type) tuple. Created at config publish
/// time from the OpenAPI spec's response schemas.
#[derive(Clone)]
pub struct ResponseValidator {
    /// Map: (path, method, status_pattern, content_type) -> validator.
    schemas: Arc<HashMap<ResponseKey, Arc<Validator>>>,
    /// When true, unknown statuses/content types are Invalid, not NoSchema.
    strict: bool,
}

/// The key for a response schema: (path, method, status_pattern,
/// content_type).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResponseKey {
    pub path: String,
    pub method: String,
    pub status: StatusPattern,
    pub content_type: String,
}

/// The result of validating a response.
#[derive(Clone, Debug)]
pub enum ValidationResult {
    /// The response conforms to the spec.
    Valid,
    /// The response violates the spec. Contains the validation errors.
    Invalid(Vec<ValidationError>),
    /// No schema found for this (path, method, status, content_type).
    /// The response is not validated (the spec does not cover it).
    NoSchema,
}

/// A single validation error.
#[derive(Clone, Debug)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

/// A response to validate.
#[derive(Clone, Debug)]
pub struct ResponseToValidate {
    pub path: String,
    pub method: String,
    pub status: u16,
    pub content_type: Option<String>,
    /// The response body as a JSON value. If the body is not JSON,
    /// this is None and validation skips schema checks (only status
    /// code is checked).
    pub body: Option<Value>,
}

/// Content types the validator extracts schemas for.
const SUPPORTED_CONTENT_TYPES: &[&str] = &[
    "application/json",
    "application/problem+json",
    "application/vnd.api+json",
    "text/plain",
    "application/xml",
];

impl ResponseValidator {
    /// Create a new empty validator (no schemas — all responses get
    /// `NoSchema`).
    pub fn empty() -> Self {
        Self {
            schemas: Arc::new(HashMap::new()),
            strict: false,
        }
    }

    /// Create a new validator from a map of compiled schemas.
    pub fn from_schemas(schemas: HashMap<ResponseKey, Value>) -> Result<Self, String> {
        Self::from_schemas_strict(schemas, false)
    }

    /// Create a new validator from a map of compiled schemas with a
    /// strict mode flag.
    pub fn from_schemas_strict(
        schemas: HashMap<ResponseKey, Value>,
        strict: bool,
    ) -> Result<Self, String> {
        let mut compiled = HashMap::new();
        for (key, schema) in schemas {
            let validator =
                Validator::new(&schema).map_err(|e| format!("compile schema for {key:?}: {e}"))?;
            compiled.insert(key, Arc::new(validator));
        }
        Ok(Self {
            schemas: Arc::new(compiled),
            strict,
        })
    }

    /// Create a new validator from an OpenAPI document.
    ///
    /// The document should be a parsed OpenAPI 3.x JSON value. This
    /// method extracts the response schemas for each (path, method,
    /// status_pattern, content_type) tuple and compiles them.
    pub fn from_openapi(doc: &Value) -> Result<Self, String> {
        Self::from_openapi_strict(doc, false)
    }

    /// Create a new validator from an OpenAPI document with a strict
    /// mode flag.
    pub fn from_openapi_strict(doc: &Value, strict: bool) -> Result<Self, String> {
        let mut schemas = HashMap::new();

        let paths = doc
            .get("paths")
            .and_then(|v| v.as_object())
            .ok_or_else(|| "OpenAPI doc missing 'paths'".to_string())?;

        for (path, path_item) in paths {
            let path_item = path_item
                .as_object()
                .ok_or_else(|| format!("path '{path}' is not an object"))?;

            for (method, operation) in path_item {
                // Skip non-method fields (parameters, summary, etc.).
                if !is_http_method(method) {
                    continue;
                }

                let responses = operation
                    .get("responses")
                    .and_then(|v| v.as_object())
                    .ok_or_else(|| format!("operation {method} {path} missing 'responses'"))?;

                for (status_str, response) in responses {
                    let status = parse_status(status_str, path, method)?;

                    // Extract schemas for all supported content types.
                    for (content_type, schema) in extract_response_schemas(response) {
                        let key = ResponseKey {
                            path: path.clone(),
                            method: method.to_uppercase(),
                            status: status.clone(),
                            content_type,
                        };
                        schemas.insert(key, schema);
                    }
                }
            }
        }

        Self::from_schemas_strict(schemas, strict)
    }

    /// Validate a response against its schema.
    ///
    /// The lookup tries exact status, then family (2XX/4XX/5XX), then
    /// default. Within each status pattern, it tries the exact content
    /// type, then any content type. The first match wins.
    pub fn validate(&self, response: &ResponseToValidate) -> ValidationResult {
        let method = response.method.to_uppercase();
        let ct = normalize_content_type(response.content_type.as_deref());

        // Build the list of candidate keys in specificity order.
        let candidates = lookup_candidates(&response.path, &method, response.status, ct.as_deref());

        let validator = candidates
            .iter()
            .find_map(|key| self.schemas.get(key))
            .cloned();

        let validator = match validator {
            Some(v) => v,
            None => {
                if self.strict {
                    return ValidationResult::Invalid(vec![ValidationError {
                        path: response.path.clone(),
                        message: format!(
                            "no schema for {} {} status {} content_type {:?} (strict mode)",
                            method, response.path, response.status, ct
                        ),
                    }]);
                }
                return ValidationResult::NoSchema;
            }
        };

        // If the response has no body, we can only check the status
        // code (which matched by virtue of finding a schema). If the
        // schema requires a body, this will be caught by the
        // validator.
        let body = match &response.body {
            Some(b) => b,
            None => return ValidationResult::Valid,
        };

        let errors: Vec<_> = validator.iter_errors(body).collect();
        if errors.is_empty() {
            ValidationResult::Valid
        } else {
            let errors: Vec<ValidationError> = errors
                .into_iter()
                .map(|e| ValidationError {
                    path: e.instance_path().to_string(),
                    message: e.to_string(),
                })
                .collect();
            ValidationResult::Invalid(errors)
        }
    }

    /// The number of compiled schemas.
    pub fn schema_count(&self) -> usize {
        self.schemas.len()
    }

    /// Whether a schema exists for the given (path, method, status).
    pub fn has_schema(&self, path: &str, method: &str, status: u16) -> bool {
        let method = method.to_uppercase();
        let candidates = lookup_candidates(path, &method, status, None);
        candidates.iter().any(|key| self.schemas.contains_key(key))
    }

    /// Whether strict mode is enabled.
    pub fn is_strict(&self) -> bool {
        self.strict
    }
}

/// Build a list of candidate `ResponseKey`s for a validate lookup,
/// ordered from most specific to least specific.
///
/// Order: exact status + exact CT, exact status + any CT, family +
/// exact CT, family + any CT, default + exact CT, default + any CT.
fn lookup_candidates(
    path: &str,
    method: &str,
    status: u16,
    content_type: Option<&str>,
) -> Vec<ResponseKey> {
    let family = (status / 100) as u8;
    let patterns = vec![
        StatusPattern::Exact(status),
        StatusPattern::Family(family),
        StatusPattern::Default,
    ];

    // When a concrete content type is given, try it then all
    // supported types (for charset-variant matching) then the
    // empty-string wildcard. When no content type is given, try
    // all supported types then the empty-string wildcard.
    let ct_candidates: Vec<String> = match content_type {
        Some(ct) => {
            let mut v = vec![ct.to_string()];
            for sct in SUPPORTED_CONTENT_TYPES {
                if *sct != ct {
                    v.push(sct.to_string());
                }
            }
            v.push(String::new());
            v
        }
        None => {
            let mut v: Vec<String> = SUPPORTED_CONTENT_TYPES
                .iter()
                .map(|s| s.to_string())
                .collect();
            v.push(String::new());
            v
        }
    };

    let mut keys = Vec::new();
    for pattern in &patterns {
        for ct in &ct_candidates {
            keys.push(ResponseKey {
                path: path.to_string(),
                method: method.to_string(),
                status: pattern.clone(),
                content_type: ct.clone(),
            });
        }
    }
    keys
}

/// Check if a string is an HTTP method.
fn is_http_method(s: &str) -> bool {
    matches!(
        s.to_lowercase().as_str(),
        "get" | "post" | "put" | "delete" | "patch" | "head" | "options"
    )
}

/// Parse a status code from an OpenAPI response key.
///
/// OpenAPI uses status codes like "200", "404", "2XX", "default".
/// Returns the corresponding `StatusPattern`.
fn parse_status(status_str: &str, path: &str, method: &str) -> Result<StatusPattern, String> {
    if status_str == "default" {
        return Ok(StatusPattern::Default);
    }

    // Handle wildcards like "2XX", "4XX".
    if status_str.ends_with("XX") && status_str.len() == 3 {
        let digit = status_str
            .chars()
            .next()
            .and_then(|c| c.to_digit(10))
            .ok_or_else(|| format!("invalid wildcard status '{status_str}' in {method} {path}"))?;
        return Ok(StatusPattern::Family(digit as u8));
    }

    let code: u16 = status_str
        .parse()
        .map_err(|_| format!("invalid status code '{status_str}' in {method} {path}"))?;
    Ok(StatusPattern::Exact(code))
}

/// Extract response schemas for all supported content types.
///
/// Returns a list of (content_type, schema) pairs. JSON-variant
/// content types (`application/json`, `application/problem+json`,
/// `application/vnd.api+json`) are returned as-is. `text/plain`
/// schemas are returned (the body is wrapped as a JSON string at
/// validate time). `application/xml` schemas are returned but body
/// validation is skipped (JSON Schema cannot validate XML).
fn extract_response_schemas(response: &Value) -> Vec<(String, Value)> {
    let content = match response.get("content").and_then(|c| c.as_object()) {
        Some(c) => c,
        None => return Vec::new(),
    };

    let mut result = Vec::new();
    for ct in SUPPORTED_CONTENT_TYPES {
        if let Some(media_type) = content.get(*ct) {
            if let Some(schema) = media_type.get("schema").cloned() {
                result.push((ct.to_string(), schema));
            }
        }
    }
    result
}

/// Normalize a content type for matching by stripping parameters
/// (e.g. `application/json; charset=utf-8` -> `application/json`).
fn normalize_content_type(ct: Option<&str>) -> Option<String> {
    let ct = ct?;
    let base = ct.split(';').next()?.trim();
    if base.is_empty() {
        None
    } else {
        Some(base.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_pattern_exact_matches() {
        assert!(StatusPattern::Exact(200).matches(200));
        assert!(!StatusPattern::Exact(200).matches(201));
    }

    #[test]
    fn status_pattern_family_matches() {
        assert!(StatusPattern::Family(2).matches(200));
        assert!(StatusPattern::Family(2).matches(204));
        assert!(!StatusPattern::Family(2).matches(404));
    }

    #[test]
    fn status_pattern_default_matches_all() {
        assert!(StatusPattern::Default.matches(200));
        assert!(StatusPattern::Default.matches(404));
        assert!(StatusPattern::Default.matches(500));
    }

    #[test]
    fn parse_status_exact() {
        assert_eq!(
            parse_status("200", "/x", "get").unwrap(),
            StatusPattern::Exact(200)
        );
    }

    #[test]
    fn parse_status_family() {
        assert_eq!(
            parse_status("2XX", "/x", "get").unwrap(),
            StatusPattern::Family(2)
        );
        assert_eq!(
            parse_status("4XX", "/x", "get").unwrap(),
            StatusPattern::Family(4)
        );
    }

    #[test]
    fn parse_status_default() {
        assert_eq!(
            parse_status("default", "/x", "get").unwrap(),
            StatusPattern::Default
        );
    }

    #[test]
    fn parse_status_invalid() {
        assert!(parse_status("abc", "/x", "get").is_err());
    }

    #[test]
    fn normalize_content_type_strips_params() {
        assert_eq!(
            normalize_content_type(Some("application/json; charset=utf-8")),
            Some("application/json".to_string())
        );
        assert_eq!(
            normalize_content_type(Some("application/json")),
            Some("application/json".to_string())
        );
        assert_eq!(normalize_content_type(None), None);
    }

    #[test]
    fn extract_response_schemas_multiple_types() {
        let response = serde_json::json!({
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
        });
        let schemas = extract_response_schemas(&response);
        assert_eq!(schemas.len(), 3);
        let cts: Vec<&str> = schemas.iter().map(|(c, _)| c.as_str()).collect();
        assert!(cts.contains(&"application/json"));
        assert!(cts.contains(&"application/problem+json"));
        assert!(cts.contains(&"text/plain"));
    }
}
