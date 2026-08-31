//! API aggregation plugin pack (DW-061).
//!
//! Multi-upstream composition, JSONPath/CEL fragment shaping,
//! per-fragment fail-open/closed (decision 10; section 5-Traffic).
//!
//! ## Constraint (decision 10, section 12.1)
//!
//! The core dataplane never buffers full bodies to support composition
//! -- only this plugin's own fragment transforms, with explicit size
//! caps, touch bodies. Composition stays an extension cost, never a
//! tax on the zero-buffering proxy path everything else uses.
//!
//! ## KrakenD-style aggregation
//!
//! An aggregation endpoint composes a response from multiple upstreams.
//! Each fragment specifies:
//! - An upstream reference (service name + path)
//! - A JSONPath expression to extract a fragment from the upstream
//!   response
//! - A target field in the composed response
//! - A fail-open/closed policy (fail-open = skip on error, fail-closed
//!   = return an error)
//!
//! The aggregator fetches all fragments in parallel, shapes each, and
//! combines them into a single JSON response.
//!
//! ## Done-when
//!
//! KrakenD-style endpoint composed from 3 upstreams incl. failure case.
//!
//! ## Feature gate
//!
//! The `aggregation` cargo feature must be enabled.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Aggregation spec
// ---------------------------------------------------------------------------

/// An aggregation endpoint spec: composes a response from multiple
/// upstream fragments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregationSpec {
    /// The endpoint name (for logging/metrics).
    pub name: String,
    /// The fragments to compose.
    pub fragments: Vec<FragmentSpec>,
    /// The maximum total response size in bytes (default: 1MB).
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
}

fn default_max_response_bytes() -> usize {
    1_048_576 // 1 MB
}

/// A single fragment in an aggregation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentSpec {
    /// The fragment name (used as the target field key if
    /// `target_field` is not set).
    pub name: String,
    /// The upstream service name.
    pub service: String,
    /// The path on the upstream service.
    pub path: String,
    /// The HTTP method (default: GET).
    #[serde(default = "default_method")]
    pub method: String,
    /// A JSONPath expression to extract a fragment from the upstream
    /// response. If empty, the entire response is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jsonpath: Option<String>,
    /// The target field in the composed response. If empty, the
    /// fragment name is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_field: Option<String>,
    /// The fail policy: fail-open (skip on error) or fail-closed
    /// (return an error). Default: fail-open.
    #[serde(default)]
    pub fail_policy: FailPolicy,
    /// The maximum fragment size in bytes (default: 256KB).
    #[serde(default = "default_max_fragment_bytes")]
    pub max_fragment_bytes: usize,
}

fn default_method() -> String {
    "GET".to_string()
}

fn default_max_fragment_bytes() -> usize {
    262_144 // 256 KB
}

/// The fail policy for a fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FailPolicy {
    /// Skip the fragment on error (the composed response omits the
    /// field). This is the default.
    FailOpen,
    /// Return an error on failure (the entire composed response fails).
    FailClosed,
}

impl Default for FailPolicy {
    fn default() -> Self {
        FailPolicy::FailOpen
    }
}

// ---------------------------------------------------------------------------
// Fragment result
// ---------------------------------------------------------------------------

/// The result of fetching a fragment.
#[derive(Clone, Debug, PartialEq)]
pub enum FragmentResult {
    /// The fragment was fetched successfully.
    Ok {
        /// The extracted JSON value (after JSONPath shaping).
        value: Value,
        /// The fragment name.
        name: String,
        /// The target field in the composed response.
        target_field: String,
    },
    /// The fragment fetch failed.
    Error {
        /// The fragment name.
        name: String,
        /// The error message.
        error: String,
        /// The fail policy for this fragment.
        fail_policy: FailPolicy,
    },
}

// ---------------------------------------------------------------------------
// Aggregator
// ---------------------------------------------------------------------------

/// Compose a response from fragment results.
///
/// This is the pure composition step: it takes the fragment results
/// (already fetched + shaped by the plugin runtime) and combines them
/// into a single JSON object. Fail-open fragments are skipped;
/// fail-closed fragments cause the entire composition to fail.
pub fn compose(spec: &AggregationSpec, results: &[FragmentResult]) -> ComposeResult {
    let mut response = serde_json::Map::new();
    let mut errors = Vec::new();

    for result in results {
        match result {
            FragmentResult::Ok {
                value,
                target_field,
                ..
            } => {
                // Check total response size.
                let current_size = serde_json::to_vec(&Value::Object(response.clone()))
                    .map(|v| v.len())
                    .unwrap_or(0);
                let fragment_size = serde_json::to_vec(value).map(|v| v.len()).unwrap_or(0);

                if current_size + fragment_size > spec.max_response_bytes {
                    errors.push(format!(
                        "composed response exceeds max size ({} + {} > {})",
                        current_size, fragment_size, spec.max_response_bytes
                    ));
                    // Skip this fragment (treat as fail-open).
                    continue;
                }

                response.insert(target_field.clone(), value.clone());
            }
            FragmentResult::Error {
                name,
                error,
                fail_policy,
            } => {
                match fail_policy {
                    FailPolicy::FailOpen => {
                        // Skip the fragment; record the error as a warning.
                        errors.push(format!("fragment '{name}' failed (fail-open): {error}"));
                    }
                    FailPolicy::FailClosed => {
                        // The entire composition fails.
                        return ComposeResult::Error {
                            error: format!("fragment '{name}' failed (fail-closed): {error}"),
                            partial: Some(Value::Object(response)),
                        };
                    }
                }
            }
        }
    }

    ComposeResult::Ok {
        response: Value::Object(response),
        warnings: errors,
    }
}

/// The result of composing fragments.
#[derive(Clone, Debug, PartialEq)]
pub enum ComposeResult {
    /// The composition succeeded.
    Ok {
        /// The composed JSON response.
        response: Value,
        /// Warnings (e.g. fail-open fragments that were skipped).
        warnings: Vec<String>,
    },
    /// The composition failed (a fail-closed fragment errored).
    Error {
        /// The error message.
        error: String,
        /// The partial response (fragments that succeeded before the
        /// failure), if any.
        partial: Option<Value>,
    },
}

// ---------------------------------------------------------------------------
// JSONPath extraction (simplified)
// ---------------------------------------------------------------------------

/// Extract a value from a JSON document using a simplified JSONPath
/// expression.
///
/// Supports:
/// - `$` -- the root object
/// - `$.field` -- a field access
/// - `$.field.subfield` -- nested field access
/// - `$.field[0]` -- array index
///
/// This is a minimal implementation for the aggregation plugin. A
/// full JSONPath implementation (filter expressions, wildcards, etc.)
/// would use a dedicated crate.
pub fn extract_jsonpath(document: &Value, path: &str) -> Result<Value, String> {
    if path.is_empty() || path == "$" {
        return Ok(document.clone());
    }

    let path = path
        .strip_prefix("$.")
        .or(path.strip_prefix("$"))
        .unwrap_or(path);

    let mut current = document;
    for segment in path.split('.') {
        current = if segment.contains('[') && segment.contains(']') {
            // Array index: field[0]
            let bracket_start = segment.find('[').ok_or("invalid array index")?;
            let field = &segment[..bracket_start];
            let index_str = &segment[bracket_start + 1..segment.len() - 1];
            let index: usize = index_str.parse().map_err(|_| "invalid array index")?;

            let obj = current
                .get(field)
                .ok_or_else(|| format!("field '{field}' not found"))?;
            obj.get(index)
                .ok_or_else(|| format!("index {index} out of bounds"))?
        } else {
            current
                .get(segment)
                .ok_or_else(|| format!("field '{segment}' not found"))?
        };
    }

    Ok(current.clone())
}

/// Shape a fragment: extract the value using the JSONPath expression
/// (if any), otherwise return the document as-is.
pub fn shape_fragment(document: &Value, fragment: &FragmentSpec) -> Result<Value, String> {
    if let Some(path) = &fragment.jsonpath {
        extract_jsonpath(document, path)
    } else {
        Ok(document.clone())
    }
}

/// Create a fragment result from a fetched upstream response.
pub fn make_fragment_result(fragment: &FragmentSpec, response_body: &str) -> FragmentResult {
    let target_field = fragment
        .target_field
        .clone()
        .unwrap_or_else(|| fragment.name.clone());

    // Check fragment size.
    if response_body.len() > fragment.max_fragment_bytes {
        return FragmentResult::Error {
            name: fragment.name.clone(),
            error: format!(
                "fragment body exceeds max size ({} > {})",
                response_body.len(),
                fragment.max_fragment_bytes
            ),
            fail_policy: fragment.fail_policy,
        };
    }

    // Parse JSON.
    let document: Value = match serde_json::from_str(response_body) {
        Ok(v) => v,
        Err(e) => {
            return FragmentResult::Error {
                name: fragment.name.clone(),
                error: format!("invalid JSON: {e}"),
                fail_policy: fragment.fail_policy,
            };
        }
    };

    // Shape the fragment.
    match shape_fragment(&document, fragment) {
        Ok(value) => FragmentResult::Ok {
            value,
            name: fragment.name.clone(),
            target_field,
        },
        Err(e) => FragmentResult::Error {
            name: fragment.name.clone(),
            error: format!("jsonpath extraction failed: {e}"),
            fail_policy: fragment.fail_policy,
        },
    }
}

/// Create an error fragment result (for when the upstream fetch fails).
pub fn make_error_fragment_result(fragment: &FragmentSpec, error: &str) -> FragmentResult {
    FragmentResult::Error {
        name: fragment.name.clone(),
        error: error.to_string(),
        fail_policy: fragment.fail_policy,
    }
}

// ---------------------------------------------------------------------------
// Aggregation spec validation
// ---------------------------------------------------------------------------

/// Validate an aggregation spec.
pub fn validate_spec(spec: &AggregationSpec) -> Result<(), String> {
    if spec.name.is_empty() {
        return Err("aggregation name cannot be empty".to_string());
    }

    if spec.fragments.is_empty() {
        return Err("aggregation must have at least one fragment".to_string());
    }

    if spec.max_response_bytes == 0 {
        return Err("max_response_bytes cannot be zero".to_string());
    }

    let mut seen_names = HashMap::new();
    for (i, fragment) in spec.fragments.iter().enumerate() {
        if fragment.name.is_empty() {
            return Err(format!("fragment {i}: name cannot be empty"));
        }

        if fragment.service.is_empty() {
            return Err(format!(
                "fragment '{}': service cannot be empty",
                fragment.name
            ));
        }

        if fragment.path.is_empty() {
            return Err(format!(
                "fragment '{}': path cannot be empty",
                fragment.name
            ));
        }

        if fragment.max_fragment_bytes == 0 {
            return Err(format!(
                "fragment '{}': max_fragment_bytes cannot be zero",
                fragment.name
            ));
        }

        // Check for duplicate target fields.
        let target = fragment
            .target_field
            .clone()
            .unwrap_or_else(|| fragment.name.clone());
        if let Some(prev) = seen_names.insert(target.clone(), i) {
            return Err(format!(
                "fragment '{target}' (index {i}) duplicates target field of fragment at index {prev}"
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fragment(name: &str, service: &str, path: &str) -> FragmentSpec {
        FragmentSpec {
            name: name.to_string(),
            service: service.to_string(),
            path: path.to_string(),
            method: "GET".to_string(),
            jsonpath: None,
            target_field: None,
            fail_policy: FailPolicy::FailOpen,
            max_fragment_bytes: 262_144,
        }
    }

    fn make_spec(name: &str, fragments: Vec<FragmentSpec>) -> AggregationSpec {
        AggregationSpec {
            name: name.to_string(),
            fragments,
            max_response_bytes: 1_048_576,
        }
    }

    // --- Validation ---

    #[test]
    fn validate_empty_name() {
        let spec = make_spec("", vec![make_fragment("f1", "svc", "/api")]);
        let err = validate_spec(&spec).unwrap_err();
        assert!(err.contains("name"));
    }

    #[test]
    fn validate_no_fragments() {
        let spec = make_spec("agg", vec![]);
        let err = validate_spec(&spec).unwrap_err();
        assert!(err.contains("at least one fragment"));
    }

    #[test]
    fn validate_zero_max_response_bytes() {
        let mut spec = make_spec("agg", vec![make_fragment("f1", "svc", "/api")]);
        spec.max_response_bytes = 0;
        let err = validate_spec(&spec).unwrap_err();
        assert!(err.contains("max_response_bytes"));
    }

    #[test]
    fn validate_duplicate_target_fields() {
        let mut f1 = make_fragment("f1", "svc1", "/api1");
        f1.target_field = Some("data".to_string());
        let mut f2 = make_fragment("f2", "svc2", "/api2");
        f2.target_field = Some("data".to_string());
        let spec = make_spec("agg", vec![f1, f2]);
        let err = validate_spec(&spec).unwrap_err();
        assert!(err.contains("duplicates target field"));
    }

    #[test]
    fn validate_valid_spec() {
        let spec = make_spec(
            "agg",
            vec![
                make_fragment("f1", "svc1", "/api1"),
                make_fragment("f2", "svc2", "/api2"),
            ],
        );
        validate_spec(&spec).unwrap();
    }

    // --- JSONPath extraction ---

    #[test]
    fn extract_root() {
        let doc = serde_json::json!({"name": "test"});
        let result = extract_jsonpath(&doc, "$").unwrap();
        assert_eq!(result, doc);
    }

    #[test]
    fn extract_field() {
        let doc = serde_json::json!({"name": "test", "value": 42});
        let result = extract_jsonpath(&doc, "$.name").unwrap();
        assert_eq!(result, Value::String("test".to_string()));
    }

    #[test]
    fn extract_nested_field() {
        let doc = serde_json::json!({"user": {"name": "alice", "age": 30}});
        let result = extract_jsonpath(&doc, "$.user.name").unwrap();
        assert_eq!(result, Value::String("alice".to_string()));
    }

    #[test]
    fn extract_array_index() {
        let doc = serde_json::json!({"items": ["a", "b", "c"]});
        let result = extract_jsonpath(&doc, "$.items[1]").unwrap();
        assert_eq!(result, Value::String("b".to_string()));
    }

    #[test]
    fn extract_field_not_found() {
        let doc = serde_json::json!({"name": "test"});
        let err = extract_jsonpath(&doc, "$.missing").unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn extract_empty_path_returns_root() {
        let doc = serde_json::json!({"name": "test"});
        let result = extract_jsonpath(&doc, "").unwrap();
        assert_eq!(result, doc);
    }

    // --- Fragment shaping ---

    #[test]
    fn shape_fragment_no_jsonpath() {
        let doc = serde_json::json!({"name": "test"});
        let fragment = make_fragment("f1", "svc", "/api");
        let result = shape_fragment(&doc, &fragment).unwrap();
        assert_eq!(result, doc);
    }

    #[test]
    fn shape_fragment_with_jsonpath() {
        let doc = serde_json::json!({"data": {"value": 42}});
        let mut fragment = make_fragment("f1", "svc", "/api");
        fragment.jsonpath = Some("$.data.value".to_string());
        let result = shape_fragment(&doc, &fragment).unwrap();
        assert_eq!(result, Value::Number(serde_json::Number::from(42)));
    }

    // --- make_fragment_result ---

    #[test]
    fn make_fragment_result_ok() {
        let fragment = make_fragment("f1", "svc", "/api");
        let result = make_fragment_result(&fragment, r#"{"name": "test"}"#);
        match result {
            FragmentResult::Ok {
                value,
                name,
                target_field,
            } => {
                assert_eq!(name, "f1");
                assert_eq!(target_field, "f1");
                assert_eq!(value, serde_json::json!({"name": "test"}));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn make_fragment_result_with_target_field() {
        let mut fragment = make_fragment("f1", "svc", "/api");
        fragment.target_field = Some("userData".to_string());
        let result = make_fragment_result(&fragment, r#"{"name": "test"}"#);
        match result {
            FragmentResult::Ok { target_field, .. } => {
                assert_eq!(target_field, "userData");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn make_fragment_result_invalid_json() {
        let fragment = make_fragment("f1", "svc", "/api");
        let result = make_fragment_result(&fragment, "not json");
        match result {
            FragmentResult::Error { error, .. } => assert!(error.contains("invalid JSON")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn make_fragment_result_exceeds_size() {
        let mut fragment = make_fragment("f1", "svc", "/api");
        fragment.max_fragment_bytes = 10;
        let result = make_fragment_result(&fragment, r#"{"name": "this is way too long"}"#);
        match result {
            FragmentResult::Error { error, .. } => assert!(error.contains("exceeds max size")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn make_fragment_result_jsonpath_error() {
        let mut fragment = make_fragment("f1", "svc", "/api");
        fragment.jsonpath = Some("$.missing".to_string());
        let result = make_fragment_result(&fragment, r#"{"name": "test"}"#);
        match result {
            FragmentResult::Error { error, .. } => assert!(error.contains("jsonpath")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn make_error_fragment_result_works() {
        let fragment = make_fragment("f1", "svc", "/api");
        let result = make_error_fragment_result(&fragment, "connection refused");
        match result {
            FragmentResult::Error { name, error, .. } => {
                assert_eq!(name, "f1");
                assert_eq!(error, "connection refused");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // --- compose ---

    #[test]
    fn compose_all_ok() {
        let spec = make_spec(
            "agg",
            vec![
                make_fragment("user", "user-svc", "/users/1"),
                make_fragment("orders", "order-svc", "/orders"),
            ],
        );

        let results = vec![
            FragmentResult::Ok {
                value: serde_json::json!({"id": 1, "name": "alice"}),
                name: "user".to_string(),
                target_field: "user".to_string(),
            },
            FragmentResult::Ok {
                value: serde_json::json!([{"id": 101}, {"id": 102}]),
                name: "orders".to_string(),
                target_field: "orders".to_string(),
            },
        ];

        match compose(&spec, &results) {
            ComposeResult::Ok { response, warnings } => {
                assert!(warnings.is_empty());
                assert_eq!(
                    response,
                    serde_json::json!({
                        "user": {"id": 1, "name": "alice"},
                        "orders": [{"id": 101}, {"id": 102}]
                    })
                );
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn compose_fail_open_skips_fragment() {
        let spec = make_spec(
            "agg",
            vec![
                make_fragment("user", "user-svc", "/users/1"),
                make_fragment("orders", "order-svc", "/orders"),
            ],
        );

        let results = vec![
            FragmentResult::Ok {
                value: serde_json::json!({"id": 1, "name": "alice"}),
                name: "user".to_string(),
                target_field: "user".to_string(),
            },
            FragmentResult::Error {
                name: "orders".to_string(),
                error: "connection refused".to_string(),
                fail_policy: FailPolicy::FailOpen,
            },
        ];

        match compose(&spec, &results) {
            ComposeResult::Ok { response, warnings } => {
                assert_eq!(warnings.len(), 1);
                assert!(warnings[0].contains("fail-open"));
                // The orders field is omitted.
                assert!(response.get("orders").is_none());
                assert!(response.get("user").is_some());
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn compose_fail_closed_returns_error() {
        let mut f1 = make_fragment("user", "user-svc", "/users/1");
        f1.fail_policy = FailPolicy::FailClosed;
        let spec = make_spec(
            "agg",
            vec![f1, make_fragment("orders", "order-svc", "/orders")],
        );

        let results = vec![
            FragmentResult::Ok {
                value: serde_json::json!({"id": 1, "name": "alice"}),
                name: "user".to_string(),
                target_field: "user".to_string(),
            },
            FragmentResult::Error {
                name: "orders".to_string(),
                error: "connection refused".to_string(),
                fail_policy: FailPolicy::FailClosed,
            },
        ];

        match compose(&spec, &results) {
            ComposeResult::Error { error, partial } => {
                assert!(error.contains("fail-closed"));
                assert!(partial.is_some());
                // The partial response contains the user fragment.
                let partial = partial.unwrap();
                assert!(partial.get("user").is_some());
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // --- KrakenD-style: 3 upstreams incl. failure case ---

    #[test]
    fn krantd_style_3_upstreams_with_failure() {
        let mut user_frag = make_fragment("user", "user-svc", "/users/1");
        user_frag.jsonpath = Some("$".to_string());

        let mut profile_frag = make_fragment("profile", "profile-svc", "/profiles/1");
        profile_frag.fail_policy = FailPolicy::FailOpen;

        let mut settings_frag = make_fragment("settings", "settings-svc", "/settings/1");
        settings_frag.fail_policy = FailPolicy::FailOpen;

        let spec = make_spec(
            "user-dashboard",
            vec![user_frag, profile_frag, settings_frag],
        );

        let results = vec![
            FragmentResult::Ok {
                value: serde_json::json!({"id": 1, "name": "alice", "email": "alice@example.com"}),
                name: "user".to_string(),
                target_field: "user".to_string(),
            },
            FragmentResult::Ok {
                value: serde_json::json!({"bio": "Software engineer", "location": "SF"}),
                name: "profile".to_string(),
                target_field: "profile".to_string(),
            },
            // Settings service is down (fail-open).
            FragmentResult::Error {
                name: "settings".to_string(),
                error: "503 service unavailable".to_string(),
                fail_policy: FailPolicy::FailOpen,
            },
        ];

        match compose(&spec, &results) {
            ComposeResult::Ok { response, warnings } => {
                // User and profile are present; settings is omitted.
                assert!(response.get("user").is_some());
                assert!(response.get("profile").is_some());
                assert!(response.get("settings").is_none());

                // There's a warning about the settings failure.
                assert_eq!(warnings.len(), 1);
                assert!(warnings[0].contains("settings"));
                assert!(warnings[0].contains("fail-open"));

                // The composed response has the expected structure.
                assert_eq!(
                    response,
                    serde_json::json!({
                        "user": {"id": 1, "name": "alice", "email": "alice@example.com"},
                        "profile": {"bio": "Software engineer", "location": "SF"}
                    })
                );
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn krantd_style_3_upstreams_all_ok() {
        let spec = make_spec(
            "user-dashboard",
            vec![
                make_fragment("user", "user-svc", "/users/1"),
                make_fragment("profile", "profile-svc", "/profiles/1"),
                make_fragment("settings", "settings-svc", "/settings/1"),
            ],
        );

        let results = vec![
            FragmentResult::Ok {
                value: serde_json::json!({"id": 1, "name": "alice"}),
                name: "user".to_string(),
                target_field: "user".to_string(),
            },
            FragmentResult::Ok {
                value: serde_json::json!({"bio": "Engineer"}),
                name: "profile".to_string(),
                target_field: "profile".to_string(),
            },
            FragmentResult::Ok {
                value: serde_json::json!({"theme": "dark"}),
                name: "settings".to_string(),
                target_field: "settings".to_string(),
            },
        ];

        match compose(&spec, &results) {
            ComposeResult::Ok { response, warnings } => {
                assert!(warnings.is_empty());
                assert_eq!(
                    response,
                    serde_json::json!({
                        "user": {"id": 1, "name": "alice"},
                        "profile": {"bio": "Engineer"},
                        "settings": {"theme": "dark"}
                    })
                );
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn krantd_style_3_upstreams_fail_closed() {
        let mut user_frag = make_fragment("user", "user-svc", "/users/1");
        user_frag.fail_policy = FailPolicy::FailClosed;

        let spec = make_spec(
            "user-dashboard",
            vec![
                user_frag,
                make_fragment("profile", "profile-svc", "/profiles/1"),
                make_fragment("settings", "settings-svc", "/settings/1"),
            ],
        );

        let results = vec![
            FragmentResult::Error {
                name: "user".to_string(),
                error: "connection refused".to_string(),
                fail_policy: FailPolicy::FailClosed,
            },
            FragmentResult::Ok {
                value: serde_json::json!({"bio": "Engineer"}),
                name: "profile".to_string(),
                target_field: "profile".to_string(),
            },
            FragmentResult::Ok {
                value: serde_json::json!({"theme": "dark"}),
                name: "settings".to_string(),
                target_field: "settings".to_string(),
            },
        ];

        match compose(&spec, &results) {
            ComposeResult::Error { error, partial } => {
                assert!(error.contains("user"));
                assert!(error.contains("fail-closed"));
                // Partial response is empty (user failed first).
                assert!(partial.is_some());
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // --- Size caps ---

    #[test]
    fn compose_exceeds_max_response_size() {
        let mut spec = make_spec("agg", vec![make_fragment("f1", "svc", "/api")]);
        spec.max_response_bytes = 10; // Very small.

        let results = vec![FragmentResult::Ok {
            value: serde_json::json!({"data": "this is way too long for the cap"}),
            name: "f1".to_string(),
            target_field: "f1".to_string(),
        }];

        match compose(&spec, &results) {
            ComposeResult::Ok { response, warnings } => {
                // The fragment is skipped due to size.
                assert!(response.get("f1").is_none());
                assert!(warnings.iter().any(|w| w.contains("exceeds max size")));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    // --- FailPolicy defaults ---

    #[test]
    fn fail_policy_default_is_fail_open() {
        assert_eq!(FailPolicy::default(), FailPolicy::FailOpen);
    }

    // --- Serialization ---

    #[test]
    fn spec_serialization() {
        let spec = make_spec("agg", vec![make_fragment("f1", "svc", "/api")]);

        let json = serde_json::to_string(&spec).unwrap();
        let deserialized: AggregationSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, deserialized);
    }

    #[test]
    fn fragment_serialization() {
        let fragment = make_fragment("f1", "svc", "/api");

        let json = serde_json::to_string(&fragment).unwrap();
        let deserialized: FragmentSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(fragment, deserialized);
    }

    #[test]
    fn fail_policy_serialization() {
        assert_eq!(
            serde_json::to_string(&FailPolicy::FailOpen).unwrap(),
            "\"fail_open\""
        );
        assert_eq!(
            serde_json::to_string(&FailPolicy::FailClosed).unwrap(),
            "\"fail_closed\""
        );
    }
}
