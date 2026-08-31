//! Unit tests for `aggregation` (relocated from src).

#![cfg(feature = "aggregation")]

use dwara_core::aggregation::{
    compose, extract_jsonpath, make_error_fragment_result, make_fragment_result, shape_fragment,
    validate_spec, AggregationSpec, ComposeResult, FailPolicy, FragmentResult, FragmentSpec,
};
use serde_json::Value;

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
