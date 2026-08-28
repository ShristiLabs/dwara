//! Unit tests for the transforms grammar and runtime helpers (DW-028):
//! the JSON-Pointer grammar (`config::transforms::JsonPointer`), the
//! compiled op application, header/query ops, security-header
//! injection, and the media-type gate. The full request/response
//! pipeline is exercised by the `transforms` integration suite.

use std::collections::BTreeMap;

use dwara_core::config::transforms::{
    is_forbidden_request_header, is_forbidden_response_header, is_json_media_type,
    CompiledJsonTransform, FrameOptions, HeaderOps, JsonBodyTransform, JsonOp, JsonPointer,
    JsonTransformError, QueryOps, SecurityHeaders,
};
use dwara_core::dataplane::transforms::{
    apply_header_ops, apply_query_ops, apply_security_headers, media_type,
};
use hyper::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use hyper::Uri;

fn ops(list: Vec<JsonOp>) -> CompiledJsonTransform {
    CompiledJsonTransform::compile(&JsonBodyTransform {
        max_bytes: 1024,
        ops: list,
    })
}

fn doc(json: &str) -> serde_json::Value {
    serde_json::from_str(json).unwrap()
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// --- JSON Pointer grammar -----------------------------------------------

#[test]
fn pointer_parses_root_object_and_array_paths() {
    assert!(JsonPointer::parse("").unwrap().is_root());
    let p = JsonPointer::parse("/meta/via").unwrap();
    assert_eq!(p.tokens(), ["meta", "via"]);
    let p = JsonPointer::parse("/items/0/id").unwrap();
    assert_eq!(p.tokens(), ["items", "0", "id"]);
    assert!(!p.is_root());
}

#[test]
fn pointer_unescapes_the_two_rfc_escapes_and_rejects_others() {
    let p = JsonPointer::parse("/a~1b~0c").unwrap();
    assert_eq!(p.tokens(), ["a/b~c"]);
    assert!(JsonPointer::parse("no-slash").is_none());
    assert!(JsonPointer::parse("/a~2b").is_none());
    assert!(JsonPointer::parse("/x/~").is_none());
}

#[test]
fn pointer_array_index_discipline_follows_rfc_6902() {
    // Digits without leading zeros address arrays; everything else is an
    // object key only ("01", "-", "1e3", overflow).
    let p = JsonPointer::parse("/10").unwrap();
    assert_eq!(p.tokens(), ["10"]);
    for key_only in ["/01", "/-", "/1e3", "/99999999999999999999999999"] {
        let p = JsonPointer::parse(key_only).unwrap();
        assert_eq!(p.tokens().len(), 1, "{key_only} parses as one token");
        // Applied to an ARRAY it must be unresolved (not an index).
        let mut arr = doc("[0, 1, 2]");
        let r = ops(vec![JsonOp::Remove {
            path: key_only.to_string(),
        }])
        .apply(&mut arr);
        assert!(
            matches!(r, Err(JsonTransformError::Unresolved { .. })),
            "{key_only} on an array is unresolved"
        );
    }
}

// --- Compiled ops application -------------------------------------------

#[test]
fn set_creates_replaces_in_objects_and_arrays() {
    let mut d = doc(r#"{"meta":{},"items":[{"id":1}]}"#);
    ops(vec![
        JsonOp::Set {
            path: "/meta/via".into(),
            value: "dwara".into(),
        },
        JsonOp::Set {
            path: "/items/0/id".into(),
            value: 42.into(),
        },
        JsonOp::Set {
            path: "/meta/via".into(),
            value: "dwara-2".into(),
        },
    ])
    .apply(&mut d)
    .unwrap();
    assert_eq!(d["meta"]["via"], "dwara-2");
    assert_eq!(d["items"][0]["id"], 42);
}

#[test]
fn set_at_root_replaces_the_whole_document() {
    let mut d = doc(r#"{"a":1}"#);
    ops(vec![JsonOp::Set {
        path: "".into(),
        value: doc(r#"{"b":[1,2]}"#),
    }])
    .apply(&mut d)
    .unwrap();
    assert_eq!(d, doc(r#"{"b":[1,2]}"#));
}

#[test]
fn set_into_array_rejects_append_and_out_of_bounds() {
    // RFC 6901 has no append token; index == len is out of bounds for
    // replace. Both are unresolved (strict failure, not a silent skip).
    for path in ["/items/1", "/items/9"] {
        let mut d = doc(r#"{"items":[0]}"#);
        let r = ops(vec![JsonOp::Set {
            path: path.into(),
            value: 1.into(),
        }])
        .apply(&mut d);
        assert!(
            matches!(r, Err(JsonTransformError::Unresolved { .. })),
            "{path}"
        );
    }
}

#[test]
fn remove_deletes_keys_and_elements_and_fails_strict_on_misses() {
    let mut d = doc(r#"{"a":1,"keep":2}"#);
    ops(vec![JsonOp::Remove { path: "/a".into() }])
        .apply(&mut d)
        .unwrap();
    assert_eq!(d, doc(r#"{"keep":2}"#));

    let mut d = doc(r#"{"items":[1,2,3]}"#);
    ops(vec![JsonOp::Remove {
        path: "/items/1".into(),
    }])
    .apply(&mut d)
    .unwrap();
    assert_eq!(d, doc(r#"{"items":[1,3]}"#));

    // A miss (absent key, absent parent, scalar parent) is an ERROR:
    // in the remove direction a silent miss is a data leak.
    for path in ["/absent", "/no/such/parent", "/keep/deeper"] {
        let mut d = doc(r#"{"keep":2}"#);
        let r = ops(vec![JsonOp::Remove { path: path.into() }]).apply(&mut d);
        assert!(
            matches!(&r, Err(JsonTransformError::Unresolved { path: got }) if got == path),
            "{path}: {r:?}"
        );
    }
}

#[test]
fn ops_apply_sequentially_each_seeing_the_prior_result() {
    // remove /list/0 then set /list/0/x: the set lands on the element
    // that MOVED into position 0 after the removal.
    let mut d = doc(r#"{"list":[{"x":1},{"x":2}]}"#);
    ops(vec![
        JsonOp::Remove {
            path: "/list/0".into(),
        },
        JsonOp::Set {
            path: "/list/0/x".into(),
            value: 9.into(),
        },
    ])
    .apply(&mut d)
    .unwrap();
    assert_eq!(d, doc(r#"{"list":[{"x":9}]}"#));
}

#[test]
fn escaped_tokens_address_keys_with_slashes_and_tildes() {
    let mut d = doc(r#"{"a/b":{"c~d":1}}"#);
    ops(vec![JsonOp::Remove {
        path: "/a~1b/c~0d".into(),
    }])
    .apply(&mut d)
    .unwrap();
    assert_eq!(d, doc(r#"{"a/b":{}}"#));
}

#[test]
fn object_key_zero_is_not_an_array_confusion() {
    // On an OBJECT the token "0" is the key "0" (RFC 6901).
    let mut d = doc(r#"{"0":"zero"}"#);
    ops(vec![JsonOp::Remove { path: "/0".into() }])
        .apply(&mut d)
        .unwrap();
    assert_eq!(d, doc("{}"));
}

// --- Media-type gate ------------------------------------------------------

#[test]
fn json_media_type_is_application_json_and_the_plus_json_family() {
    assert!(is_json_media_type("application/json"));
    assert!(is_json_media_type("application/vnd.acme.v2+json"));
    assert!(!is_json_media_type("text/json"));
    assert!(!is_json_media_type("application/jsonp"));
    assert!(!is_json_media_type("application/xml"));
    assert!(!is_json_media_type("json"));
}

#[test]
fn media_type_extraction_strips_parameters_and_lowercases() {
    let mut h = HeaderMap::new();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("Application/JSON; charset=utf-8"),
    );
    assert_eq!(media_type(&h).as_deref(), Some("application/json"));
    h.remove(CONTENT_TYPE);
    assert_eq!(media_type(&h), None);
}

// --- Header ops -----------------------------------------------------------

#[test]
fn header_ops_apply_in_the_frozen_set_add_rename_remove_order() {
    let mut h = HeaderMap::new();
    h.append("x-old", HeaderValue::from_static("1"));
    h.append("x-old", HeaderValue::from_static("2"));
    h.append("x-keep", HeaderValue::from_static("k"));
    let op = HeaderOps {
        set: map(&[("x-set", "s1"), ("x-old", "replaced")]),
        add: map(&[("x-keep", "k2")]),
        remove: vec!["x-gone".into()],
        rename: map(&[("x-old", "x-new")]),
    };
    apply_header_ops(&mut h, &op);
    // set replaced every x-old value BEFORE rename moved it: the rename
    // then relabeled that single value.
    assert_eq!(h.get_all("x-old").iter().count(), 0);
    assert_eq!(h.get_all("x-new").iter().count(), 1);
    assert_eq!(h.get("x-new").unwrap(), "replaced");
    assert_eq!(h.get("x-set").unwrap(), "s1");
    // add appended after the existing value
    let keep: Vec<_> = h.get_all("x-keep").iter().collect();
    assert_eq!(keep.len(), 2);
    assert_eq!(keep[0], "k");
    assert_eq!(keep[1], "k2");
    // remove of an absent header is a no-op
    assert!(h.get("x-gone").is_none());
}

#[test]
fn header_rename_moves_every_value_and_remove_strips_all() {
    let mut h = HeaderMap::new();
    h.append("a", HeaderValue::from_static("1"));
    h.append("a", HeaderValue::from_static("2"));
    h.append("b", HeaderValue::from_static("3"));
    let op = HeaderOps {
        set: BTreeMap::new(),
        add: BTreeMap::new(),
        remove: vec!["b".into()],
        rename: map(&[("a", "c")]),
    };
    apply_header_ops(&mut h, &op);
    assert_eq!(h.get_all("a").iter().count(), 0);
    let c: Vec<_> = h.get_all("c").iter().collect();
    assert_eq!(c.len(), 2);
    assert_eq!(c[0], "1");
    assert_eq!(c[1], "2");
    assert!(h.get("b").is_none());
}

// --- Query ops ------------------------------------------------------------

#[test]
fn query_ops_rename_in_place_remove_and_append_set_add() {
    let uri: Uri = "http://x/api?uid=7&keep=%2Fpath&z=1&drop=9"
        .parse()
        .unwrap();
    let op = QueryOps {
        set: map(&[("region", "us-east")]),
        add: map(&[("source", "gw")]),
        remove: vec!["drop".into()],
        rename: map(&[("uid", "user_id")]),
    };
    let new = apply_query_ops(&uri, &op).unwrap();
    assert_eq!(
        new.query().unwrap(),
        "user_id=7&keep=%2Fpath&z=1&region=us-east&source=gw",
        "renamed pair keeps position and raw value; set/add append at the end"
    );
    assert_eq!(new.path(), "/api");
}

#[test]
fn query_ops_preserve_untouched_bytes_exactly_and_report_no_op() {
    // Raw spelling of untouched pairs survives (%2f lowercase stays); a
    // no-op op set returns None so the caller keeps the original Uri.
    let uri: Uri = "http://x/p?a=%2f&b=1".parse().unwrap();
    let op = QueryOps {
        set: BTreeMap::new(),
        add: BTreeMap::new(),
        remove: vec![],
        rename: map(&[("c", "d")]), // absent key: no-op rename
    };
    assert!(apply_query_ops(&uri, &op).is_none());

    let op = QueryOps {
        set: BTreeMap::new(),
        add: BTreeMap::new(),
        remove: vec!["b".into()],
        rename: BTreeMap::new(),
    };
    let new = apply_query_ops(&uri, &op).unwrap();
    assert_eq!(
        new.query().unwrap(),
        "a=%2f",
        "untouched raw bytes preserved"
    );
}

#[test]
fn query_ops_encode_new_values_and_build_from_nothing() {
    let uri: Uri = "http://x/p".parse().unwrap();
    let op = QueryOps {
        set: map(&[("q", "a b&c=d")]),
        add: BTreeMap::new(),
        remove: vec![],
        rename: BTreeMap::new(),
    };
    let new = apply_query_ops(&uri, &op).unwrap();
    assert_eq!(new.query().unwrap(), "q=a%20b%26c%3Dd");
}

#[test]
fn query_ops_set_replaces_every_pair_and_full_removal_empties_the_query() {
    let uri: Uri = "http://x/p?a=1&a=2&b=3".parse().unwrap();
    let op = QueryOps {
        set: map(&[("a", "one")]),
        add: BTreeMap::new(),
        remove: vec![],
        rename: BTreeMap::new(),
    };
    let new = apply_query_ops(&uri, &op).unwrap();
    assert_eq!(new.query().unwrap(), "b=3&a=one");

    let op = QueryOps {
        set: BTreeMap::new(),
        add: BTreeMap::new(),
        remove: vec!["a".into(), "b".into()],
        rename: BTreeMap::new(),
    };
    let new = apply_query_ops(&uri, &op).unwrap();
    assert_eq!(new.query(), None, "everything removed: no query at all");
}

// --- Security headers -----------------------------------------------------

fn sh(pairs: &[(&str, &str)], flags: (&bool, &bool)) -> SecurityHeaders {
    SecurityHeaders {
        hsts_max_age_secs: pairs
            .iter()
            .find(|(k, _)| *k == "hsts")
            .and_then(|(_, v)| v.parse().ok()),
        hsts_include_subdomains: *flags.0,
        hsts_preload: *flags.1,
        nosniff: pairs.iter().any(|(k, _)| *k == "nosniff"),
        content_security_policy: pairs
            .iter()
            .find(|(k, _)| *k == "csp")
            .map(|(_, v)| v.to_string()),
        frame_options: pairs
            .iter()
            .find(|(k, _)| *k == "frame")
            .map(|(_, v)| match *v {
                "deny" => FrameOptions::Deny,
                _ => FrameOptions::Sameorigin,
            }),
    }
}

#[test]
fn security_headers_emit_each_field_and_replace_upstream_values() {
    let mut h = HeaderMap::new();
    h.insert(
        hyper::header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=1"),
    );
    h.insert(
        hyper::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("stale"),
    );
    apply_security_headers(
        &mut h,
        &sh(
            &[
                ("hsts", "31536000"),
                ("nosniff", ""),
                ("csp", "default-src 'self'"),
                ("frame", "deny"),
            ],
            (&true, &true),
        ),
    );
    assert_eq!(
        h.get(hyper::header::STRICT_TRANSPORT_SECURITY).unwrap(),
        "max-age=31536000; includeSubDomains; preload"
    );
    assert_eq!(
        h.get(hyper::header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(
        h.get(hyper::header::CONTENT_SECURITY_POLICY).unwrap(),
        "default-src 'self'"
    );
    assert_eq!(h.get(hyper::header::X_FRAME_OPTIONS).unwrap(), "DENY");

    // Sameorigin spelling + plain HSTS (no directives)
    let mut h = HeaderMap::new();
    apply_security_headers(
        &mut h,
        &sh(&[("hsts", "60"), ("frame", "sameorigin")], (&false, &false)),
    );
    assert_eq!(
        h.get(hyper::header::STRICT_TRANSPORT_SECURITY).unwrap(),
        "max-age=60"
    );
    assert_eq!(h.get(hyper::header::X_FRAME_OPTIONS).unwrap(), "SAMEORIGIN");
}

#[test]
fn security_headers_absent_fields_leave_headers_alone() {
    let mut h = HeaderMap::new();
    h.insert(
        hyper::header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=1"),
    );
    apply_security_headers(&mut h, &sh(&[("nosniff", "")], (&false, &false)));
    // No hsts configured: the upstream value stands (the route did not
    // opt into HSTS policy).
    assert_eq!(
        h.get(hyper::header::STRICT_TRANSPORT_SECURITY).unwrap(),
        "max-age=1"
    );
}

// --- Forbidden header lists ----------------------------------------------

#[test]
fn forbidden_header_lists_cover_framing_and_hop_by_hop() {
    // host is REQUEST-side only: the gateway names the origin it dials
    // (a request-side concern); it never emits a Host to the client.
    assert!(is_forbidden_request_header("host"));
    assert!(!is_forbidden_response_header("host"));
    for name in [
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
        "proxy-connection",
    ] {
        assert!(is_forbidden_request_header(name), "{name} request-side");
        assert!(is_forbidden_response_header(name), "{name} response-side");
    }
    // Response-only addition: content-encoding belongs to the
    // compression pipeline.
    assert!(!is_forbidden_request_header("content-encoding"));
    assert!(is_forbidden_response_header("content-encoding"));
    // Case-insensitive.
    assert!(is_forbidden_request_header("Content-Length"));
    // Ordinary headers are untouched.
    assert!(!is_forbidden_request_header("x-custom"));
    assert!(!is_forbidden_response_header("x-custom"));
}
