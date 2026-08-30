//! Unit tests for the WAF-lite pattern matching engine (DW-051).
//!
//! Tests the individual patterns, edge cases, and encoding variants
//! against the [`crate::dataplane::waf::WafGeneration`] engine directly
//! (no HTTP, no server) — the integration suite (`tests/waf.rs`) covers
//! the end-to-end request path.

use dwara_core::config::RouteWaf;
use dwara_core::dataplane::waf::{WafFilter, WafGeneration, WafTarget};

fn waf_all() -> WafGeneration {
    let cfg = RouteWaf {
        enabled: true,
        dry_run: false,
        filters: vec![],
        max_body_inspect_bytes: 131_072,
        custom_patterns: vec![],
    };
    WafGeneration::from_config(&cfg).expect("enabled WAF builds a generation")
}

fn waf_filters(filters: &[&str]) -> WafGeneration {
    let cfg = RouteWaf {
        enabled: true,
        dry_run: false,
        filters: filters.iter().map(|s| s.to_string()).collect(),
        max_body_inspect_bytes: 131_072,
        custom_patterns: vec![],
    };
    WafGeneration::from_config(&cfg).expect("enabled WAF builds a generation")
}

fn waf_custom(patterns: &[&str]) -> WafGeneration {
    let cfg = RouteWaf {
        enabled: true,
        dry_run: false,
        filters: vec![],
        max_body_inspect_bytes: 131_072,
        custom_patterns: patterns.iter().map(|s| s.to_string()).collect(),
    };
    WafGeneration::from_config(&cfg).expect("enabled WAF builds a generation")
}

fn empty_headers() -> hyper::HeaderMap {
    hyper::HeaderMap::new()
}

// ---------------------------------------------------------------------------
// SQLi patterns
// ---------------------------------------------------------------------------

#[test]
fn sqli_union_select_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head(
            "/api/users",
            Some("id=1 UNION SELECT * FROM users"),
            &empty_headers(),
        )
        .expect("UNION SELECT should match");
    assert_eq!(m.filter, WafFilter::Sqli);
    assert_eq!(m.target, WafTarget::Query);
}

#[test]
fn sqli_or_1_eq_1_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api", Some("id=1' OR 1=1--"), &empty_headers())
        .expect("OR 1=1 should match");
    assert_eq!(m.filter, WafFilter::Sqli);
}

#[test]
fn sqli_drop_table_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api", Some("q=';DROP TABLE users--"), &empty_headers())
        .expect("DROP TABLE should match");
    assert_eq!(m.filter, WafFilter::Sqli);
}

#[test]
fn sqli_stacked_query_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head(
            "/api",
            Some("id=1; SELECT * FROM passwords"),
            &empty_headers(),
        )
        .expect("stacked query should match");
    assert_eq!(m.filter, WafFilter::Sqli);
}

#[test]
fn sqli_xp_cmdshell_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api", Some("cmd=xp_cmdshell('dir')"), &empty_headers())
        .expect("xp_cmdshell should match");
    assert_eq!(m.filter, WafFilter::Sqli);
}

#[test]
fn sqli_hex_encoded_keyword_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api", Some("data=0x44415441424153"), &empty_headers())
        .expect("hex-encoded keyword should match");
    assert_eq!(m.filter, WafFilter::Sqli);
}

#[test]
fn sqli_sleep_benchmark_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api", Some("id=SLEEP(5)"), &empty_headers())
        .expect("SLEEP() should match");
    assert_eq!(m.filter, WafFilter::Sqli);
}

#[test]
fn sqli_case_insensitive() {
    let gen = waf_all();
    let m = gen
        .inspect_head(
            "/api",
            Some("id=1 union select * from users"),
            &empty_headers(),
        )
        .expect("lowercase union select should match");
    assert_eq!(m.filter, WafFilter::Sqli);
}

// ---------------------------------------------------------------------------
// XSS patterns
// ---------------------------------------------------------------------------

#[test]
fn xss_script_tag_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head(
            "/api",
            Some("q=<script>alert(1)</script>"),
            &empty_headers(),
        )
        .expect("script tag should match");
    assert_eq!(m.filter, WafFilter::Xss);
    assert_eq!(m.target, WafTarget::Query);
}

#[test]
fn xss_javascript_protocol_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api", Some("url=javascript:alert(1)"), &empty_headers())
        .expect("javascript: protocol should match");
    assert_eq!(m.filter, WafFilter::Xss);
}

#[test]
fn xss_onerror_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head(
            "/api",
            Some("img=<img src=x onerror=alert(1)>"),
            &empty_headers(),
        )
        .expect("onerror= should match");
    assert_eq!(m.filter, WafFilter::Xss);
}

#[test]
fn xss_iframe_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head(
            "/api",
            Some("embed=<iframe src=evil></iframe>"),
            &empty_headers(),
        )
        .expect("iframe should match");
    assert_eq!(m.filter, WafFilter::Xss);
}

#[test]
fn xss_document_cookie_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api", Some("steal=document.cookie"), &empty_headers())
        .expect("document.cookie should match");
    assert_eq!(m.filter, WafFilter::Xss);
}

#[test]
fn xss_eval_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api", Some("run=eval('malicious')"), &empty_headers())
        .expect("eval() should match");
    assert_eq!(m.filter, WafFilter::Xss);
}

#[test]
fn xss_html_entity_encoded_variant() {
    let gen = waf_all();
    let m = gen
        .inspect_head(
            "/api",
            Some("q=&lt;script&gt;alert(1)&lt;/script&gt;"),
            &empty_headers(),
        )
        .expect("HTML entity-encoded script should match");
    assert_eq!(m.filter, WafFilter::Xss);
}

#[test]
fn xss_svg_onload_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api", Some("q=<svg onload=alert(1)>"), &empty_headers())
        .expect("svg onload should match");
    assert_eq!(m.filter, WafFilter::Xss);
}

// ---------------------------------------------------------------------------
// Path traversal patterns
// ---------------------------------------------------------------------------

#[test]
fn path_traversal_dot_dot_slash_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api/../../etc/passwd", None, &empty_headers())
        .expect("../ should match");
    assert_eq!(m.filter, WafFilter::PathTraversal);
    assert_eq!(m.target, WafTarget::Path);
}

#[test]
fn path_traversal_backslash_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api", Some("file=..\\..\\windows"), &empty_headers())
        .expect("..\\ should match");
    assert_eq!(m.filter, WafFilter::PathTraversal);
}

#[test]
fn path_traversal_url_encoded_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head(
            "/api",
            Some("file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
            &empty_headers(),
        )
        .expect("URL-encoded ../ should match");
    assert_eq!(m.filter, WafFilter::PathTraversal);
}

#[test]
fn path_traversal_double_url_encoded_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api", Some("file=%252e%252e%252f"), &empty_headers())
        .expect("double URL-encoded ../ should match");
    assert_eq!(m.filter, WafFilter::PathTraversal);
}

#[test]
fn path_traversal_null_byte_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api", Some("file=legit.txt%00.exe"), &empty_headers())
        .expect("null byte injection should match");
    assert_eq!(m.filter, WafFilter::PathTraversal);
}

#[test]
fn path_traversal_etc_passwd_detected() {
    let gen = waf_all();
    let m = gen
        .inspect_head("/api", Some("file=/etc/passwd"), &empty_headers())
        .expect("/etc/passwd should match");
    assert_eq!(m.filter, WafFilter::PathTraversal);
}

// ---------------------------------------------------------------------------
// Header inspection
// ---------------------------------------------------------------------------

#[test]
fn header_sqli_in_user_agent_detected() {
    let gen = waf_all();
    let mut headers = hyper::HeaderMap::new();
    headers.insert("user-agent", "Bot' OR 1=1--".parse().unwrap());
    let m = gen
        .inspect_head("/api", None, &headers)
        .expect("SQLi in User-Agent should match");
    assert_eq!(m.filter, WafFilter::Sqli);
    assert_eq!(m.target, WafTarget::Header);
}

#[test]
fn header_xss_in_referer_detected() {
    let gen = waf_all();
    let mut headers = hyper::HeaderMap::new();
    headers.insert("referer", "https://evil.com/<script>".parse().unwrap());
    let m = gen
        .inspect_head("/api", None, &headers)
        .expect("XSS in Referer should match");
    assert_eq!(m.filter, WafFilter::Xss);
    assert_eq!(m.target, WafTarget::Header);
}

#[test]
fn header_path_traversal_in_xff_detected() {
    let gen = waf_all();
    let mut headers = hyper::HeaderMap::new();
    headers.insert("x-forwarded-for", "../../etc/passwd".parse().unwrap());
    let m = gen
        .inspect_head("/api", None, &headers)
        .expect("path traversal in X-Forwarded-For should match");
    assert_eq!(m.filter, WafFilter::PathTraversal);
    assert_eq!(m.target, WafTarget::Header);
}

// ---------------------------------------------------------------------------
// Filter selection
// ---------------------------------------------------------------------------

#[test]
fn filter_selection_sqli_only_skips_xss() {
    let gen = waf_filters(&["sqli"]);
    let m = gen.inspect_head(
        "/api",
        Some("q=<script>alert(1)</script>"),
        &empty_headers(),
    );
    assert!(m.is_none(), "XSS payload should not match sqli-only filter");
}

#[test]
fn filter_selection_xss_only_catches_xss() {
    let gen = waf_filters(&["xss"]);
    let m = gen
        .inspect_head(
            "/api",
            Some("q=<script>alert(1)</script>"),
            &empty_headers(),
        )
        .expect("XSS payload should match xss filter");
    assert_eq!(m.filter, WafFilter::Xss);
}

#[test]
fn filter_selection_path_traversal_only_skips_sqli() {
    let gen = waf_filters(&["path_traversal"]);
    let m = gen.inspect_head("/api", Some("id=1' OR 1=1--"), &empty_headers());
    assert!(
        m.is_none(),
        "SQLi payload should not match path_traversal-only filter"
    );
}

// ---------------------------------------------------------------------------
// Custom patterns
// ---------------------------------------------------------------------------

#[test]
fn custom_pattern_detected() {
    let gen = waf_custom(&[r"(?i)malicious_payload_\d+"]);
    let m = gen
        .inspect_head("/api", Some("data=malicious_payload_42"), &empty_headers())
        .expect("custom pattern should match");
    // Custom patterns are appended to every enabled filter; the first
    // filter (sqli) will match since the custom pattern is checked
    // after the built-in sqli patterns.
    assert_eq!(m.filter, WafFilter::Sqli);
}

// ---------------------------------------------------------------------------
// Disabled WAF
// ---------------------------------------------------------------------------

#[test]
fn disabled_waf_produces_no_generation() {
    let cfg = RouteWaf {
        enabled: false,
        dry_run: false,
        filters: vec![],
        max_body_inspect_bytes: 131_072,
        custom_patterns: vec![],
    };
    assert!(WafGeneration::from_config(&cfg).is_none());
}

// ---------------------------------------------------------------------------
// Body inspection
// ---------------------------------------------------------------------------

#[test]
fn body_slice_sqli_detected() {
    let gen = waf_all();
    let body = br#"{"id":"1' OR 1=1--"}"#;
    let m = gen
        .inspect_body_slice(body)
        .expect("SQLi in body should match");
    assert_eq!(m.filter, WafFilter::Sqli);
    assert_eq!(m.target, WafTarget::Body);
}

#[test]
fn body_slice_xss_detected() {
    let gen = waf_all();
    let body = br#"{"comment":"<script>alert(1)</script>"}"#;
    let m = gen
        .inspect_body_slice(body)
        .expect("XSS in body should match");
    assert_eq!(m.filter, WafFilter::Xss);
    assert_eq!(m.target, WafTarget::Body);
}

#[test]
fn body_slice_clean_no_match() {
    let gen = waf_all();
    let body = br#"{"name":"John Doe","email":"john@example.com"}"#;
    assert!(gen.inspect_body_slice(body).is_none());
}

// ---------------------------------------------------------------------------
// Value preview truncation
// ---------------------------------------------------------------------------

#[test]
fn value_preview_truncated_to_64_chars() {
    let gen = waf_all();
    let long_payload = &format!("id={}", "a".repeat(200));
    let m = gen
        .inspect_head(
            "/api",
            Some(&format!("{}' OR 1=1--", long_payload)),
            &empty_headers(),
        )
        .expect("long SQLi payload should match");
    assert!(m.value_preview.len() <= 67); // 64 chars + "..."
    assert!(m.value_preview.ends_with("..."));
}

// ---------------------------------------------------------------------------
// False positive battery (legitimate requests that must NOT match)
// ---------------------------------------------------------------------------

#[test]
fn no_false_positives_on_legitimate_requests() {
    let gen = waf_all();
    let legit: &[(&str, Option<&str>)] = &[
        ("/api/users", Some("page=1&limit=20")),
        ("/api/users/123", Some("fields=name,email")),
        ("/api/search", Some("q=hello+world&sort=relevance")),
        (
            "/api/products",
            Some("category=electronics&min_price=10&max_price=500"),
        ),
        (
            "/api/orders",
            Some("status=pending&from=2024-01-01&to=2024-12-31"),
        ),
        ("/api/profile", Some("user=john_doe")),
        ("/api/blog/posts", Some("tag=rust&tag=programming")),
        ("/api/geo", Some("lat=37.7749&lng=-122.4194")),
        ("/api/translate", Some("text=Hello&from=en&to=es")),
        ("/api/upload", Some("filename=report.pdf&size=1024")),
        ("/api/calc", Some("expr=2+2*3-1")),
        ("/api/lookup", Some("key=abc123def456")),
        ("/api/config", Some("env=production&debug=false")),
        ("/api/health", Some("check=all")),
        ("/api/metrics", Some("interval=60s&format=prometheus")),
        ("/api/v2/users", Some("expand=profile,settings")),
        ("/api/v1/items", Some("cursor=eyJpZCI6MTIzfQ&limit=50")),
        ("/api/reports", Some("type=summary&year=2024")),
        ("/api/notifications", Some("unread=true&limit=10")),
        ("/api/cart", Some("item_id=42&quantity=3")),
        ("/api/checkout", Some("payment_method=card&currency=usd")),
        ("/api/feedback", Some("rating=5&comment=Great+service")),
    ];
    for (path, query) in legit {
        assert!(
            gen.inspect_head(path, *query, &empty_headers()).is_none(),
            "false positive on path={path} query={query:?}"
        );
    }
}

#[test]
fn no_false_positive_on_normal_headers() {
    let gen = waf_all();
    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        "user-agent",
        "Mozilla/5.0 (compatible; Bot/1.0)".parse().unwrap(),
    );
    headers.insert("referer", "https://example.com/page".parse().unwrap());
    headers.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
    assert!(gen.inspect_head("/api", None, &headers).is_none());
}
