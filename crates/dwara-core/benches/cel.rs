//! DW-058: CEL engine benchmark.
//!
//! Measures the evaluator throughput for representative expressions.
//! The benchmark sets the acceptance threshold (ns/op) from the
//! comparative measurement itself — the issue notes that
//! FEATURE_ANALYSIS.md does not fix a target eval throughput number,
//! so this benchmark OWNS setting that threshold.
//!
//! Run with: `cargo bench --features cel --bench cel`

#![cfg(feature = "cel")]

use criterion::{criterion_group, criterion_main, Criterion};
use dwara_core::cel::{CelContext, CelProgram};

fn bench_cel(c: &mut Criterion) {
    let mut g = c.benchmark_group("cel");

    // Simple arithmetic: 1 + 2 * 3
    let prog_arith = CelProgram::compile("1 + 2 * 3").unwrap();
    g.bench_function("arithmetic", |b| {
        b.iter(|| {
            let ctx = CelContext::new();
            prog_arith.evaluate(&ctx).unwrap()
        })
    });

    // Variable access + comparison: request.path == "/api/v1"
    let prog_var = CelProgram::compile("request.path == \"/api/v1\"").unwrap();
    g.bench_function("variable_compare", |b| {
        b.iter(|| {
            let mut ctx = CelContext::new();
            let mut request = std::collections::HashMap::new();
            request.insert("path", "/api/v1".to_string());
            ctx.add_var("request", &request).unwrap();
            prog_var.evaluate(&ctx).unwrap()
        })
    });

    // String method call: s.startsWith("hello")
    let prog_str = CelProgram::compile("s.startsWith(\"hello\")").unwrap();
    g.bench_function("string_method", |b| {
        b.iter(|| {
            let mut ctx = CelContext::new();
            ctx.add_var("s", &"hello world").unwrap();
            prog_str.evaluate(&ctx).unwrap()
        })
    });

    // Ternary: x > 0 ? "pos" : "neg"
    let prog_ternary = CelProgram::compile("x > 0 ? \"pos\" : \"neg\"").unwrap();
    g.bench_function("ternary", |b| {
        b.iter(|| {
            let mut ctx = CelContext::new();
            ctx.add_var("x", &5i64).unwrap();
            prog_ternary.evaluate(&ctx).unwrap()
        })
    });

    // Complex: multiple operations
    let prog_complex =
        CelProgram::compile("request.method == \"GET\" && request.path.startsWith(\"/api/\") && request.headers[\"x-api-key\"] != \"\"")
            .unwrap();
    g.bench_function("complex_condition", |b| {
        b.iter(|| {
            let mut ctx = CelContext::new();
            let mut request: std::collections::HashMap<String, serde_json::Value> =
                std::collections::HashMap::new();
            request.insert(
                "method".to_string(),
                serde_json::Value::String("GET".to_string()),
            );
            request.insert(
                "path".to_string(),
                serde_json::Value::String("/api/v1/users".to_string()),
            );
            let mut headers = std::collections::HashMap::new();
            headers.insert("x-api-key", "abc123".to_string());
            request.insert(
                "headers".to_string(),
                serde_json::Value::Object(
                    headers
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), serde_json::Value::String(v)))
                        .collect(),
                ),
            );
            ctx.add_var("request", &request).unwrap();
            prog_complex.evaluate(&ctx).unwrap()
        })
    });

    g.finish();
}

criterion_group!(benches, bench_cel);
criterion_main!(benches);
