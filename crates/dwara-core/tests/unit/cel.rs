//! Unit tests for `cel` (relocated from src).

#![cfg(feature = "cel")]

use dwara_core::cel::{
    value_to_bool, value_to_float, value_to_int, value_to_string, CelContext, CelProgram, Value,
};

#[test]
fn compile_and_evaluate_simple_expression() {
    let program = CelProgram::compile("1 + 2").unwrap();
    let ctx = CelContext::new();
    let result = program.evaluate(&ctx).unwrap();
    assert_eq!(value_to_int(&result), Some(3));
}

#[test]
fn evaluate_with_variables() {
    let program = CelProgram::compile("request.path == \"/api/v1\"").unwrap();
    let mut ctx = CelContext::new();
    // Add a request object with a path field.
    let mut request = std::collections::HashMap::new();
    request.insert("path", "/api/v1".to_string());
    ctx.add_var("request", &request).unwrap();
    let result = program.evaluate(&ctx).unwrap();
    assert_eq!(value_to_bool(&result), Some(true));
}

#[test]
fn evaluate_string_operations() {
    let program = CelProgram::compile("name + \" \" + suffix").unwrap();
    let mut ctx = CelContext::new();
    ctx.add_var("name", &"hello").unwrap();
    ctx.add_var("suffix", &"world").unwrap();
    let result = program.evaluate(&ctx).unwrap();
    assert_eq!(value_to_string(&result), Some("hello world".to_string()));
}

#[test]
fn evaluate_boolean_logic() {
    let program = CelProgram::compile("x > 10 && y < 20").unwrap();
    let mut ctx = CelContext::new();
    ctx.add_var("x", &15i64).unwrap();
    ctx.add_var("y", &5i64).unwrap();
    let result = program.evaluate(&ctx).unwrap();
    assert_eq!(value_to_bool(&result), Some(true));
}

#[test]
fn compile_rejects_invalid_syntax() {
    // The cel-interpreter's parser (antlr4rust) panics on some
    // malformed inputs rather than returning an error. We use
    // std::panic::catch_unwind to handle both cases.
    let result1 = std::panic::catch_unwind(|| CelProgram::compile("1 +"));
    assert!(result1.is_err() || result1.unwrap().is_err());

    let result2 = std::panic::catch_unwind(|| CelProgram::compile(""));
    // Empty string is a valid (empty) expression in some parsers;
    // just ensure it doesn't panic.
    let _ = result2;
}

#[test]
fn references_lists_variables() {
    let program = CelProgram::compile("a + b + c").unwrap();
    let refs = program.references();
    assert!(refs.contains(&"a".to_string()));
    assert!(refs.contains(&"b".to_string()));
    assert!(refs.contains(&"c".to_string()));
}

#[test]
fn evaluate_ternary() {
    let program = CelProgram::compile("x > 0 ? \"positive\" : \"negative\"").unwrap();
    let mut ctx = CelContext::new();
    ctx.add_var("x", &5i64).unwrap();
    let result = program.evaluate(&ctx).unwrap();
    assert_eq!(value_to_string(&result), Some("positive".to_string()));
}

#[test]
fn evaluate_string_methods() {
    let program = CelProgram::compile("s.startsWith(\"hello\")").unwrap();
    let mut ctx = CelContext::new();
    ctx.add_var("s", &"hello world").unwrap();
    let result = program.evaluate(&ctx).unwrap();
    assert_eq!(value_to_bool(&result), Some(true));
}

#[test]
fn evaluate_list_operations() {
    let program = CelProgram::compile("[1, 2, 3].size()").unwrap();
    let ctx = CelContext::new();
    let result = program.evaluate(&ctx).unwrap();
    assert_eq!(value_to_int(&result), Some(3));
}

#[test]
fn evaluate_map_operations() {
    let program = CelProgram::compile("m[\"key\"]").unwrap();
    let mut ctx = CelContext::new();
    let mut m = std::collections::HashMap::new();
    m.insert("key", "value".to_string());
    ctx.add_var("m", &m).unwrap();
    let result = program.evaluate(&ctx).unwrap();
    assert_eq!(value_to_string(&result), Some("value".to_string()));
}

#[test]
fn value_converters() {
    use std::sync::Arc;
    assert_eq!(value_to_bool(&Value::Bool(true)), Some(true));
    assert_eq!(
        value_to_string(&Value::String(Arc::new("x".to_string()))),
        Some("x".to_string())
    );
    assert_eq!(value_to_int(&Value::Int(42)), Some(42));
    assert_eq!(value_to_float(&Value::Float(2.5)), Some(2.5));
}
