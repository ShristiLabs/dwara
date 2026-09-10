//! CEL JIT compilation via cranelift (PERF-09, #260).
//!
//! This module provides a cranelift-based JIT compiler for CEL
//! expressions. When the `cel-jit` cargo feature is enabled, the
//! [`CelProgram`] can optionally JIT-compile simple CEL expressions
//! to native code for faster evaluation.
//!
//! # Supported expressions
//!
//! The JIT compiler supports a subset of CEL expressions:
//! - Boolean literals (`true`, `false`)
//! - Integer literals (`1`, `42`)
//! - String literals (`"hello"`)
//! - Identifier references (`request.path`)
//! - Comparison operators (`==`, `!=`, `<`, `<=`, `>`, `>=`)
//! - Logical operators (`&&`, `||`, `!`)
//! - The `startsWith`, `endsWith`, `contains` string functions
//!
//! Complex expressions (comprehensions, maps, structs, custom
//! functions) fall back to the tree-walking interpreter.
//!
//! # Architecture
//!
//! The JIT compiler:
//! 1. Parses the CEL expression using `cel-parser` to get the AST.
//! 2. Checks if the expression is supported by the JIT (simple enough).
//! 3. Compiles the AST to cranelift IR.
//! 4. Compiles the cranelift IR to native code.
//! 5. Returns a function pointer that can be called to evaluate the
//!    expression.
//!
//! The JIT-compiled function takes a context pointer and returns a
//! `CelJitResult` (a tagged union of bool, i64, f64, or string).
//!
//! # Current status
//!
//! The `cel-jit` feature gate, dependency wiring, and module structure
//! are in place. The actual AST-to-cranelift-IR compilation is a future
//! enhancement — the JIT currently returns `Unsupported` for all
//! expressions, so evaluation falls back to the tree-walking
//! interpreter. This scaffolding allows the feature to be compiled and
//! tested without a full JIT implementation, and provides the
//! integration point for future work.
//!
//! # Fallback
//!
//! When the `cel-jit` feature is OFF or the expression is too complex
//! for the JIT, evaluation falls back to the tree-walking interpreter
//! (`cel-interpreter`). This is transparent to the caller: the
//! [`CelProgram::evaluate`] API is the same regardless of whether the
//! JIT is used.

use cel_interpreter::{Context, Value};

/// The result of a JIT-compiled CEL evaluation. A tagged union of
/// the CEL scalar types the JIT supports. The JIT-compiled function
/// returns this by value.
#[repr(C, u8)]
#[derive(Debug, Clone)]
pub enum CelJitResult {
    /// A boolean value.
    Bool(bool),
    /// A 64-bit integer value.
    Int(i64),
    /// A 64-bit float value.
    Float(f64),
    /// The JIT does not support this expression; the caller should
    /// fall back to the tree-walking interpreter.
    Unsupported,
    /// An error occurred during JIT evaluation.
    Error,
}

/// Check if the `cel-jit` cargo feature is compiled in.
pub fn cel_jit_available() -> bool {
    cfg!(feature = "cel-jit")
}

/// A JIT-compiled CEL program. When the `cel-jit` feature is ON and
/// the expression is simple enough, [`CelProgram::compile`] produces
/// a `CelJitProgram` that can be evaluated without the tree-walking
/// interpreter. When the feature is OFF or the expression is too
/// complex, this is `None` and evaluation falls back to the
/// interpreter.
pub struct CelJitProgram {
    _private: (),
}

impl CelJitProgram {
    /// Try to JIT-compile a CEL expression. Returns `None` if the
    /// expression is too complex for the JIT or if compilation fails.
    ///
    /// The current implementation always returns `None`: the
    /// scaffolding (feature gate, dependency wiring, module structure)
    /// is in place, but the actual AST-to-cranelift-IR compilation is
    /// a future enhancement. All expressions fall back to the
    /// tree-walking interpreter.
    pub fn try_compile(_source: &str) -> Option<Self> {
        None
    }

    /// Evaluate the JIT-compiled expression. Returns
    /// [`CelJitResult::Unsupported`] if the JIT cannot handle the
    /// expression (the caller should fall back to the interpreter).
    pub fn evaluate(&self, _context: &Context) -> CelJitResult {
        CelJitResult::Unsupported
    }
}

/// Convert a `CelJitResult` to a `cel_interpreter::Value`. Returns
/// `None` for `Unsupported` or `Error` (the caller should fall back
/// to the interpreter).
pub fn jit_result_to_value(result: CelJitResult) -> Option<Value> {
    match result {
        CelJitResult::Bool(b) => Some(Value::Bool(b)),
        CelJitResult::Int(i) => Some(Value::Int(i)),
        CelJitResult::Float(f) => Some(Value::Float(f)),
        CelJitResult::Unsupported | CelJitResult::Error => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jit_result_bool() {
        let r = CelJitResult::Bool(true);
        let v = jit_result_to_value(r);
        assert!(matches!(v, Some(Value::Bool(true))));
    }

    #[test]
    fn jit_result_int() {
        let r = CelJitResult::Int(42);
        let v = jit_result_to_value(r);
        assert!(matches!(v, Some(Value::Int(42))));
    }

    #[test]
    fn jit_result_float() {
        let r = CelJitResult::Float(2.71);
        let v = jit_result_to_value(r);
        assert!(matches!(v, Some(Value::Float(_))));
    }

    #[test]
    fn jit_result_unsupported() {
        let r = CelJitResult::Unsupported;
        let v = jit_result_to_value(r);
        assert!(v.is_none());
    }

    #[test]
    fn jit_result_error() {
        let r = CelJitResult::Error;
        let v = jit_result_to_value(r);
        assert!(v.is_none());
    }

    #[test]
    fn cel_jit_feature_flag() {
        // When the feature is on, cel_jit_available returns true.
        // When off, it returns false.
        assert_eq!(cel_jit_available(), cfg!(feature = "cel-jit"));
    }

    #[test]
    fn try_compile_returns_none() {
        // The JIT scaffolding returns None for all expressions (the
        // actual AST-to-IR compilation is a future enhancement).
        let prog = CelJitProgram::try_compile("1 + 2");
        assert!(prog.is_none());
    }
}
