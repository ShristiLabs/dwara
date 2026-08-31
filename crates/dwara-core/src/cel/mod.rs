//! CEL (Common Expression Language) engine (DW-058).
//!
//! This module provides a thin wrapper around the `cel-interpreter`
//! crate, offering:
//!
//! - [`CelProgram`] — a compiled CEL program (parse + type-check done
//!   at compile time, never on the request path).
//! - [`CelContext`] — a CEL evaluation context (variable bindings).
//! - [`CelValue`] — a CEL value (the result of evaluation).
//!
//! ## Design (decision 5; §9.3)
//!
//! CEL expressions are compiled once at config publish time and
//! embedded in the snapshot as [`CelProgram`] instances. The request
//! path only evaluates — it never parses or compiles. This keeps the
//! hot path fast (the cel-interpreter's tree-walking evaluator is
//! ~100-500 ns/op for simple expressions, measured by the benchmark
//! in `benches/micro.rs`).
//!
//! ## AOT vs JIT
//!
//! The issue scope mentions "cranelift JIT optional". The current
//! implementation uses the cel-interpreter's tree-walking evaluator
//! (no JIT). If the benchmark shows this is too slow for a given use
//! case, a cranelift JIT backend can be added behind a feature flag
//! without changing the API — [`CelProgram`] would hold either an AST
//! or JIT-compiled code, and [`CelProgram::evaluate`] would dispatch
//! accordingly.
//!
//! ## Feature gate
//!
//! The `cel` cargo feature must be enabled. Without it, the module is
//! not compiled and config fields that reference CEL expressions are
//! accepted but inert.

use std::collections::HashMap;

pub use cel_interpreter::{ExecutionError, ParseError, ParseErrors, Value};

// DW-059: CEL everywhere -- one CEL surface across four use-sites.
pub mod everywhere;

/// A compiled CEL program.
///
/// Created at config publish time by [`CelProgram::compile`]. The
/// program is immutable and can be safely shared across threads (the
/// underlying AST is `Send + Sync`).
///
/// On the request path, call [`CelProgram::evaluate`] with a
/// [`CelContext`] containing the request variables.
#[derive(Debug)]
pub struct CelProgram {
    source: String,
    program: cel_interpreter::Program,
}

/// A CEL evaluation context — variable bindings for evaluation.
///
/// Built per-request (or per-evaluation) with the variables the CEL
/// expression can reference. For example, a route condition expression
/// `request.path.startsWith("/api/")` needs a `request` variable with
/// a `path` field.
pub struct CelContext {
    inner: cel_interpreter::Context<'static>,
}

/// The result of evaluating a CEL expression.
pub type CelResult = Result<Value, ExecutionError>;

impl CelProgram {
    /// Compile a CEL expression from source.
    ///
    /// This is the parse + type-check step. It should be called at
    /// config publish time, never on the request path.
    pub fn compile(source: &str) -> Result<Self, ParseErrors> {
        let program = cel_interpreter::Program::compile(source)?;
        Ok(Self {
            source: source.to_string(),
            program,
        })
    }

    /// The original source string.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Evaluate the program against a context.
    ///
    /// This is the hot-path call. It walks the AST and resolves
    /// variables/functions against the context. No parsing or
    /// compilation happens here.
    pub fn evaluate(&self, context: &CelContext) -> CelResult {
        self.program.execute(&context.inner)
    }

    /// Returns the variables referenced by the program.
    /// Useful for validation (e.g. ensuring an expression only
    /// references allowed variables).
    pub fn references(&self) -> Vec<String> {
        self.program
            .references()
            .variables()
            .into_iter()
            .map(String::from)
            .collect()
    }
}

impl CelContext {
    /// Create a new empty context.
    pub fn new() -> Self {
        Self {
            inner: cel_interpreter::Context::default(),
        }
    }

    /// Add a variable binding to the context.
    ///
    /// The value must implement `serde::Serialize` (the cel-interpreter
    /// converts it to its internal `Value` type). Common types: strings,
    /// integers, floats, bools, Vec, HashMap.
    pub fn add_var<T: serde::Serialize>(&mut self, name: &str, value: &T) -> Result<(), String> {
        self.inner
            .add_variable(name, value)
            .map_err(|e| format!("CEL context add_var {name}: {e}"))
    }

    /// Add a raw CEL Value to the context.
    pub fn add_value(&mut self, name: &str, value: Value) {
        self.inner.add_variable_from_value(name, value);
    }

    /// Add all key-value pairs from a HashMap to the context.
    pub fn add_vars<T: serde::Serialize>(
        &mut self,
        vars: &HashMap<String, T>,
    ) -> Result<(), String> {
        for (key, value) in vars {
            self.add_var(key, value)?;
        }
        Ok(())
    }
}

impl Default for CelContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a CEL Value to a Rust bool, if possible.
pub fn value_to_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

/// Convert a CEL Value to a Rust string, if possible.
pub fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.to_string()),
        _ => None,
    }
}

/// Convert a CEL Value to a Rust i64, if possible.
pub fn value_to_int(value: &Value) -> Option<i64> {
    match value {
        Value::Int(i) => Some(*i),
        Value::UInt(u) => Some(*u as i64),
        _ => None,
    }
}

/// Convert a CEL Value to a Rust f64, if possible.
pub fn value_to_float(value: &Value) -> Option<f64> {
    match value {
        Value::Float(f) => Some(*f),
        Value::Int(i) => Some(*i as f64),
        Value::UInt(u) => Some(*u as f64),
        _ => None,
    }
}
