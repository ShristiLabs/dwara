# CEL Engine (DW-058)

## Overview

dwara includes a CEL (Common Expression Language) engine that compiles
and evaluates CEL expressions. CEL is a lightweight, non-Turing-complete
expression language designed for evaluating conditions and
transformations in policy and configuration systems.

The engine is feature-gated behind the `cel` cargo feature (default
OFF) because the `cel-interpreter` crate adds binary size.

## Enabling

Build with the `cel` feature:

```sh
cargo build --features cel
```

Without the feature, config fields that reference CEL expressions are
accepted but inert.

## Design (decision 5; section 9.3)

CEL expressions are compiled once at config publish time and embedded
in the snapshot as `CelProgram` instances. The request path only
evaluates -- it never parses or compiles. This keeps the hot path fast.

### Compile pipeline

```
source string
    |
    v
parse (cel-parser, ANTLR4 grammar)
    |
    v
type-check (cel-interpreter)
    |
    v
CelProgram (AST, immutable, Send + Sync)
```

### Evaluation

```
CelProgram + CelContext (variable bindings)
    |
    v
tree-walking interpreter (cel-interpreter)
    |
    v
Value (Bool, Int, Float, String, List, Map, ...)
```

## API

### CelProgram

```rust
use dwara_core::cel::{CelProgram, CelContext};

// Compile at config publish time (never on the request path).
let program = CelProgram::compile("request.path.startsWith(\"/api/\")")?;

// Evaluate on the request path.
let mut ctx = CelContext::new();
ctx.add_var("request", &request)?;
let result = program.evaluate(&ctx)?;
```

### Value converters

```rust
use dwara_core::cel::{value_to_bool, value_to_string, value_to_int, value_to_float};

let result = program.evaluate(&ctx)?;
if let Some(should_allow) = value_to_bool(&result) {
    // ...
}
```

### References

```rust
let program = CelProgram::compile("a + b + c")?;
let refs = program.references();
// refs == ["a", "b", "c"]
```

Useful for validation -- ensuring an expression only references allowed
variables.

## Benchmark

The `cel` benchmark measures evaluator throughput for representative
expressions:

```sh
cargo bench --features cel --bench cel
```

Benchmark groups:
- `arithmetic` -- simple arithmetic (`1 + 2 * 3`)
- `variable_compare` -- variable access + comparison
- `string_method` -- string method call (`s.startsWith("hello")`)
- `ternary` -- ternary expression
- `complex_condition` -- multiple operations (method calls, map
  access, boolean logic)

The benchmark sets the acceptance threshold (ns/op) from the
comparative measurement itself -- the issue notes that
FEATURE_ANALYSIS.md does not fix a target eval throughput number.

## AOT vs JIT

The current implementation uses the cel-interpreter's tree-walking
evaluator (no JIT). If the benchmark shows this is too slow for a
given use case, a cranelift JIT backend can be added behind a feature
flag without changing the API -- `CelProgram` would hold either an AST
or JIT-compiled code, and `evaluate` would dispatch accordingly.

## Feature gate

The `cel` cargo feature must be enabled. Without it, the module is not
compiled and config fields that reference CEL expressions are accepted
but inert.

## New dependencies

- `cel-interpreter` 0.10 (MIT) -- CEL parser, type-checker, and
  tree-walking interpreter. Feature-gated behind `cel`.
