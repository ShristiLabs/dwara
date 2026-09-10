//! API aggregation (DW-061 spec, DP-09 runtime / #237).
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
//! ## Runtime (DP-09, #237)
//!
//! [`run_aggregation`] is the async runtime: it fetches all fragments
//! in parallel via simple async TCP + HTTP/1.1, shapes each through
//! JSONPath, and composes the result through the pure [`compose`]
//! function. A [`ServiceResolver`] trait abstracts service-to-endpoint
//! resolution so the runtime can be wired to the dataplane's current
//! generation balancers.
//!
//! ## Availability
//!
//! The module is always compiled into the OSS build.

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FailPolicy {
    /// Skip the fragment on error (the composed response omits the
    /// field). This is the default.
    #[default]
    FailOpen,
    /// Return an error on failure (the entire composed response fails).
    FailClosed,
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

// ---------------------------------------------------------------------------
// Async runtime (DP-09, #237)
// ---------------------------------------------------------------------------

/// The async aggregation runtime: fetches all fragments, shapes each,
/// and composes the result.
///
/// This is the runtime half of the aggregation module (DW-061 spec +
/// DP-09 runtime). It uses simple async TCP with manual HTTP/1.1
/// framing to fetch each fragment from its upstream service, then
/// feeds the results through the pure [`compose`] function.
///
/// Fragments are fetched sequentially (the resolver is a borrowed
/// reference, so spawning parallel tasks would require `'static`).
/// A future optimization can wrap the resolver in `Arc` and use
/// `JoinSet` for parallel fetches.
pub async fn run_aggregation(
    spec: &AggregationSpec,
    resolver: &dyn ServiceResolver,
) -> ComposeResult {
    let mut results = Vec::with_capacity(spec.fragments.len());
    for fragment in &spec.fragments {
        results.push(fetch_fragment(fragment, resolver).await);
    }
    compose(spec, &results)
}

/// Fetch a single fragment from its upstream service.
async fn fetch_fragment(fragment: &FragmentSpec, resolver: &dyn ServiceResolver) -> FragmentResult {
    // Resolve the service to an upstream endpoint.
    let endpoint = match resolver.resolve(&fragment.service) {
        Some(e) => e,
        None => {
            return make_error_fragment_result(
                fragment,
                &format!(
                    "service '{}' not found or has no endpoint",
                    fragment.service
                ),
            );
        }
    };

    // Build the HTTP request.
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\nAccept: application/json\r\n\r\n",
        fragment.method, fragment.path, endpoint.host, endpoint.port
    );

    // Connect and send the request.
    let addr = format!("{}:{}", endpoint.host, endpoint.port);
    let mut stream = match tokio::net::TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            return make_error_fragment_result(fragment, &format!("connect to {addr} failed: {e}"));
        }
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if let Err(e) = stream.write_all(request.as_bytes()).await {
        return make_error_fragment_result(fragment, &format!("write failed: {e}"));
    }

    // Read the response (bounded by max_fragment_bytes + headers).
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() > fragment.max_fragment_bytes + 8192 {
                    return make_error_fragment_result(
                        fragment,
                        "response exceeds max fragment size",
                    );
                }
            }
            Err(e) => {
                return make_error_fragment_result(fragment, &format!("read failed: {e}"));
            }
        }
    }

    // Parse the HTTP response: skip headers, extract body.
    let body = match extract_http_body(&response) {
        Ok(b) => b,
        Err(e) => {
            return make_error_fragment_result(fragment, &format!("http parse failed: {e}"));
        }
    };

    make_fragment_result(fragment, &body)
}

/// Extract the body from an HTTP/1.1 response (skip the status line
/// and headers, return the body bytes as a string).
fn extract_http_body(response: &[u8]) -> Result<String, String> {
    // Find the end of headers (\r\n\r\n).
    let separator = b"\r\n\r\n";
    let pos = response
        .windows(separator.len())
        .position(|w| w == separator)
        .ok_or("no header/body separator found")?;

    let body = &response[pos + separator.len()..];
    String::from_utf8(body.to_vec()).map_err(|e| format!("invalid UTF-8 in body: {e}"))
}

/// A service resolver: maps a service name to an upstream endpoint.
/// Implemented by the dataplane (which has the current snapshot's
/// services + upstreams + balancers).
pub trait ServiceResolver: Send + Sync {
    /// Resolve a service name to an upstream endpoint (host, port).
    fn resolve(&self, service: &str) -> Option<ResolvedEndpoint>;
}

/// A resolved upstream endpoint.
#[derive(Debug, Clone)]
pub struct ResolvedEndpoint {
    pub host: String,
    pub port: u16,
}
