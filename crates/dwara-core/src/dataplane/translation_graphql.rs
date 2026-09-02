//! REST <-> GraphQL translation (DW-100).
//!
//! The [`GraphqlTranslator`] implements [`super::ProtocolTranslator`] for
//! routes that front a GraphQL upstream with a REST client (or vice
//! versa). Two directions:
//!
//! - **REST-to-GraphQL** (`kind: rest_to_graphql`): the client sends a
//!   REST JSON body; the translator builds a GraphQL request from a
//!   config-supplied query template. The template carries `$variable`
//!   placeholders that are filled from the JSON body's fields, and the
//!   filled query plus a `variables` map become the GraphQL-over-HTTP
//!   POST body the upstream expects.
//! - **GraphQL-to-REST** (`kind: graphql_to_rest`): the upstream returns
//!   a GraphQL response envelope `{ "data": { ... } }`; the translator
//!   unwraps the `data` object and returns it as the REST JSON body the
//!   client expects. (A GraphQL `errors` array maps to a 502 with the
//!   errors as the body.)
//!
//! ## Template syntax
//!
//! The query template is plain GraphQL text with `$variable` references.
//! Each `$name` in the template is resolved from the inbound JSON body's
//! top-level `name` field (the value is also placed in the `variables`
//! map sent to the upstream, so the upstream's own variable resolution
//! works). A `$name` the body does not supply fails the translation
//! closed (the request never reaches the upstream with a dangling
//! variable).
//!
//! ## Feature gating
//!
//! Compiled under the `protocol_translation` cargo feature.

#![cfg(feature = "protocol_translation")]

use bytes::Bytes;
use hyper::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use serde_json::Value;

use super::translation::{
    ProtocolTranslator, TranslatedRequest, TranslatedResponse, TranslationBody, TranslationError,
};
use crate::config::GraphqlTranslation;

/// The GraphQL-over-HTTP media type (the upstream expects this on the
/// request and returns it on the response).
const GRAPHQL_CONTENT_TYPE: &str = "application/graphql+json";

/// The REST/JSON media type (the client sends and expects).
const JSON_CONTENT_TYPE: &str = "application/json";

/// The REST-to-GraphQL / GraphQL-to-REST translator.
#[derive(Debug, Clone)]
pub struct GraphqlTranslator {
    /// The direction this translator was built for.
    direction: GraphqlDirection,
    /// The query template (REST-to-GraphQL only; empty for the reverse
    /// direction, which only unwraps the `data` envelope).
    query_template: String,
    /// The path to send the GraphQL upstream (REST-to-GraphQL rewrites
    /// every request to this; default `/graphql`).
    upstream_path: String,
}

/// The translation direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphqlDirection {
    /// A REST client -> GraphQL upstream.
    RestToGraphql,
    /// A GraphQL client -> REST upstream (the response path unwraps the
    /// GraphQL `data` envelope into a REST body).
    GraphqlToRest,
}

impl GraphqlTranslator {
    /// Build a REST-to-GraphQL translator from a route's GraphQL
    /// translation config.
    pub fn rest_to_graphql(cfg: &GraphqlTranslation) -> Result<Self, TranslationError> {
        if cfg.query_template.trim().is_empty() {
            return Err(TranslationError::SchemaNotFound(
                "graphql translation requires a query_template".to_string(),
            ));
        }
        Ok(GraphqlTranslator {
            direction: GraphqlDirection::RestToGraphql,
            query_template: cfg.query_template.clone(),
            upstream_path: cfg.upstream_path.clone(),
        })
    }

    /// Build a GraphQL-to-REST translator. The reverse direction only
    /// unwraps the GraphQL `data` envelope on the response path, so no
    /// query template is required.
    pub fn graphql_to_rest() -> Self {
        GraphqlTranslator {
            direction: GraphqlDirection::GraphqlToRest,
            query_template: String::new(),
            upstream_path: String::new(),
        }
    }

    /// The configured direction.
    pub fn direction(&self) -> GraphqlDirection {
        self.direction
    }
}

impl ProtocolTranslator for GraphqlTranslator {
    fn translate_request(
        &self,
        req: &Request<TranslationBody>,
    ) -> Result<TranslatedRequest, TranslationError> {
        match self.direction {
            GraphqlDirection::RestToGraphql => {
                let body = req.body().as_bytes();
                let json: Value = serde_json::from_slice(body).map_err(|e| {
                    TranslationError::InvalidBody(format!("expected a JSON body: {e}"))
                })?;
                let obj = json.as_object().ok_or_else(|| {
                    TranslationError::InvalidBody(
                        "expected a JSON object for the GraphQL variables".to_string(),
                    )
                })?;

                // Collect every $variable referenced by the template and
                // resolve it from the JSON body. Each resolved value is
                // placed in the `variables` map the upstream receives.
                let variables = collect_variables(&self.query_template, obj)?;

                // Substitute the $variables into the query text. The
                // substituted query is sent verbatim (the variables map
                // is also sent, so the upstream can resolve either way;
                // sending both matches Apollo's over-HTTP convention).
                let query = substitute_template(&self.query_template, &variables);

                let gql_body = serde_json::json!({
                    "query": query,
                    "variables": variables,
                });
                let body = serde_json::to_vec(&gql_body).map_err(|e| {
                    TranslationError::TranslationFailed(format!(
                        "failed to serialize graphql request: {e}"
                    ))
                })?;

                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static(GRAPHQL_CONTENT_TYPE));

                Ok(TranslatedRequest {
                    method: Method::POST,
                    path: self.upstream_path.clone(),
                    headers,
                    body: Bytes::from(body),
                })
            }
            GraphqlDirection::GraphqlToRest => {
                // A GraphQL client -> REST upstream: the client already
                // sent a GraphQL body; pass it through unchanged (the
                // upstream is the REST backend, so no request translation
                // is needed -- the response path does the work).
                let mut headers = HeaderMap::new();
                if let Some(ct) = req.headers().get(CONTENT_TYPE).cloned() {
                    headers.insert(CONTENT_TYPE, ct);
                } else {
                    headers.insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
                }
                Ok(TranslatedRequest {
                    method: req.method().clone(),
                    path: req.uri().path().to_string(),
                    headers,
                    body: req.body().as_bytes().clone(),
                })
            }
        }
    }

    fn translate_response(
        &self,
        resp: &Response<TranslationBody>,
    ) -> Result<TranslatedResponse, TranslationError> {
        match self.direction {
            GraphqlDirection::RestToGraphql => {
                // The upstream returned a GraphQL response; unwrap the
                // `data` envelope into a REST body. A GraphQL `errors`
                // array maps to a 502 with the errors as the body.
                let body = resp.body().as_bytes();
                let gql: Value = serde_json::from_slice(body).map_err(|e| {
                    TranslationError::InvalidBody(format!("expected a graphql JSON response: {e}"))
                })?;
                if let Some(errors) = gql.get("errors") {
                    if !errors.is_null() {
                        let body = serde_json::to_vec(errors).map_err(|e| {
                            TranslationError::TranslationFailed(format!(
                                "failed to serialize graphql errors: {e}"
                            ))
                        })?;
                        let mut headers = HeaderMap::new();
                        headers.insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
                        return Ok(TranslatedResponse {
                            status: StatusCode::BAD_GATEWAY,
                            headers,
                            body: Bytes::from(body),
                        });
                    }
                }
                let data = gql.get("data").cloned().unwrap_or(Value::Null);
                let body = serde_json::to_vec(&data).map_err(|e| {
                    TranslationError::TranslationFailed(format!(
                        "failed to serialize rest response: {e}"
                    ))
                })?;
                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
                Ok(TranslatedResponse {
                    status: resp.status(),
                    headers,
                    body: Bytes::from(body),
                })
            }
            GraphqlDirection::GraphqlToRest => {
                // The REST upstream returned a plain JSON body; wrap it
                // in the GraphQL `{ "data": ... }` envelope the client
                // expects.
                let body = resp.body().as_bytes();
                let data: Value = if body.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(body).map_err(|e| {
                        TranslationError::InvalidBody(format!(
                            "expected a JSON response from the rest upstream: {e}"
                        ))
                    })?
                };
                let gql = serde_json::json!({ "data": data });
                let body = serde_json::to_vec(&gql).map_err(|e| {
                    TranslationError::TranslationFailed(format!(
                        "failed to serialize graphql envelope: {e}"
                    ))
                })?;
                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static(GRAPHQL_CONTENT_TYPE));
                Ok(TranslatedResponse {
                    status: resp.status(),
                    headers,
                    body: Bytes::from(body),
                })
            }
        }
    }

    fn content_type_in(&self) -> &str {
        match self.direction {
            GraphqlDirection::RestToGraphql => JSON_CONTENT_TYPE,
            GraphqlDirection::GraphqlToRest => GRAPHQL_CONTENT_TYPE,
        }
    }

    fn content_type_out(&self) -> &str {
        match self.direction {
            GraphqlDirection::RestToGraphql => GRAPHQL_CONTENT_TYPE,
            GraphqlDirection::GraphqlToRest => JSON_CONTENT_TYPE,
        }
    }
}

/// Collect every `$variable` referenced by the template and resolve it
/// from the JSON body. Returns a JSON object mapping variable name ->
/// value. A variable the body does not supply fails closed.
fn collect_variables(
    template: &str,
    body: &serde_json::Map<String, Value>,
) -> Result<Value, TranslationError> {
    let mut vars = serde_json::Map::new();
    for name in referenced_variables(template) {
        if vars.contains_key(&name) {
            continue;
        }
        let value = body.get(&name).ok_or_else(|| {
            TranslationError::TranslationFailed(format!(
                "graphql template references ${name} but the request body has no such field"
            ))
        })?;
        vars.insert(name.clone(), value.clone());
    }
    Ok(Value::Object(vars))
}

/// Scan a query template for `$variable` references. A variable name is
/// a `$` followed by one or more GraphQL name characters
/// (`[A-Za-z_][A-Za-z0-9_]*`). Returns the names in first-reference
/// order, deduplicated.
fn referenced_variables(template: &str) -> Vec<String> {
    let bytes = template.as_bytes();
    let mut names = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && is_name_start(bytes[i + 1]) {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && is_name_char(bytes[j]) {
                j += 1;
            }
            let name = &template[start..j];
            if seen.insert(name.to_string()) {
                names.push(name.to_string());
            }
            i = j;
            continue;
        }
        i += 1;
    }
    names
}

/// Substitute `$variable` references in the template with the JSON
/// variable values, serialized as GraphQL literal values (strings
/// quoted, numbers bare, booleans bare, null bare, objects/arrays
/// inlined). The substituted query is sent verbatim to the upstream.
fn substitute_template(template: &str, variables: &Value) -> String {
    let bytes = template.as_bytes();
    let mut out = String::with_capacity(template.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && is_name_start(bytes[i + 1]) {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && is_name_char(bytes[j]) {
                j += 1;
            }
            let name = &template[start..j];
            if let Some(value) = variables.get(name) {
                out.push_str(&json_to_graphql_literal(value));
            } else {
                // An unresolved variable: leave the reference intact
                // (the variables map carries it; the upstream resolves).
                out.push('$');
                out.push_str(name);
            }
            i = j;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Render a JSON value as a GraphQL literal value.
fn json_to_graphql_literal(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            // A minimal string escape: double-quote and escape the
            // GraphQL-significant characters. This is sufficient for
            // template-substituted values; complex strings ride in the
            // variables map instead.
            let mut out = String::with_capacity(s.len() + 2);
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        out.push_str(&format!("\\u{:04x}", c as u32));
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(json_to_graphql_literal).collect();
            format!("[{}]", items.join(", "))
        }
        Value::Object(obj) => {
            let items: Vec<String> = obj
                .iter()
                .map(|(k, v)| format!("{}: {}", k, json_to_graphql_literal(v)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
    }
}

fn is_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
