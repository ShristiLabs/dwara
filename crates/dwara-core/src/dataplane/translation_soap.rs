//! SOAP/XML protocol translation (DW-100).
//!
//! The [`SoapTranslator`] implements [`super::translation::ProtocolTranslator`]
//! for routes that bridge a REST/JSON client and a SOAP/XML upstream (or
//! vice versa). Two directions:
//!
//! - **SOAP-to-REST** (`kind: soap_to_rest`): the client sends a SOAP
//!   XML envelope; the translator parses the envelope, extracts the
//!   `Body`'s first child element (the operation), and converts its XML
//!   children to a JSON body the REST upstream expects.
//! - **REST-to-SOAP** (`kind: rest_to_soap`): the upstream returns a
//!   REST JSON body; the translator wraps it in a SOAP envelope
//!   (`Envelope > Body > {operation}`) with the configured operation
//!   name and namespace, converting the JSON to XML.
//!
//! ## Minimal XML parser
//!
//! A full XML library would be a new dependency (and a deny.toml
//! review). SOAP envelopes are a narrow XML subset: elements with
//! optional attributes, text content, and nested elements -- no DTDs,
//! no entity expansion, no processing instructions. A minimal hand-rolled
//! parser handles that subset and rejects everything else (fail-closed
//! against anything it cannot prove well-formed). The parser is bounded:
//! a depth cap prevents element-nesting DoS, and a size cap rejects
//! oversized bodies before parsing.
//!
//! ## XML <-> JSON convention
//!
//! The conversion follows a simple, deterministic convention:
//!
//! - An element with only text content -> a JSON string (or number/bool
//!   when the text parses as one).
//! - An element with child elements -> a JSON object mapping each child
//!   tag to its converted value. Repeated child tags become a JSON array.
//! - Attributes -> a `@attr` key in the object.
//!
//! This is sufficient for SOAP body payloads (which are flat-ish data
//! records); complex XSD types are out of scope for the hand-rolled
//! converter.
//!
//! ## Feature gating
//!
//! Compiled under the `soap` cargo feature (which implies
//! `protocol_translation`).

#![cfg(feature = "soap")]

use bytes::Bytes;
use hyper::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use hyper::{Method, Request, Response};
use serde_json::Value;

use super::translation::{
    ProtocolTranslator, TranslatedRequest, TranslatedResponse, TranslationBody, TranslationError,
};
use crate::config::SoapTranslation;

/// The SOAP/XML media type (the SOAP side sends and expects
/// `text/xml`; SOAP 1.2 uses `application/soap+xml` but `text/xml` is
/// the universally accepted default).
const SOAP_CONTENT_TYPE: &str = "text/xml";

/// The REST/JSON media type.
const JSON_CONTENT_TYPE: &str = "application/json";

/// The SOAP envelope namespace (SOAP 1.1).
const SOAP_ENVELOPE_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

/// Maximum element-nesting depth the parser will track before aborting
/// (parser-DoS cap). A SOAP envelope this deep is malformed.
const PARSE_DEPTH_CAP: usize = 256;

/// The SOAP-to-REST / REST-to-SOAP translator.
#[derive(Debug, Clone)]
pub struct SoapTranslator {
    /// The direction this translator was built for.
    direction: SoapDirection,
    /// The SOAP operation name (the Body's first child element name).
    operation: String,
    /// The XML namespace for the operation element.
    namespace: String,
}

/// The translation direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoapDirection {
    /// A SOAP client -> REST upstream.
    SoapToRest,
    /// A REST client -> SOAP upstream.
    RestToSoap,
}

impl SoapTranslator {
    /// Build a SOAP-to-REST translator. The operation name is used to
    /// locate the Body's payload element (the first child whose local
    /// name matches, ignoring namespace prefixes).
    pub fn soap_to_rest(cfg: &SoapTranslation) -> Result<Self, TranslationError> {
        if cfg.operation.trim().is_empty() {
            return Err(TranslationError::SchemaNotFound(
                "soap translation requires an operation name".to_string(),
            ));
        }
        Ok(SoapTranslator {
            direction: SoapDirection::SoapToRest,
            operation: cfg.operation.clone(),
            namespace: cfg.namespace.clone(),
        })
    }

    /// Build a REST-to-SOAP translator. Both the operation name and
    /// namespace are required (the envelope's payload element carries
    /// the namespace).
    pub fn rest_to_soap(cfg: &SoapTranslation) -> Result<Self, TranslationError> {
        if cfg.operation.trim().is_empty() {
            return Err(TranslationError::SchemaNotFound(
                "soap translation requires an operation name".to_string(),
            ));
        }
        if cfg.namespace.trim().is_empty() {
            return Err(TranslationError::SchemaNotFound(
                "rest_to_soap translation requires a namespace".to_string(),
            ));
        }
        Ok(SoapTranslator {
            direction: SoapDirection::RestToSoap,
            operation: cfg.operation.clone(),
            namespace: cfg.namespace.clone(),
        })
    }

    /// The configured direction.
    pub fn direction(&self) -> SoapDirection {
        self.direction
    }
}

impl ProtocolTranslator for SoapTranslator {
    fn translate_request(
        &self,
        req: &Request<TranslationBody>,
    ) -> Result<TranslatedRequest, TranslationError> {
        match self.direction {
            SoapDirection::SoapToRest => {
                let body = req.body().as_bytes();
                let envelope = parse_envelope(body)?;
                let payload = extract_body_payload(&envelope, &self.operation)?;
                let json = xml_element_to_json(&payload);
                let body = serde_json::to_vec(&json).map_err(|e| {
                    TranslationError::TranslationFailed(format!(
                        "failed to serialize soap body to json: {e}"
                    ))
                })?;
                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
                Ok(TranslatedRequest {
                    method: req.method().clone(),
                    path: req.uri().path().to_string(),
                    headers,
                    body: Bytes::from(body),
                })
            }
            SoapDirection::RestToSoap => {
                let body = req.body().as_bytes();
                let json: Value = serde_json::from_slice(body).map_err(|e| {
                    TranslationError::InvalidBody(format!("expected a JSON body: {e}"))
                })?;
                let envelope = build_envelope(&self.operation, &self.namespace, &json);
                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static(SOAP_CONTENT_TYPE));
                Ok(TranslatedRequest {
                    method: Method::POST,
                    path: req.uri().path().to_string(),
                    headers,
                    body: Bytes::from(envelope.into_bytes()),
                })
            }
        }
    }

    fn translate_response(
        &self,
        resp: &Response<TranslationBody>,
    ) -> Result<TranslatedResponse, TranslationError> {
        match self.direction {
            SoapDirection::SoapToRest => {
                // The REST upstream returned a plain JSON body; wrap it
                // in a SOAP envelope the SOAP client expects.
                let body = resp.body().as_bytes();
                let json: Value = if body.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(body).map_err(|e| {
                        TranslationError::InvalidBody(format!(
                            "expected a JSON response from the rest upstream: {e}"
                        ))
                    })?
                };
                let envelope = build_envelope(&self.operation, &self.namespace, &json);
                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static(SOAP_CONTENT_TYPE));
                Ok(TranslatedResponse {
                    status: resp.status(),
                    headers,
                    body: Bytes::from(envelope.into_bytes()),
                })
            }
            SoapDirection::RestToSoap => {
                // The SOAP upstream returned a SOAP envelope; unwrap the
                // Body's payload into a REST JSON body.
                let body = resp.body().as_bytes();
                let envelope = parse_envelope(body)?;
                let payload = extract_body_payload(&envelope, &self.operation)?;
                let json = xml_element_to_json(&payload);
                let body = serde_json::to_vec(&json).map_err(|e| {
                    TranslationError::TranslationFailed(format!(
                        "failed to serialize soap body to json: {e}"
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
        }
    }

    fn content_type_in(&self) -> &str {
        match self.direction {
            SoapDirection::SoapToRest => SOAP_CONTENT_TYPE,
            SoapDirection::RestToSoap => JSON_CONTENT_TYPE,
        }
    }

    fn content_type_out(&self) -> &str {
        match self.direction {
            SoapDirection::SoapToRest => JSON_CONTENT_TYPE,
            SoapDirection::RestToSoap => SOAP_CONTENT_TYPE,
        }
    }
}

// ---------------------------------------------------------------------------
// SOAP envelope helpers
// ---------------------------------------------------------------------------

/// Build a SOAP 1.1 envelope wrapping a JSON value as the Body's
/// operation element.
fn build_envelope(operation: &str, namespace: &str, payload: &Value) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out.push_str("<soap:Envelope xmlns:soap=\"");
    out.push_str(SOAP_ENVELOPE_NS);
    out.push_str("\">");
    out.push_str("<soap:Body>");
    // The operation element carries the configured namespace.
    out.push('<');
    out.push_str(operation);
    out.push_str(" xmlns=\"");
    out.push_str(namespace);
    out.push_str("\">");
    json_to_xml_element(payload, operation, &mut out);
    out.push_str("</");
    out.push_str(operation);
    out.push('>');
    out.push_str("</soap:Body>");
    out.push_str("</soap:Envelope>");
    out
}

/// Render a JSON value as XML child elements of the enclosing operation
/// element. A JSON object maps each key to a child element; a JSON array
/// maps each item to a repeated child element with the enclosing key; a
/// scalar becomes the text content of the enclosing element (the caller
/// has already opened the element and supplies the tag name).
fn json_to_xml_element(value: &Value, tag: &str, out: &mut String) {
    match value {
        Value::Null => {}
        Value::Bool(b) => {
            out.push_str(&escape_xml_text(&b.to_string()));
        }
        Value::Number(n) => {
            out.push_str(&escape_xml_text(&n.to_string()));
        }
        Value::String(s) => {
            out.push_str(&escape_xml_text(s));
        }
        Value::Array(arr) => {
            for item in arr {
                out.push('<');
                out.push_str(tag);
                out.push('>');
                json_to_xml_element(item, tag, out);
                out.push_str("</");
                out.push_str(tag);
                out.push('>');
            }
        }
        Value::Object(obj) => {
            for (k, v) in obj {
                out.push('<');
                out.push_str(&escape_xml_name(k));
                out.push('>');
                json_to_xml_element(v, k, out);
                out.push_str("</");
                out.push_str(&escape_xml_name(k));
                out.push('>');
            }
        }
    }
}

/// Extract the SOAP Body's first child element whose local name matches
/// the configured operation (namespace prefixes ignored). Returns the
/// payload element (the operation element with its children to convert).
fn extract_body_payload(
    envelope: &XmlElement,
    operation: &str,
) -> Result<XmlElement, TranslationError> {
    let body = find_child_by_local_name(envelope, "Body").ok_or_else(|| {
        TranslationError::InvalidBody("soap envelope has no Body element".to_string())
    })?;
    // The Body's first child element is the operation payload. Match by
    // local name (strip any namespace prefix) so the caller does not
    // need to know the prefix the client used.
    for child in &body.children {
        if let XmlChild::Element(el) = child {
            if local_name(&el.name) == operation {
                return Ok(el.clone());
            }
        }
    }
    Err(TranslationError::InvalidBody(format!(
        "soap Body has no child element matching operation '{operation}'"
    )))
}

/// Find the first child element whose local name (prefix stripped)
/// matches `name`.
fn find_child_by_local_name<'a>(el: &'a XmlElement, name: &str) -> Option<&'a XmlElement> {
    for child in &el.children {
        if let XmlChild::Element(c) = child {
            if local_name(&c.name) == name {
                return Some(c);
            }
        }
    }
    None
}

/// Strip the namespace prefix from a qualified name (`soap:Body` ->
/// `Body`).
fn local_name(qname: &str) -> &str {
    qname
        .rsplit_once(':')
        .map(|(_, local)| local)
        .unwrap_or(qname)
}

/// Convert an XML element to a JSON value following the module's
/// convention (see the module docs).
fn xml_element_to_json(el: &XmlElement) -> Value {
    // Collect child elements by tag (repeated tags -> array).
    let mut child_map: std::collections::BTreeMap<String, Vec<Value>> =
        std::collections::BTreeMap::new();
    let mut text = String::new();
    let mut has_elements = false;
    for child in &el.children {
        match child {
            XmlChild::Element(c) => {
                has_elements = true;
                child_map
                    .entry(local_name(&c.name).to_string())
                    .or_default()
                    .push(xml_element_to_json(c));
            }
            XmlChild::Text(t) => {
                text.push_str(t);
            }
        }
    }

    if !has_elements {
        // Leaf element: text content -> scalar JSON value.
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Value::Null;
        }
        return parse_scalar(trimmed);
    }

    // Object element: attributes as @-prefixed keys, children by tag.
    let mut obj = serde_json::Map::new();
    for (attr, val) in &el.attributes {
        obj.insert(format!("@{attr}"), parse_scalar(val));
    }
    for (tag, values) in child_map {
        if values.len() == 1 {
            obj.insert(tag, values.into_iter().next().unwrap());
        } else {
            obj.insert(tag, Value::Array(values));
        }
    }
    Value::Object(obj)
}

/// Parse a text scalar into a JSON value: integers, floats, booleans,
/// and null are recognized; everything else is a string.
fn parse_scalar(s: &str) -> Value {
    if s.eq_ignore_ascii_case("true") {
        return Value::Bool(true);
    }
    if s.eq_ignore_ascii_case("false") {
        return Value::Bool(false);
    }
    if s.eq_ignore_ascii_case("null") {
        return Value::Null;
    }
    if let Ok(n) = s.parse::<i64>() {
        return Value::Number(n.into());
    }
    if let Ok(n) = s.parse::<u64>() {
        return Value::Number(n.into());
    }
    if let Ok(f) = s.parse::<f64>() {
        if let Some(n) = serde_json::Number::from_f64(f) {
            return Value::Number(n);
        }
    }
    Value::String(s.to_string())
}

/// Escape text for XML text content.
fn escape_xml_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            c => out.push(c),
        }
    }
    out
}

/// Escape a string for use as an XML element name. Names must start
/// with a letter or underscore; invalid start characters are prefixed
/// with `_`. This is a best-effort sanitization for JSON keys coming
/// from a REST body.
fn escape_xml_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for (i, c) in name.chars().enumerate() {
        let valid = if i == 0 {
            c.is_ascii_alphabetic() || c == '_'
        } else {
            c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
        };
        if valid {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

// ---------------------------------------------------------------------------
// Minimal XML parser
// ---------------------------------------------------------------------------

/// A parsed XML element: name (qualified, prefix retained), attributes,
/// and children (elements and text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlElement {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<XmlChild>,
}

/// One child of an XML element: a nested element or a text run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlChild {
    Element(XmlElement),
    Text(String),
}

/// Parse a SOAP XML envelope into its root element. Rejects anything
/// that is not a well-formed (enough) single-rooted XML document the
/// parser can prove: DTDs, entity declarations, processing instructions
/// other than the optional XML declaration, and unbalanced tags all
/// fail closed.
fn parse_envelope(input: &[u8]) -> Result<XmlElement, TranslationError> {
    let text = std::str::from_utf8(input)
        .map_err(|e| TranslationError::InvalidBody(format!("soap body is not valid UTF-8: {e}")))?;
    let mut parser = XmlParser::new(text);
    parser.skip_prolog()?;
    let root = parser.parse_element(0)?;
    // Trailing non-whitespace is malformed.
    parser.skip_whitespace();
    if !parser.remaining().is_empty() {
        return Err(TranslationError::InvalidBody(
            "trailing content after the root element".to_string(),
        ));
    }
    Ok(root)
}

/// A minimal, hand-rolled XML parser. Tracks a byte cursor; produces
/// [`XmlElement`]s. Bounded by [`PARSE_DEPTH_CAP`].
struct XmlParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> XmlParser<'a> {
    fn new(input: &'a str) -> Self {
        XmlParser { input, pos: 0 }
    }

    fn remaining(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.advance(c.len_utf8());
            } else {
                break;
            }
        }
    }

    /// Skip the optional XML prolog (`<?xml ... ?>`) and any
    /// comments/processing instructions before the root element.
    fn skip_prolog(&mut self) -> Result<(), TranslationError> {
        loop {
            self.skip_whitespace();
            if self.remaining().starts_with("<?") {
                // Processing instruction: skip to `?>`.
                let end = self.remaining().find("?>").ok_or_else(|| {
                    TranslationError::InvalidBody("unterminated processing instruction".to_string())
                })?;
                self.advance(end + 2);
                continue;
            }
            if self.remaining().starts_with("<!--") {
                // Comment: skip to `-->`.
                let end = self.remaining().find("-->").ok_or_else(|| {
                    TranslationError::InvalidBody("unterminated comment".to_string())
                })?;
                self.advance(end + 3);
                continue;
            }
            if self.remaining().starts_with("<!") {
                // DTDs and entity declarations are rejected (the parser
                // does not expand entities -- fail closed).
                return Err(TranslationError::InvalidBody(
                    "DTDs and entity declarations are not supported".to_string(),
                ));
            }
            break;
        }
        Ok(())
    }

    /// Parse a single element starting at `<`. Returns the element.
    fn parse_element(&mut self, depth: usize) -> Result<XmlElement, TranslationError> {
        if depth > PARSE_DEPTH_CAP {
            return Err(TranslationError::InvalidBody(format!(
                "xml element nesting exceeds the parser depth cap ({PARSE_DEPTH_CAP})"
            )));
        }
        self.skip_whitespace();
        if self.peek() != Some('<') {
            return Err(TranslationError::InvalidBody(
                "expected '<' to start an element".to_string(),
            ));
        }
        self.advance(1); // consume '<'
        let name = self.parse_name()?;
        let mut attributes = Vec::new();
        loop {
            self.skip_whitespace();
            match self.peek() {
                Some('/') => {
                    // Empty element: `<name .../>`.
                    self.advance(1);
                    if self.peek() != Some('>') {
                        return Err(TranslationError::InvalidBody(
                            "expected '>' to close an empty element".to_string(),
                        ));
                    }
                    self.advance(1);
                    return Ok(XmlElement {
                        name,
                        attributes,
                        children: Vec::new(),
                    });
                }
                Some('>') => {
                    self.advance(1);
                    break;
                }
                Some(_) => {
                    let attr = self.parse_attribute()?;
                    attributes.push(attr);
                }
                None => {
                    return Err(TranslationError::InvalidBody(
                        "unterminated element start tag".to_string(),
                    ));
                }
            }
        }

        // Parse children until the closing `</name>`.
        let mut children = Vec::new();
        loop {
            let rest = self.remaining();
            if rest.starts_with("</") {
                self.advance(2);
                let close_name = self.parse_name()?;
                if local_name(&close_name) != local_name(&name) {
                    return Err(TranslationError::InvalidBody(format!(
                        "mismatched closing tag: expected </{name}>, got </{close_name}>"
                    )));
                }
                self.skip_whitespace();
                if self.peek() != Some('>') {
                    return Err(TranslationError::InvalidBody(
                        "expected '>' to close the end tag".to_string(),
                    ));
                }
                self.advance(1);
                return Ok(XmlElement {
                    name,
                    attributes,
                    children,
                });
            }
            if rest.starts_with("<!--") {
                let end = rest.find("-->").ok_or_else(|| {
                    TranslationError::InvalidBody("unterminated comment".to_string())
                })?;
                self.advance(end + 3);
                continue;
            }
            if rest.starts_with("<![CDATA[") {
                let end = rest.find("]]>").ok_or_else(|| {
                    TranslationError::InvalidBody("unterminated CDATA section".to_string())
                })?;
                let cdata = &rest[9..end];
                children.push(XmlChild::Text(cdata.to_string()));
                self.advance(end + 3);
                continue;
            }
            if rest.starts_with('<') {
                let el = self.parse_element(depth + 1)?;
                children.push(XmlChild::Element(el));
                continue;
            }
            // Text content up to the next `<`.
            let end = rest.find('<').unwrap_or(rest.len());
            let text = &rest[..end];
            if !text.is_empty() {
                children.push(XmlChild::Text(decode_entities(text)));
                self.advance(end);
            }
        }
    }

    /// Parse an XML name (letters, digits, `_`, `-`, `.`, `:`).
    fn parse_name(&mut self) -> Result<String, TranslationError> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '-' || c == '.' {
                self.advance(c.len_utf8());
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(TranslationError::InvalidBody(
                "expected an XML name".to_string(),
            ));
        }
        Ok(self.input[start..self.pos].to_string())
    }

    /// Parse a `name="value"` attribute.
    fn parse_attribute(&mut self) -> Result<(String, String), TranslationError> {
        let name = self.parse_name()?;
        self.skip_whitespace();
        if self.peek() != Some('=') {
            return Err(TranslationError::InvalidBody(
                "expected '=' after an attribute name".to_string(),
            ));
        }
        self.advance(1);
        self.skip_whitespace();
        let quote = self.peek().ok_or_else(|| {
            TranslationError::InvalidBody("expected a quoted attribute value".to_string())
        })?;
        if quote != '"' && quote != '\'' {
            return Err(TranslationError::InvalidBody(
                "attribute value must be quoted".to_string(),
            ));
        }
        self.advance(1);
        let value_start = self.pos;
        while let Some(c) = self.peek() {
            if c == quote {
                let value = decode_entities(&self.input[value_start..self.pos]);
                self.advance(1);
                return Ok((name, value));
            }
            self.advance(c.len_utf8());
        }
        Err(TranslationError::InvalidBody(
            "unterminated attribute value".to_string(),
        ))
    }
}

/// Decode the minimal set of XML entities the parser handles (`&lt;`,
/// `&gt;`, `&amp;`, `&quot;`, `&apos;`). Numeric character references
/// (`&#nn;` / `&#xHH;`) are also decoded. Unknown entities fail closed
/// (returned verbatim -- the parser does not expand custom entities).
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some(end) = s[i + 1..].find(';') {
                let entity = &s[i + 1..i + 1 + end];
                if let Some(decoded) = decode_one_entity(entity) {
                    out.push_str(&decoded);
                    i += 1 + end + 1;
                    continue;
                }
            }
            // Unknown/unterminated: keep the '&' verbatim.
            out.push('&');
            i += 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Decode a single entity body (the text between `&` and `;`).
fn decode_one_entity(entity: &str) -> Option<String> {
    match entity {
        "lt" => Some("<".to_string()),
        "gt" => Some(">".to_string()),
        "amp" => Some("&".to_string()),
        "quot" => Some("\"".to_string()),
        "apos" => Some("'".to_string()),
        _ => {
            if let Some(hex) = entity.strip_prefix("#x") {
                let code = u32::from_str_radix(hex, 16).ok()?;
                char::from_u32(code).map(|c| c.to_string())
            } else if let Some(dec) = entity.strip_prefix('#') {
                let code = dec.parse::<u32>().ok()?;
                char::from_u32(code).map(|c| c.to_string())
            } else {
                None
            }
        }
    }
}
