//! A deliberately tiny flat-JSON reader for plugin configuration.
//!
//! dwara hands a plugin's `config:` string to `proxy_on_configure`
//! as raw bytes; the convention is a small JSON object the plugin
//! parses itself. These example plugins depend on nothing, so instead
//! of pulling a JSON crate into the wasm module they use this
//! purpose-built reader, which supports exactly what plugin configs
//! need: a flat object whose values are strings or arrays of strings.
//!
//! Supported: `{ "key": "value", "key2": ["a", "b"] }` with standard
//! whitespace, empty arrays, empty objects, and the string escapes
//! `\"` `\\` `\/` `\b` `\f` `\n` `\r` `\t`. Anything else (nested
//! objects, numbers, booleans, null, `\uXXXX`) is rejected with an
//! error, so a malformed config fails closed at configure time
//! instead of misbehaving per request.

// A shared helper file: not every consumer uses every accessors.
#![allow(dead_code)]

/// A parsed JSON value: a string or an array of strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Str(String),
    Arr(Vec<String>),
}

impl JsonValue {
    /// The value as a string, or `None` when it is an array.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::Str(s) => Some(s),
            JsonValue::Arr(_) => None,
        }
    }

    /// The value as an array of strings, or `None` when it is a
    /// string.
    pub fn as_arr(&self) -> Option<&[String]> {
        match self {
            JsonValue::Str(_) => None,
            JsonValue::Arr(items) => Some(items),
        }
    }
}

/// Parse a flat JSON object into ordered key/value pairs. Duplicate
/// keys keep the first occurrence (last-write-wins is a footgun for
/// security-relevant config).
pub fn parse_flat_object(bytes: &[u8]) -> Result<Vec<(String, JsonValue)>, String> {
    let mut parser = Parser { bytes, pos: 0 };
    parser.skip_ws();
    parser.expect(b'{')?;
    let mut pairs = Vec::new();
    parser.skip_ws();
    if parser.peek() == Some(b'}') {
        parser.pos += 1;
    } else {
        loop {
            parser.skip_ws();
            let key = parser.parse_string()?;
            parser.skip_ws();
            parser.expect(b':')?;
            parser.skip_ws();
            let value = parser.parse_value()?;
            if !pairs.iter().any(|(k, _): &(String, JsonValue)| *k == key) {
                pairs.push((key, value));
            }
            parser.skip_ws();
            match parser.peek() {
                Some(b',') => {
                    parser.pos += 1;
                }
                Some(b'}') => {
                    parser.pos += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", parser.pos)),
            }
        }
    }
    parser.skip_ws();
    if parser.pos != bytes.len() {
        return Err(format!("trailing data at byte {}", parser.pos));
    }
    Ok(pairs)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        match self.peek() {
            Some(b) if b == byte => {
                self.pos += 1;
                Ok(())
            }
            _ => Err(format!("expected '{}' at byte {}", byte as char, self.pos)),
        }
    }

    fn skip_ws(&mut self) {
        while matches!(
            self.peek(),
            Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')
        ) {
            self.pos += 1;
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            match self.peek() {
                None => return Err("unterminated string".to_string()),
                Some(b'"') => {
                    self.pos += 1;
                    // Raw bytes are copied verbatim above, so valid
                    // UTF-8 in the input survives intact and anything
                    // else is rejected here.
                    return String::from_utf8(out)
                        .map_err(|_| "string is not valid UTF-8".to_string());
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'"') => out.push(b'"'),
                        Some(b'\\') => out.push(b'\\'),
                        Some(b'/') => out.push(b'/'),
                        Some(b'b') => out.push(0x08),
                        Some(b'f') => out.push(0x0C),
                        Some(b'n') => out.push(b'\n'),
                        Some(b'r') => out.push(b'\r'),
                        Some(b't') => out.push(b'\t'),
                        other => {
                            return Err(format!(
                                "unsupported escape '\\{}' at byte {}",
                                other.map(|b| b as char).unwrap_or('?'),
                                self.pos
                            ));
                        }
                    }
                    self.pos += 1;
                }
                Some(byte) if byte < 0x20 => {
                    return Err(format!("control character at byte {}", self.pos));
                }
                Some(byte) => {
                    out.push(byte);
                    self.pos += 1;
                }
            }
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, String> {
        match self.peek() {
            Some(b'"') => Ok(JsonValue::Str(self.parse_string()?)),
            Some(b'[') => {
                self.pos += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(JsonValue::Arr(items));
                }
                loop {
                    self.skip_ws();
                    items.push(self.parse_string()?);
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => {
                            self.pos += 1;
                        }
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(JsonValue::Arr(items));
                        }
                        _ => {
                            return Err(format!("expected ',' or ']' at byte {}", self.pos));
                        }
                    }
                }
            }
            _ => Err(format!(
                "expected a string or array of strings at byte {} \
                 (numbers, booleans, null, and nested objects are not supported)",
                self.pos
            )),
        }
    }
}
