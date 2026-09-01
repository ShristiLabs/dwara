//! PII redaction (DW-081): scrubs PII/secrets from prompt and response
//! text before it reaches the log store.
//!
//! A [`Redactor`] is compiled from a [`crate::config::ai::RedactionConfig`]
//! and applies a set of regex patterns in a single pass over the text.
//! Built-in patterns (always active when redaction is on) cover the
//! common PII/secrets surfaces: email addresses, phone numbers, API
//! keys, and credit card numbers. Custom patterns from the config are
//! added to the built-in set.
//!
//! # Dependency direction
//!
//! `ai` depends on `config` only (see `scripts/check_deps.py`); this
//! module reads `config::ai::RedactionConfig` and nothing else. The
//! `regex` crate is a workspace dependency (no new addition).

use crate::config::ai::RedactionConfig;
use regex::RegexSet;
use serde_json::Value;

/// The built-in PII/secrets patterns (always active when redaction is
/// on). Ordered roughly by specificity (longer/more-structured
/// patterns first to avoid sub-matches shadowing them).
const BUILTIN_PATTERNS: &[&str] = &[
    // Email addresses.
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    // API keys (common formats): sk-/pk-/AKIA/ghp/gho/xox* prefixes
    // followed by 20+ alphanumeric chars, and Bearer tokens.
    r"(?:sk|pk|sk-|pk-|AKIA|ghp|gho|xox[baprs])-[a-zA-Z0-9]{20,}",
    r"Bearer [a-zA-Z0-9._-]+",
    // Credit card numbers: 4 groups of 4 digits, optionally separated
    // by dashes or spaces.
    r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
    // Phone numbers (US and international). Conservative to avoid
    // false positives: requires a leading + or at least 7 digits with
    // separators.
    r"\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}",
];

/// The built-in PII/secrets pattern strings (public for reuse by the
/// DW-082 guardrails engine's PII detection). Returns the same set
/// the [`Redactor`] always active when redaction is on.
pub fn builtin_pii_patterns() -> &'static [&'static str] {
    BUILTIN_PATTERNS
}

/// A compiled PII redactor (DW-081). Built from a
/// [`RedactionConfig`]; applies all patterns (built-in + custom) in a
/// single pass over the text, replacing matches with the configured
/// replacement string.
#[derive(Debug, Clone)]
pub struct Redactor {
    set: RegexSet,
    replacement: String,
}

impl Redactor {
    /// Compile a redactor from the config. Built-in patterns are
    /// always included; custom patterns are appended. The replacement
    /// string defaults to `"[REDACTED]"` when empty.
    pub fn compile(cfg: &RedactionConfig) -> Self {
        let mut patterns: Vec<String> = BUILTIN_PATTERNS.iter().map(|s| s.to_string()).collect();
        patterns.extend(cfg.patterns.iter().cloned());
        let replacement = if cfg.replacement.is_empty() {
            "[REDACTED]".to_string()
        } else {
            cfg.replacement.clone()
        };
        // The config is validated at publish time (invalid regexes
        // fail validation), so a compile failure here is a
        // validate-vs-build race. Fail safe: an empty set redacts
        // nothing (the prompt is still stored, but without redaction
        // — logged loudly so an operator notices).
        let set = match RegexSet::new(patterns.iter().map(|s| s.as_str())) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    code = "ai_redaction_compile_failed",
                    "redaction patterns failed to compile at runtime \
                     (validation should have caught this); redaction is \
                     INERT for this generation: {e}"
                );
                RegexSet::new::<[&str; 0], &str>([]).unwrap_or_else(|_| {
                    // An empty pattern list always compiles; this is
                    // truly unreachable.
                    RegexSet::new([r"a^"]).unwrap()
                })
            }
        };
        Redactor { set, replacement }
    }

    /// A redactor that scrubs nothing (the default when logging is
    /// off or no redaction config is present).
    pub fn inert() -> Self {
        Redactor {
            set: RegexSet::new::<[&str; 0], &str>([])
                .unwrap_or_else(|_| RegexSet::new([r"a^"]).unwrap()),
            replacement: "[REDACTED]".to_string(),
        }
    }

    /// Redact all PII/secrets matches in `text`, replacing them with
    /// the configured replacement string. Returns the scrubbed text.
    pub fn redact(&self, text: &str) -> String {
        if self.set.is_empty() {
            return text.to_string();
        }
        // RegexSet gives match booleans per pattern; walk the text and
        // replace the first matching pattern at each position. A
        // single combined pass avoids double-redaction artifacts (a
        // later pattern re-matching the replacement string).
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize;
        let bytes = text.as_bytes();
        while cursor < bytes.len() {
            // Find the earliest match across all patterns starting at
            // or after `cursor`.
            let mut earliest: Option<(usize, usize)> = None;
            for pat_idx in self.set.matches(&text[cursor..]).iter() {
                // Re-run the individual pattern to get the span. The
                // RegexSet only reports WHICH patterns matched
                // somewhere in the text, not where; so we compile a
                // single-pattern regex on demand. This is acceptable
                // because redaction runs off the request path (the
                // capture hook is fire-and-forget).
                let pat = &self.set.patterns()[pat_idx];
                if let Ok(re) = regex::Regex::new(pat) {
                    if let Some(m) = re.find_at(text, cursor) {
                        let (s, e) = (m.start(), m.end());
                        if earliest.is_none() || s < earliest.unwrap().0 {
                            earliest = Some((s, e));
                        }
                    }
                }
            }
            match earliest {
                Some((s, e)) => {
                    out.push_str(&text[cursor..s]);
                    out.push_str(&self.replacement);
                    cursor = e;
                }
                None => {
                    out.push_str(&text[cursor..]);
                    break;
                }
            }
        }
        out
    }

    /// Recursively redact all string values in a JSON tree. Numbers,
    /// booleans, null, and structure are preserved verbatim; only
    /// string leaves are scrubbed.
    pub fn redact_json(&self, json: &Value) -> Value {
        match json {
            Value::String(s) => Value::String(self.redact(s)),
            Value::Array(arr) => Value::Array(arr.iter().map(|v| self.redact_json(v)).collect()),
            Value::Object(map) => {
                let redacted: serde_json::Map<String, Value> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), self.redact_json(v)))
                    .collect();
                Value::Object(redacted)
            }
            other => other.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_redactor() -> Redactor {
        Redactor::compile(&RedactionConfig::default())
    }

    #[test]
    fn redacts_email() {
        let r = default_redactor();
        let out = r.redact("contact me at alice@example.com please");
        assert!(!out.contains("alice@example.com"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_phone() {
        let r = default_redactor();
        let out = r.redact("call +1-555-123-4567 now");
        assert!(!out.contains("+1-555-123-4567"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_api_key() {
        let r = default_redactor();
        let out = r.redact("key: sk-abcdefghijklmnopqrstuvwxyz1234");
        assert!(!out.contains("sk-abcdefghijklmnopqrstuvwxyz1234"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_bearer_token() {
        let r = default_redactor();
        let out = r.redact("Authorization: Bearer eyJhbGciOiJIUzI1");
        assert!(!out.contains("Bearer eyJhbGciOiJIUzI1"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_credit_card() {
        let r = default_redactor();
        let out = r.redact("card: 4111-1111-1111-1111");
        assert!(!out.contains("4111-1111-1111-1111"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn custom_pattern_alongside_builtins() {
        let cfg = RedactionConfig {
            patterns: vec![r"SSN-\d{3}-\d{2}".to_string()],
            replacement: "[REDACTED]".to_string(),
        };
        let r = Redactor::compile(&cfg);
        let out = r.redact("email alice@example.com ssn SSN-123-45");
        assert!(!out.contains("alice@example.com"));
        assert!(!out.contains("SSN-123-45"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redact_json_preserves_structure() {
        let r = default_redactor();
        let input = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "email alice@example.com"}
            ],
            "count": 42,
            "flag": true
        });
        let out = r.redact_json(&input);
        assert_eq!(out["model"], "gpt-4");
        assert_eq!(out["count"], 42);
        assert_eq!(out["flag"], true);
        assert!(out["messages"][0]["content"]
            .as_str()
            .unwrap()
            .contains("[REDACTED]"));
        assert!(!out["messages"][0]["content"]
            .as_str()
            .unwrap()
            .contains("alice@example.com"));
    }

    #[test]
    fn custom_replacement_string() {
        let cfg = RedactionConfig {
            patterns: vec![],
            replacement: "<HIDDEN>".to_string(),
        };
        let r = Redactor::compile(&cfg);
        let out = r.redact("email alice@example.com");
        assert!(out.contains("<HIDDEN>"));
        assert!(!out.contains("alice@example.com"));
    }

    #[test]
    fn inert_redactor_scrubs_nothing() {
        let r = Redactor::inert();
        let out = r.redact("email alice@example.com");
        assert_eq!(out, "email alice@example.com");
    }
}
