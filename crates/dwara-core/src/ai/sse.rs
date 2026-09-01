//! Hand-rolled SSE framing (DW-075).
//!
//! The locked M4 dependency decision is in-house framing: the
//! `text/event-stream` wire format is small enough (a line grammar over
//! a byte stream) that pulling an SSE crate — and the transitive
//! futures-stack it would drag into the AI domain — buys nothing. This
//! decoder implements the parts the provider dialects actually use:
//!
//! - events are separated by a blank line (`\n\n` or `\r\n\r\n`),
//! - `data:` lines carry the payload (multiple `data:` lines in one
//!   event join with `\n`, per the WHATWG spec),
//! - `event:` names the event (Anthropic sends `event: message_start`
//!   alongside the data payload),
//! - `id:` and `retry:` lines are ignored, and `:`-prefixed comment
//!   lines are ignored,
//! - leading whitespace after the field name is stripped once.
//!
//! What it deliberately does NOT do: charset negotiation,
//! `Last-Event-ID` resumption (providers do not support it), or BOM
//! sniffing — none of the shipped dialects use any of that.

/// One decoded SSE event: its optional name and its data payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseFrame {
    pub event: Option<String>,
    pub data: String,
}

/// An incremental SSE decoder: feed it raw bytes as they arrive, take
/// complete frames back. Call [`SseDecoder::finish`] at stream end to
/// recover a final frame not terminated by a blank line (tolerant
/// providers exist; a well-formed stream yields nothing there).
#[derive(Debug, Default)]
pub struct SseDecoder {
    buf: String,
}

impl SseDecoder {
    pub fn new() -> Self {
        SseDecoder { buf: String::new() }
    }

    /// Feed raw bytes; returns every frame completed by this chunk.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<SseFrame> {
        // Provider streams are ASCII JSON; lossy conversion only ever
        // replaces bytes on a malformed (non-UTF-8) stream, where the
        // JSON parse downstream fails loudly anyway.
        self.buf.push_str(&String::from_utf8_lossy(bytes));
        self.drain()
    }

    /// Flush any buffered partial frame at stream end.
    pub fn finish(&mut self) -> Vec<SseFrame> {
        let rest = std::mem::take(&mut self.buf);
        if rest.trim().is_empty() {
            Vec::new()
        } else {
            parse_frame(&rest).into_iter().collect()
        }
    }

    /// Split every COMPLETE frame (terminated by a blank line) off the
    /// buffer.
    fn drain(&mut self) -> Vec<SseFrame> {
        let mut frames = Vec::new();
        while let Some((text_end, term_len)) = find_event_end(&self.buf) {
            let frame_text = self.buf[..text_end].to_string();
            self.buf.drain(..text_end + term_len);
            // A blank separator with no event text (or a comment-only
            // keepalive block) produces no frame.
            if let Some(frame) = parse_frame(&frame_text) {
                frames.push(frame);
            }
        }
        frames
    }
}

/// Find the first COMPLETE event terminator in `s`.
///
/// Returns `(event_text_end, terminator_len)`: the event text is
/// `s[..event_text_end]` and the terminator is the `terminator_len`
/// bytes starting there. Recognized blank-line spellings (a data line
/// ending plus an empty line, in any LF/CRLF mix):
///
/// - `\n\n` — event text ends at the first `\n`, width 2.
/// - `\r\n\r\n` — event text ends before the first `\r`, width 4.
/// - `\n\r\n` — an LF-ended data line followed by a CRLF blank line:
///   event text ends at the `\n`, width 3.
///
/// A buffer that ends mid-terminator (`... \n\r`, possibly the first
/// half of a `\r\n\r\n` or `\n\r\n`) matches NOTHING: the caller must
/// wait for more bytes rather than split on a partial terminator.
fn find_event_end(s: &str) -> Option<(usize, usize)> {
    let b = s.as_bytes();
    for i in 0..b.len() {
        if b[i] != b'\n' {
            continue;
        }
        // "\n\n": the event text ends at i.
        if i + 1 < b.len() && b[i + 1] == b'\n' {
            return Some((i, 2));
        }
        // A "\r\n" blank line follows. Where the event text ends
        // depends on how the DATA line ended: "\r\n\r\n" puts a "\r"
        // just before i (it belongs to the terminator); "\n\r\n" does
        // not.
        if i + 2 < b.len() && b[i + 1] == b'\r' && b[i + 2] == b'\n' {
            return if i >= 1 && b[i - 1] == b'\r' {
                Some((i - 1, 4))
            } else {
                Some((i, 3))
            };
        }
    }
    None
}

/// Parse one event's text into a frame. Comment-only events (keepalive
/// `:` pings) return None — they carry no data.
fn parse_frame(text: &str) -> Option<SseFrame> {
    let mut event = None;
    let mut data_lines: Vec<String> = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (name, value) = match line.split_once(':') {
            Some((n, v)) => (n, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        match name {
            "data" => data_lines.push(value.to_string()),
            "event" => event = Some(value.to_string()),
            _ => {}
        }
    }
    if data_lines.is_empty() {
        return None;
    }
    Some(SseFrame {
        event,
        data: data_lines.join("\n"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // White-box: the decoder's frame grammar is private behavior not
    // yet exercised through a public caller (the gateway streaming
    // path is DW-077); these stay here with that justification and are
    // additionally replayed through adapter stream tests in
    // tests/ai_adapters.rs.

    fn datas(dec: &mut SseDecoder, chunk: &str) -> Vec<String> {
        dec.push(chunk.as_bytes())
            .into_iter()
            .map(|f| f.data)
            .collect()
    }

    #[test]
    fn splits_two_events_in_one_chunk() {
        let mut dec = SseDecoder::new();
        let out = datas(&mut dec, "event: x\ndata: one\n\ndata: two\n\n");
        assert_eq!(out, vec!["one".to_string(), "two".to_string()]);
    }

    #[test]
    fn assembles_event_split_across_chunks() {
        let mut dec = SseDecoder::new();
        assert!(datas(&mut dec, "data: par").is_empty());
        assert!(datas(&mut dec, "tial\n").is_empty());
        assert_eq!(datas(&mut dec, "\n"), vec!["partial".to_string()]);
    }

    #[test]
    fn crlf_line_endings_and_comments() {
        let mut dec = SseDecoder::new();
        let out = dec.push(b": keepalive\r\n\r\nevent: m\r\ndata: {\"a\":1}\r\n\r\n");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].event.as_deref(), Some("m"));
        assert_eq!(out[0].data, "{\"a\":1}");
    }

    #[test]
    fn waits_on_partial_crlf_terminator() {
        let mut dec = SseDecoder::new();
        // "...\n\r" could be the first half of an "\r\n\r\n"
        // terminator — must NOT emit yet.
        assert!(datas(&mut dec, "data: x\n\r").is_empty());
        assert_eq!(datas(&mut dec, "\n"), vec!["x".to_string()]);
    }

    #[test]
    fn multiple_data_lines_join_with_newline() {
        let mut dec = SseDecoder::new();
        assert_eq!(
            datas(&mut dec, "data: a\ndata: b\n\n"),
            vec!["a\nb".to_string()]
        );
    }

    #[test]
    fn finish_recovers_unterminated_frame() {
        let mut dec = SseDecoder::new();
        assert!(datas(&mut dec, "data: tail").is_empty());
        let out = dec.finish();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].data, "tail");
    }
}
