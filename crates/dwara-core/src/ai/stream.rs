//! Streaming translation (DW-077): provider SSE in, OpenAI SSE out,
//! frame by frame.
//!
//! The [`StreamTranslator`] is the pure half of the streaming path:
//! feed it the provider's response BYTES as they arrive and it returns
//! the client-facing SSE TEXT to forward for exactly those bytes —
//! nothing is held: a complete provider frame becomes complete client
//! frames in the same poll, and a partial frame stays in the
//! [`SseDecoder`] buffer (bounded by the provider's own frame size)
//! until its terminator arrives.
//!
//! The dataplane's `AiStreamBody` (see `dataplane/ai_proxy.rs`) drives
//! this translator over the upstream body and owns the metrics hooks.
//!
//! # Client-facing stream shape
//!
//! The client is OpenAI-shaped regardless of provider dialect:
//!
//! - each provider delta becomes one `data: {chat.completion.chunk}`
//!   frame (via [`openai_compat::stream_event_to_openai_chunk`]),
//! - provider `Usage` events are ACCUMULATED (not forwarded inline) —
//!   they merge across the stream (Anthropic reports input tokens at
//!   `message_start` and output tokens at `message_delta`) —
//! - at stream end the accumulated usage (if any) is emitted as ONE
//!   terminal `choices: []` usage chunk (the `stream_options.
//!   include_usage` shape), and the gateway ALWAYS writes its own
//!   `data: [DONE]` terminator (the provider's own terminator is
//!   swallowed, even OpenAI's, so the terminal ordering is uniform:
//!   deltas, usage, DONE).
//!
//! # Token counting (the locked decision)
//!
//! Token counts are PROVIDER-REPORTED ONLY. The translator accumulates
//! the usage events the provider emits mid-stream; there is no local
//! estimation, and chunk counts / text lengths are never presented as
//! token estimates.
//!
//! # Mid-stream aborts
//!
//! [`StreamTranslator::abort_tail`] produces the terminal frames for a
//! provider stream that died after frames were already forwarded: an
//! OpenAI-shaped error chunk then `data: [DONE]` — the stream ends
//! cleanly for the client instead of a connection reset, and the
//! already-forwarded content stands.

use crate::ai::adapter::ProviderAdapter;
use crate::ai::openai_compat;
use crate::ai::sse::{SseDecoder, SseFrame};
use crate::ai::types::{StreamEvent, Usage};
use serde_json::Value;

/// One translated client frame (raw SSE text, terminator included).
pub type ClientFrame = String;

/// Pure streaming translator state (DW-077).
pub struct StreamTranslator {
    decoder: SseDecoder,
    /// Provider-reported usage accumulated across the stream.
    usage: Usage,
    /// The provider signalled end-of-stream (its terminator event, its
    /// `[DONE]` sentinel, or the body's clean end).
    ended: bool,
    /// The terminal frames (usage chunk + gateway [DONE]) were
    /// emitted. Distinct from `ended`: the provider's own terminator
    /// sets `ended` mid-stream, and the terminal frames must STILL be
    /// emitted afterwards — exactly once.
    tail_emitted: bool,
    /// Identity stamped on every client chunk.
    id: String,
    model_alias: String,
    created: u64,
}

impl StreamTranslator {
    /// New translator stamping chunks with `id` (the response id),
    /// `model_alias` (what the client asked for — never the provider
    /// model), and `created` (unix seconds, fixed at stream start).
    pub fn new(id: String, model_alias: String, created: u64) -> Self {
        StreamTranslator {
            decoder: SseDecoder::new(),
            usage: Usage::default(),
            ended: false,
            tail_emitted: false,
            id,
            model_alias,
            created,
        }
    }

    /// Feed provider bytes; returns the client frames for every
    /// COMPLETE provider frame these bytes complete (may be empty —
    /// bytes that only continue a partial frame). Also reports how
    /// many delta chunks were forwarded and whether one of them was
    /// the FIRST forwarded chunk of the stream (the first-token
    /// signal).
    pub fn feed(
        &mut self,
        bytes: &[u8],
        adapter: &dyn ProviderAdapter,
    ) -> (Vec<ClientFrame>, usize, bool) {
        let frames = self.decoder.push(bytes);
        self.translate(frames, adapter)
    }

    /// Flush a final provider frame not terminated by a blank line
    /// (tolerant providers exist; well-formed streams yield nothing
    /// here — the body's clean end drives [`Self::finish`]).
    pub fn flush_partial(
        &mut self,
        adapter: &dyn ProviderAdapter,
    ) -> (Vec<ClientFrame>, usize, bool) {
        let frames = self.decoder.finish();
        self.translate(frames, adapter)
    }

    fn translate(
        &mut self,
        frames: Vec<SseFrame>,
        adapter: &dyn ProviderAdapter,
    ) -> (Vec<ClientFrame>, usize, bool) {
        let mut out = Vec::new();
        let mut chunk_count = 0usize;
        let mut first = false;
        for frame in frames {
            // The provider's own end-of-stream sentinel (OpenAI
            // `[DONE]`): swallowed — the gateway writes its own
            // terminator in `finish`.
            if Some(frame.data.as_str()) == adapter.stream_done_sentinel() {
                self.ended = true;
                continue;
            }
            let Ok(data) = serde_json::from_str::<Value>(&frame.data) else {
                // A non-JSON data line is a provider bug; skip the
                // frame rather than kill the stream.
                continue;
            };
            let Ok(events) = adapter.parse_stream_event(&data) else {
                // Same posture as a non-JSON line: one bad frame must
                // not take down an otherwise healthy stream.
                continue;
            };
            for event in events {
                match event {
                    StreamEvent::Delta(delta) => {
                        let chunk = openai_compat::stream_event_to_openai_chunk(
                            &StreamEvent::Delta(delta),
                            &self.id,
                            &self.model_alias,
                            self.created,
                        );
                        out.push(sse_data(&chunk));
                        chunk_count += 1;
                        first = true;
                    }
                    StreamEvent::Usage(u) => {
                        // Accumulated, not forwarded: one terminal
                        // usage chunk at stream end carries the merged
                        // provider-reported totals.
                        self.usage.merge(u);
                    }
                    StreamEvent::Done => {
                        self.ended = true;
                    }
                }
            }
        }
        // `first` is only true for the first TRANSLATED batch that
        // contained a delta; the caller treats it as the first-token
        // signal when it has not seen one yet.
        (out, chunk_count, first)
    }

    /// The terminal frames for a CLEAN stream end: the accumulated
    /// usage chunk (when the provider reported any usage) followed by
    /// the gateway's own `data: [DONE]`. Returns them once; later
    /// calls return empty (idempotent tail).
    pub fn finish(&mut self) -> Vec<ClientFrame> {
        if self.tail_emitted {
            return Vec::new();
        }
        self.tail_emitted = true;
        self.ended = true;
        let mut out = Vec::new();
        if self.usage.prompt_tokens.is_some() || self.usage.completion_tokens.is_some() {
            let usage = openai_compat::stream_event_to_openai_chunk(
                &StreamEvent::Usage(self.usage),
                &self.id,
                &self.model_alias,
                self.created,
            );
            out.push(sse_data(&usage));
        }
        out.push("data: [DONE]\n\n".to_string());
        out
    }

    /// The terminal frames for a MID-STREAM ABORT (the provider body
    /// errored after frames were forwarded): an OpenAI-shaped error
    /// chunk then the terminator. Already-forwarded content stands.
    pub fn abort_tail(&mut self, message: &str) -> Vec<ClientFrame> {
        self.tail_emitted = true;
        self.ended = true;
        vec![
            sse_data(&openai_compat::error_body(
                message,
                "api_error",
                Some("provider_stream_aborted"),
                &self.id,
            )),
            "data: [DONE]\n\n".to_string(),
        ]
    }

    /// Whether the provider signalled end-of-stream (its terminator or
    /// the body's clean end already consumed).
    pub fn is_ended(&self) -> bool {
        self.ended
    }

    /// The accumulated provider-reported usage so far.
    pub fn usage(&self) -> Usage {
        self.usage
    }
}

/// Serialize one JSON value as an SSE `data:` frame (event streams to
/// OpenAI clients carry only data lines).
fn sse_data(v: &Value) -> String {
    format!("data: {}\n\n", v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::adapter::adapter_for;
    use crate::config::ai::AiProviderKind;

    // White-box: the translator is the private half of the streaming
    // pipeline; the gateway-level behavior is covered end to end by
    // tests/ai_streaming.rs. These pin the frame grammar cheaply.

    #[test]
    fn openai_deltas_translate_and_terminator_is_swallowed() {
        let mut t = StreamTranslator::new("chatcmpl-x".into(), "alias".into(), 7);
        let adapter = adapter_for(AiProviderKind::Openai);
        let (frames, n, first) = t.feed(
            concat!(
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"he\"}}]}\n\n",
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"llo\"}}]}\n\n"
            )
            .as_bytes(),
            adapter,
        );
        assert_eq!(n, 2);
        assert!(first);
        assert_eq!(frames.len(), 2);
        assert!(frames[0].starts_with("data: {"));
        assert!(frames[0].contains("chat.completion.chunk"));
        assert!(frames[1].contains("llo"));
        // The provider's [DONE] is swallowed; OUR finish writes it.
        let (_, n2, _) = t.feed(b"data: [DONE]\n\n", adapter);
        assert_eq!(n2, 0);
        assert!(t.is_ended());
    }

    #[test]
    fn usage_accumulates_and_finish_emits_one_terminal_chunk() {
        let mut t = StreamTranslator::new("c".into(), "m".into(), 1);
        let adapter = adapter_for(AiProviderKind::Anthropic);
        // input tokens at message_start, output tokens at message_delta
        t.feed(
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":100}}}\n\n",
            adapter,
        );
        t.feed(
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":50}}\n\n",
            adapter,
        );
        let tail = t.finish();
        assert_eq!(tail.len(), 2);
        assert!(tail[0].contains("\"prompt_tokens\":100"));
        assert!(tail[0].contains("\"completion_tokens\":50"));
        assert!(tail[0].contains("\"choices\":[]"));
        assert_eq!(tail[1], "data: [DONE]\n\n");
        // Idempotent: a second finish yields nothing.
        assert!(t.finish().is_empty());
    }

    #[test]
    fn abort_tail_shapes_an_error_chunk_then_done() {
        let mut t = StreamTranslator::new("c".into(), "m".into(), 1);
        let tail = t.abort_tail("the model provider closed the stream");
        assert_eq!(tail.len(), 2);
        assert!(tail[0].contains("provider_stream_aborted"));
        assert!(tail[0].contains("the model provider closed the stream"));
        assert_eq!(tail[1], "data: [DONE]\n\n");
    }

    #[test]
    fn bad_frames_are_skipped_not_fatal() {
        let mut t = StreamTranslator::new("c".into(), "m".into(), 1);
        let adapter = adapter_for(AiProviderKind::Openai);
        let (frames, n, _) = t.feed(b"data: not-json\n\n", adapter);
        assert_eq!(n, 0);
        assert!(frames.is_empty());
        // The stream continues after the bad frame.
        let (frames2, n2, _) = t.feed(
            b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\n",
            adapter,
        );
        assert_eq!(n2, 1);
        assert_eq!(frames2.len(), 1);
    }
}
