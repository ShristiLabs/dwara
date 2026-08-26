//! Fuzz the HTTP/1 head hardening parsers (DW-025): `head_end`,
//! `head_is_ambiguous`, and `head_has_obs_fold` over arbitrary bytes.
//!
//! The input is exercised twice: once as a raw buffer (a head still being
//! sniffed, possibly incomplete) and once split into head/body halves at
//! a data-derived position — the shape the sniff loop actually sees once
//! the terminator is found and the body follows. Only the panic-freedom
//! of the parsers is asserted (a found CL+TE pair or obs-fold is a
//! rejection, never a crash).

#![no_main]

use dwara_core::hardening::{head_end, head_has_obs_fold, head_is_ambiguous};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let end = head_end(data);
    let ambiguous = head_is_ambiguous(data);
    let folded = head_has_obs_fold(data);
    let _ = std::hint::black_box((end, ambiguous, folded));

    // Head/body split at a position derived from the data itself.
    if !data.is_empty() {
        let split = (data[0] as usize) % data.len();
        let (head, body) = data.split_at(split);
        let end = head_end(head);
        let ambiguous = head_is_ambiguous(head);
        let folded = head_has_obs_fold(head);
        let _ = std::hint::black_box((end, ambiguous, folded, body.len()));
    }
});
