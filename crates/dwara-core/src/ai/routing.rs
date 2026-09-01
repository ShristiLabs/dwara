//! AI routing decisions (DW-076): which provider/model serves one
//! request, and in what order to fail over.
//!
//! Pure functions over the compiled [`AiRuntime`](crate::ai::AiRuntime)
//! structures — no I/O, no clocks, no shared state. The dataplane's AI
//! action calls [`route`](crate::ai::AiRuntime::route) once per request
//! and walks the returned candidates; this module owns the two
//! decision kinds:
//!
//! - **Failover chain** (an alias with `failover:`): candidates are
//!   `[primary, alternates...]` in config order. The action tries each
//!   in turn on 429/5xx/transport errors and STOPS at the first
//!   non-retryable outcome. Same-provider retries are not the chain's
//!   job — the provider's upstream breaker owns those.
//! - **Canary split** (an alias with `canary:`): ONE candidate is
//!   picked deterministically by a weighted hash of the pick key (the
//!   request id), using the same slot semantics as the dataplane's
//!   traffic splitting: cumulative bounds over weights, `hash % total`
//!   selects the slot, and the entry whose bound first exceeds the
//!   slot wins. Deterministic means re-sends with the same request id
//!   land on the same version, and ratios hold per request (converging
//!   statistically over distinct ids).
//!
//! The hash is an explicit 64-bit FNV-1a rather than
//! `std::collections::hash_map::DefaultHasher`: the pick must be stable
//! across toolchain versions (it is arithmetic on the bytes, not a
//! seeded SipHash) because canary attribution compares series across
//! process restarts. This mirrors why `dataplane::balance::key_hash`
//! exists — but duplicated here in four lines rather than importing
//! upward from `dataplane`, which the dependency direction forbids.

/// The FNV-1a 64-bit offset basis.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// The FNV-1a 64-bit prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Toolchain-stable 64-bit FNV-1a over UTF-8 bytes. Deterministic for
/// a given input forever; good enough distribution for slot picks.
pub fn pick_hash(key: &str) -> u64 {
    let mut h = FNV_OFFSET;
    for b in key.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// The deterministic weighted pick over `(weight, T)` entries: the
/// entry whose cumulative weight bound first exceeds
/// `pick_hash(key) % total`. Mirrors `dataplane::split`'s slot walk
/// over at most a handful of entries (validation bounds canary lists),
/// so a linear scan is cheaper than any index. `total` must be > 0
/// (validation guarantees it: weights are >= 1 and the list
/// non-empty).
pub fn weighted_pick<'a, T>(entries: &'a [(u32, T)], key: &str) -> &'a T {
    let total: u64 = entries.iter().map(|(w, _)| u64::from(*w)).sum();
    debug_assert!(total > 0, "validation guarantees positive total weight");
    let slot = pick_hash(key) % total;
    let mut bound = 0u64;
    for (w, item) in entries {
        bound += u64::from(*w);
        if slot < bound {
            return item;
        }
    }
    // Unreachable for total > 0 (the last bound IS the total); the
    // fallthrough keeps a hostile zero-weight list from panicking.
    &entries[0].1
}

#[cfg(test)]
mod tests {
    use super::*;

    // White-box: the slot arithmetic is private behavior; the
    // end-to-end convergence is covered by tests/ai_routing.rs against
    // the real gateway. These stay here with that justification.

    #[test]
    fn hash_is_stable_for_known_inputs() {
        // FNV-1a 64 of "" and "a" — fixed vectors pin the arithmetic.
        assert_eq!(pick_hash(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(pick_hash("a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn pick_is_deterministic_and_respects_zero_slots() {
        let entries = vec![(10u32, "wide"), (0u32, "parked")];
        // The zero-weight entry can never win when the other has all
        // the slots... with total 10, slot < 10 always lands on "wide".
        for key in ["a", "b", "c", "d", "e", "f", "g"] {
            assert_eq!(weighted_pick(&entries, key), &"wide");
        }
        // Same key, same pick, always.
        assert_eq!(
            weighted_pick(&entries, "same"),
            weighted_pick(&entries, "same")
        );
    }

    #[test]
    fn single_entry_always_wins() {
        let entries = vec![(1u32, "only")];
        for key in ["", "x", "long-request-id-123"] {
            assert_eq!(weighted_pick(&entries, key), &"only");
        }
    }
}
