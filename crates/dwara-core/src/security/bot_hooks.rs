//! Bot detection hooks (DW-109).
//!
//! STUB: this module is a placeholder so the `pub mod bot_hooks;`
//! declaration in `security/mod.rs` resolves. The full bot-detection
//! engine (regex-based pre-request and post-response checks, like
//! WAF-lite DW-051) is not yet implemented. The module compiles in
//! every build (no feature gate) but is inert until the engine lands.

/// A compiled bot-hooks engine (stub). No hooks are compiled; every
/// request passes through unchecked.
#[derive(Debug, Clone, Default)]
pub struct BotHooksEngine;

impl BotHooksEngine {
    /// Build an empty (inert) engine.
    pub fn empty() -> Self {
        Self
    }
}
