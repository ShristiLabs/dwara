//! Provider dialect implementations (DW-075). Each module is a
//! stateless [`ProviderAdapter`](crate::ai::adapter::ProviderAdapter)
//! singleton; see the module docs of each for its translation notes.

pub mod anthropic;
pub mod gemini;
pub mod openai;
