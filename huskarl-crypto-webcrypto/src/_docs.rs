//! Task-oriented and conceptual documentation for the WebCrypto backend.
//!
//! Choose a section by what you need:
//!
//! - **[How-to guides](guide)** — task-oriented recipes for browser crypto.
//! - **[Explanation](explanation)** — understanding-oriented background on how
//!   the crate works and why it is shaped the way it is.
//! - **Reference** — the crate's API modules describe its key types, algorithms,
//!   parameters, and return values.
//!
//! This module is documentation only; it contains no runnable API.

/// Task-oriented recipes.
pub mod guide {
    #[doc = include_str!("../docs/guide/signing_a_jwt.md")]
    pub mod signing_a_jwt {}
}

/// Understanding-oriented background on the crate's design.
pub mod explanation {
    #[doc = include_str!("../docs/explanation/platform_constraints.md")]
    pub mod platform_constraints {}
}
