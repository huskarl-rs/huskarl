//! Task-oriented and conceptual documentation for the native crypto backend.
//!
//! Choose a section by what you need:
//!
//! - **[How-to guides](guide)** — task-oriented recipes for loading keys.
//! - **[Explanation](explanation)** — understanding-oriented background on how
//!   the crate works and why it is shaped the way it is.
//! - **Reference** — the crate's API modules describe its key types, algorithms,
//!   parameters, and return values.
//!
//! This module is documentation only; it contains no runnable API.

/// Task-oriented recipes for getting a key into the crate.
pub mod guide {
    #[doc = include_str!("../docs/guide/loading_a_signing_key.md")]
    pub mod loading_a_signing_key {}
}

/// Understanding-oriented background on the crate's design.
pub mod explanation {
    #[doc = include_str!("../docs/explanation/jwk_as_key_format.md")]
    pub mod jwk_as_key_format {}
}
