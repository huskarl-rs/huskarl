//! Task-oriented and conceptual documentation for the Google Cloud backend.
//!
//! Choose a section by what you need:
//!
//! - **[How-to guides](guide)** — task-oriented recipes for signing, encrypting,
//!   serving public keys, refreshing keys under rotation, and reading secrets.
//! - **[Explanation](explanation)** — understanding-oriented background on how
//!   the crate works and why it is shaped the way it is.
//! - **Reference** — the crate's API modules describe its types, methods,
//!   parameters, and return values.
//!
//! This module is documentation only; it contains no runnable API. It is gated
//! on `cfg(docsrs)`, so its code blocks are real doctests that run only under
//! `RUSTDOCFLAGS="--cfg docsrs" cargo +nightly test --doc` (mirroring the
//! docs.rs build environment); a plain `cargo test --doc` skips them.

/// Task-oriented recipes for signing, encrypting, and reading secrets.
pub mod guide {
    #[doc = include_str!("../docs/guide/asymmetric_signing.md")]
    pub mod asymmetric_signing {}

    #[doc = include_str!("../docs/guide/symmetric_crypto.md")]
    pub mod symmetric_crypto {}

    #[doc = include_str!("../docs/guide/refreshing_keys.md")]
    pub mod refreshing_keys {}

    #[doc = include_str!("../docs/guide/secret_manager.md")]
    pub mod secret_manager {}
}

/// Understanding-oriented background on how the crate works and why.
pub mod explanation {
    #[doc = include_str!("../docs/explanation/versions_and_rotation.md")]
    pub mod versions_and_rotation {}

    #[doc = include_str!("../docs/explanation/key_ids.md")]
    pub mod key_ids {}

    #[doc = include_str!("../docs/explanation/error_handling.md")]
    pub mod error_handling {}
}
