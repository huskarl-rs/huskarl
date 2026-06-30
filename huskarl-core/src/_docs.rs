//! Extended documentation: how-to guides and explanation.
//!
//! The API items in this crate are the **reference** documentation — they say
//! what each utility is and how to call it. These pages cover the other
//! [Diátaxis](https://diataxis.fr) quadrants:
//!
//! - **[How-to guides](guide)** — task-oriented recipes for the things people
//!   reach for this crate to do: building and validating JWTs, providing
//!   secrets, and plugging in a transport or crypto backend.
//! - **[Explanation](explanation)** — understanding-oriented background on how
//!   the crate works and why it is shaped the way it is.
//!
//! This module is documentation only; it contains no runnable API. It is gated
//! on `cfg(docsrs)`, so its code blocks are real doctests that run only under
//! `RUSTDOCFLAGS="--cfg docsrs" cargo +nightly test --doc` (mirroring the
//! docs.rs build environment); a plain `cargo test --doc` skips them.

/// Task-oriented recipes for building JWTs, handling secrets, and plugging in
/// backends.
pub mod guide {
    #[doc = include_str!("../docs/guide/signing_a_jwt.md")]
    pub mod signing_a_jwt {}

    #[doc = include_str!("../docs/guide/validating_a_jwt.md")]
    pub mod validating_a_jwt {}

    #[doc = include_str!("../docs/guide/providing_secrets.md")]
    pub mod providing_secrets {}

    #[doc = include_str!("../docs/guide/implementing_a_backend.md")]
    pub mod implementing_a_backend {}
}

/// Understanding-oriented background on how the crate works and why.
pub mod explanation {
    #[doc = include_str!("../docs/explanation/error_handling.md")]
    pub mod error_handling {}

    #[doc = include_str!("../docs/explanation/untrusted_keys.md")]
    pub mod untrusted_keys {}

    #[doc = include_str!("../docs/explanation/crypto_strategies.md")]
    pub mod crypto_strategies {}
}
