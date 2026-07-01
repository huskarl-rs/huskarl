//! Extended documentation: explanation and how-to guides.
//!
//! The API items in this crate are the **reference** documentation — they say
//! what each type and method is. These pages cover the other
//! [Diátaxis](https://diataxis.fr) quadrants:
//!
//! - **[Explanation](explanation)** — understanding-oriented background on how
//!   the crate works and why it is shaped the way it is.
//! - **[How-to guides](guide)** — task-oriented recipes for wiring a validator
//!   into a resource server.
//!
//! This module is documentation only; it contains no runnable API. It is gated
//! on `cfg(docsrs)`, so its code blocks are real doctests that run only under
//! `RUSTDOCFLAGS="--cfg docsrs" cargo +nightly test --doc` (mirroring the
//! docs.rs build environment); a plain `cargo test --doc` skips them.

/// Understanding-oriented background on how the crate works and why.
pub mod explanation {
    #[doc = include_str!("../docs/explanation/choosing_a_validator.md")]
    pub mod choosing_a_validator {}

    #[doc = include_str!("../docs/explanation/multi_issuer_routing.md")]
    pub mod multi_issuer_routing {}
}

/// Task-oriented recipes for wiring a validator into a resource server.
pub mod guide {
    #[doc = include_str!("../docs/guide/rfc9068.md")]
    pub mod rfc9068 {}

    #[doc = include_str!("../docs/guide/custom.md")]
    pub mod custom {}

    #[doc = include_str!("../docs/guide/introspection.md")]
    pub mod introspection {}

    #[doc = include_str!("../docs/guide/multi_issuer.md")]
    pub mod multi_issuer {}
}
