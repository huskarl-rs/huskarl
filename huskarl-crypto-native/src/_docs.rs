//! Extended documentation: how-to guides and explanation.
//!
//! The API items in this crate are the **reference** documentation — they say
//! what each type is and how to call it. These pages cover the other
//! [Diátaxis](https://diataxis.fr) quadrants:
//!
//! - **[How-to guides](guide)** — task-oriented recipes.
//! - **[Explanation](explanation)** — understanding-oriented background on how
//!   the crate works and why it is shaped the way it is.
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
