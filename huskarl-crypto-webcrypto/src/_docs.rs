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
