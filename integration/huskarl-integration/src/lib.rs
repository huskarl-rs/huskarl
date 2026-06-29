//! Provider-agnostic integration flow suite. Flow bodies live in [`suite`];
//! [`flows::FLOWS`] is the canonical list feeding [`runner`] and [`matrix`].

pub mod flows;
pub mod matrix;
pub mod runner;
pub mod suite;

pub use flows::{FLOWS, Flow, FlowBody, Variant};
pub use huskarl_testkit::Features;
pub use runner::{ProviderCtor, ProviderFuture, provider_trials};
