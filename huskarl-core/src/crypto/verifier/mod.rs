//! Cryptographic verification key traits.

mod error;
#[cfg(feature = "metrics")]
mod metrics_verifier;
mod multi;
mod refreshing;
mod retrying;
mod swappable;
mod r#trait;

pub use error::{CreateVerifierError, VerifyError};
#[cfg(feature = "metrics")]
pub use metrics_verifier::MetricsJwsVerifier;
pub use multi::MultiKeyVerifier;
pub use refreshing::ScheduledRefreshVerifier;
pub use retrying::RetryingVerifier;
pub use swappable::RefreshableVerifier;

/// Deprecated: renamed to [`ScheduledRefreshVerifier`].
#[deprecated(note = "renamed to ScheduledRefreshVerifier")]
pub type RefreshingVerifier<V> = ScheduledRefreshVerifier<V>;

pub use r#trait::{JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform, KeyMatch};
