//! Cryptographic verification key traits.

mod error;
#[cfg(feature = "metrics")]
mod metrics_verifier;
mod multi;
mod refreshing;
mod retrying;
mod r#trait;

pub use error::{CreateVerifierError, NoMatchingKeySnafu, SignatureMismatchSnafu, VerifyError};
#[cfg(feature = "metrics")]
pub use metrics_verifier::MetricsJwsVerifier;
pub use multi::{MultiKeyVerifier, MultiKeyVerifierError};
pub use refreshing::RefreshingVerifier;
pub use retrying::RetryingVerifier;
pub use crate::crypto::KeyMatchStrength;
pub use r#trait::{BoxedJwsVerifier, JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform, KeyMatch};
