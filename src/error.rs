//! Error types and the [`Error`] trait.
//!
//! All errors in this library implement the [`Error`] trait, which extends
//! [`std::error::Error`] with retry semantics. [`BoxedError`] provides
//! type-erased error handling while preserving retryability.

use std::convert::Infallible;

use snafu::{AsErrorSource, Snafu};

use crate::platform::MaybeSendSync;

/// Errors that may occur in the library.
pub trait Error: std::error::Error + AsErrorSource + MaybeSendSync + 'static {
    /// If true, this indicates that a failed request may succeed if retried.
    fn is_retryable(&self) -> bool;
}

impl Error for Infallible {
    fn is_retryable(&self) -> bool {
        false
    }
}

/// A boxed error that can be used without type parameters.
#[derive(Debug, Snafu)]
#[snafu(transparent)]
pub struct BoxedError {
    source: Box<dyn Error>,
}

impl BoxedError {
    /// Create a new boxed error from a generic `Error`.
    pub fn from_err<E: Error + 'static>(err: E) -> Self {
        Self {
            source: Box::new(err),
        }
    }
}

impl Error for BoxedError {
    fn is_retryable(&self) -> bool {
        self.source.is_retryable()
    }
}
