use std::sync::Arc;

use crate::{
    error::Error,
    platform::{MaybeSendBoxFuture, MaybeSendSync},
};

/// A uniqueness checker for the `jti` claim of JWTs.
///
/// Implementations of this trait should check if the value was previously seen,
/// and register this value in the seen set.
///
/// Details like cache lifetime are left to concrete implementations.
///
/// This trait is dyn-capable: consumers store it as
/// `Arc<dyn JtiUniquenessChecker>`.
///
/// # Implementing
///
/// Write the method body as `Box::pin(async move { ... })`. The future may
/// only borrow `self`, so copy the `jti` value into it if needed. Transient
/// failures of a backing store carry
/// [`RetryAdvice::Retry`](crate::error::RetryAdvice::Retry).
pub trait JtiUniquenessChecker: std::fmt::Debug + MaybeSendSync {
    /// Checks if the supplied JTI value was seen before, and adds the JTI value to the set of seen values.
    ///
    /// Returns `true` if the JTI value was previously seen.
    fn check_and_mark_seen(&self, jti: &str) -> MaybeSendBoxFuture<'_, Result<bool, Error>>;
}

impl<T: JtiUniquenessChecker + ?Sized> JtiUniquenessChecker for &T {
    fn check_and_mark_seen(&self, jti: &str) -> MaybeSendBoxFuture<'_, Result<bool, Error>> {
        (**self).check_and_mark_seen(jti)
    }
}

impl<T: JtiUniquenessChecker + ?Sized> JtiUniquenessChecker for Box<T> {
    fn check_and_mark_seen(&self, jti: &str) -> MaybeSendBoxFuture<'_, Result<bool, Error>> {
        (**self).check_and_mark_seen(jti)
    }
}

impl<T: JtiUniquenessChecker + ?Sized> JtiUniquenessChecker for Arc<T> {
    fn check_and_mark_seen(&self, jti: &str) -> MaybeSendBoxFuture<'_, Result<bool, Error>> {
        (**self).check_and_mark_seen(jti)
    }
}
