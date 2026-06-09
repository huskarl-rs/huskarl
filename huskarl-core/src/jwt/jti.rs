use std::{pin::Pin, sync::Arc};

use crate::{
    BoxedError,
    platform::{MaybeSendFuture, MaybeSendSync},
};

/// A boxed JTI uniqueness checker.
///
/// This can check that JTI values have not previously been seen.
#[derive(Debug, Clone)]
pub struct BoxedJtiUniquenessChecker {
    inner: Arc<dyn JtiUniquenessChecker>,
}

impl BoxedJtiUniquenessChecker {
    /// Create a boxed JTI uniqueness checker from a non-boxed.
    pub fn new<T: JtiUniquenessChecker + 'static>(checker: T) -> Self {
        Self {
            inner: Arc::new(checker),
        }
    }
}

impl JtiUniquenessChecker for BoxedJtiUniquenessChecker {
    fn check_and_mark_seen(
        &self,
        jti: &str,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<bool, BoxedError>> + '_>> {
        self.inner.check_and_mark_seen(jti)
    }
}

/// A uniqueness checker for the `jti` claim of JWTs.
///
/// Implementations of this trait should check if the value was previously seen,
/// and register this value in the seen set.
///
/// Details like cache lifetime are left to concrete implementations.
pub trait JtiUniquenessChecker: std::fmt::Debug + MaybeSendSync {
    /// Checks if the supplied JTI value was seen before, and adds the JTI value to the set of seen values.
    ///
    /// Returns `true` if the JTI value was previously seen.
    fn check_and_mark_seen(
        &self,
        jti: &str,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<bool, BoxedError>> + '_>>;
}
