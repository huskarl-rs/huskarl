//! Fixed error categories only; never format backend errors or key material.
#[inline]
pub(crate) fn failure(reason: &'static str) {
    #[cfg(feature = "tracing")]
    tracing::debug!(outcome = "error", reason, "Cryptographic operation failed");
    #[cfg(not(feature = "tracing"))]
    let _ = reason;
}
