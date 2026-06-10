//! Signing key traits.

use std::{borrow::Cow, sync::Arc};

use crate::{
    error::Error,
    platform::{MaybeSendBoxFuture, MaybeSendSync},
};

/// A selector for a JWS signer.
///
/// This returns a signer which has a fixed identity and metadata. The resulting
/// signer can be used to create signatures without worrying that the metadata
/// will be invalidated between use and signing.
///
/// The signer returned by [`Self::select_signer`] should be held for a short period
/// of time, as longer periods would work against system policies like key rotation.
///
/// This trait is dyn-capable: consumers store it as
/// `Arc<dyn JwsSignerSelector>`.
pub trait JwsSignerSelector: std::fmt::Debug + MaybeSendSync {
    /// Selects the current JWS signer to use for signing.
    fn select_signer(&self) -> Arc<dyn JwsSigner>;
}

/// Trait for using signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
///
/// This trait is dyn-capable: selectors hand out signers as
/// `Arc<dyn JwsSigner>`.
///
/// # Implementing
///
/// Write the `sign` body as `Box::pin(async move { ... })`. Signing failures
/// classify as [`ErrorKind::Crypto`](crate::error::ErrorKind::Crypto);
/// transient failures of a remote keystore (KMS, HSM) as
/// [`ErrorKind::Transport`](crate::error::ErrorKind::Transport) with
/// `retryable: true`.
pub trait JwsSigner: std::fmt::Debug + MaybeSendSync {
    /// Returns the JWS algorithm for this signer.
    ///
    /// This is the algorithm identifier to use in the JWT `alg` header parameter.
    fn jws_algorithm(&self) -> Cow<'_, str>;

    /// Returns the key ID for this signer.
    ///
    /// This is specifically for use in the JWT `kid` header parameter.
    ///
    /// Note: The "natural" key ID is not always directly suitable as a
    /// `kid` value, and may require transformation before use.
    fn key_id(&self) -> Option<Cow<'_, str>>;

    /// Asynchronously signs the given input data.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign<'a>(&'a self, input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>>;
}

impl<T: JwsSignerSelector + ?Sized> JwsSignerSelector for &T {
    fn select_signer(&self) -> Arc<dyn JwsSigner> {
        (**self).select_signer()
    }
}

impl<T: JwsSignerSelector + ?Sized> JwsSignerSelector for Box<T> {
    fn select_signer(&self) -> Arc<dyn JwsSigner> {
        (**self).select_signer()
    }
}

impl<T: JwsSignerSelector + ?Sized> JwsSignerSelector for Arc<T> {
    fn select_signer(&self) -> Arc<dyn JwsSigner> {
        (**self).select_signer()
    }
}

impl<T: JwsSigner + ?Sized> JwsSigner for &T {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        (**self).jws_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        (**self).key_id()
    }

    fn sign<'a>(&'a self, input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
        (**self).sign(input)
    }
}

impl<T: JwsSigner + ?Sized> JwsSigner for Box<T> {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        (**self).jws_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        (**self).key_id()
    }

    fn sign<'a>(&'a self, input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
        (**self).sign(input)
    }
}

impl<T: JwsSigner + ?Sized> JwsSigner for Arc<T> {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        (**self).jws_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        (**self).key_id()
    }

    fn sign<'a>(&'a self, input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
        (**self).sign(input)
    }
}
