//! Signing key traits.

pub mod boxed;

use std::borrow::Cow;

use crate::Error;
use crate::platform::{MaybeSend, MaybeSendSync};

/// A selector for a JWS signer.
///
/// This returns a signer which has a fixed identity and metadata. The resulting
/// signer can be used to create signatures without worrying that the metadata
/// will be invalidated between use and signing.
///
/// The signer returned by [`Self::select_signer`] should be held for a short period
/// of time, as longer periods would work against system policies like key rotation.
pub trait JwsSignerSelector: std::fmt::Debug + Clone + MaybeSendSync {
    /// The type of the JWS signer to be returned.
    type Signer: JwsSigner;

    /// Selects the current JWS signer to use for signing.
    fn select_signer(&self) -> Self::Signer;
}

/// Trait for using signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait JwsSigner: std::fmt::Debug + Clone + MaybeSendSync {
    /// The error type returned by this signer's operations.
    type Error: Error + 'static;

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
    /// Returns [`Self::Error`] if the signing operation fails.
    fn sign(&self, input: &[u8]) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;
}
