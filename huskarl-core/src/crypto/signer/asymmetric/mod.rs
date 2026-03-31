use std::borrow::Cow;

use crate::{crypto::signer::JwsSigner, jwk::PublicJwk, platform::MaybeSendSync};

pub mod boxed;

/// A selector for an asymmetric JWS signer.
///
/// This returns a signer which has a fixed identity and metadata. The resulting
/// signer can be used to create signatures without worrying that the metadata
/// will be invalidated between use and signing.
///
/// The thumbprint option allows selecting a signer by its thumbprint, which
/// may be used to find the appropriate signing key for a `DPoP` proof.
pub trait AsymmetricJwsSignerSelector: std::fmt::Debug + Clone + MaybeSendSync {
    /// The type of the asymmetric JWS signer to be returned.
    type AsymmetricSigner: AsymmetricJwsSigner;

    /// Selects the current asymmetric JWS signer to use for signing.
    fn select_asymmetric_signer(&self) -> Self::AsymmetricSigner;

    /// Selects the asymmetric JWS signer to use for signing by its thumbprint.
    fn select_asymmetric_signer_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<Self::AsymmetricSigner>;
}

/// Trait for asymmetric signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait AsymmetricJwsSigner: JwsSigner {
    /// Returns the public key JWK for this signer.
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk>;
}
