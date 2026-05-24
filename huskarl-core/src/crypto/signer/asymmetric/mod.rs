use std::borrow::Cow;

use crate::{
    crypto::signer::{JwsSigner, JwsSignerSelector},
    jwk::PublicJwk,
};

pub mod boxed;

/// A selector for an asymmetric JWS signer.
///
/// This is a refinement of [`JwsSignerSelector`] for asymmetric keys — it
/// additionally requires that the selected signer exposes its public key
/// (via [`AsymmetricJwsSigner`]) and supports selection by JWK thumbprint
/// (used for `DPoP` key confirmation).
///
/// Because `AsymmetricJwsSignerSelector` is a subtrait of `JwsSignerSelector`,
/// any asymmetric selector can be used wherever a plain `JwsSignerSelector` is
/// required (for example as the `Sgn` of [`JwtBearer`](crate::client_auth::JwtBearer)).
pub trait AsymmetricJwsSignerSelector: JwsSignerSelector<Signer: AsymmetricJwsSigner> {
    /// Selects the asymmetric JWS signer to use for signing by its thumbprint.
    fn select_signer_by_thumbprint(&self, thumbprint: &str) -> Option<Self::Signer>;
}

/// Trait for asymmetric signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait AsymmetricJwsSigner: JwsSigner {
    /// Returns the public key JWK for this signer.
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk>;
}
