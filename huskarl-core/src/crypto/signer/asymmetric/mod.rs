use std::{borrow::Cow, sync::Arc};

use crate::{
    crypto::signer::{JwsSigner, JwsSignerSelector},
    jwk::PublicJwk,
};

/// A selector for an asymmetric JWS signer.
///
/// This is a refinement of [`JwsSignerSelector`] for asymmetric keys — it
/// additionally requires that the selected signer exposes its public key
/// (via [`AsymmetricJwsSigner`]) and supports selection by JWK thumbprint
/// (used for `DPoP` key confirmation).
///
/// Because `AsymmetricJwsSignerSelector` is a subtrait of `JwsSignerSelector`,
/// any asymmetric selector can be used wherever a plain `JwsSignerSelector` is
/// required (for example as the signer of
/// [`JwtBearer`](crate::client_auth::JwtBearer)). Implement the supertrait's
/// [`select_signer`](JwsSignerSelector::select_signer) by delegating:
/// `self.select_asymmetric_signer()` (the `Arc` upcasts).
pub trait AsymmetricJwsSignerSelector: JwsSignerSelector {
    /// Selects the current asymmetric JWS signer to use for signing.
    fn select_asymmetric_signer(&self) -> Arc<dyn AsymmetricJwsSigner>;

    /// Selects the asymmetric JWS signer to use for signing by its thumbprint.
    fn select_signer_by_thumbprint(&self, thumbprint: &str)
    -> Option<Arc<dyn AsymmetricJwsSigner>>;
}

/// Trait for asymmetric signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait AsymmetricJwsSigner: JwsSigner {
    /// Returns the public key JWK for this signer.
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk>;
}

impl<T: AsymmetricJwsSignerSelector + ?Sized> AsymmetricJwsSignerSelector for &T {
    fn select_asymmetric_signer(&self) -> Arc<dyn AsymmetricJwsSigner> {
        (**self).select_asymmetric_signer()
    }

    fn select_signer_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<Arc<dyn AsymmetricJwsSigner>> {
        (**self).select_signer_by_thumbprint(thumbprint)
    }
}

impl<T: AsymmetricJwsSignerSelector + ?Sized> AsymmetricJwsSignerSelector for Box<T> {
    fn select_asymmetric_signer(&self) -> Arc<dyn AsymmetricJwsSigner> {
        (**self).select_asymmetric_signer()
    }

    fn select_signer_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<Arc<dyn AsymmetricJwsSigner>> {
        (**self).select_signer_by_thumbprint(thumbprint)
    }
}

impl<T: AsymmetricJwsSignerSelector + ?Sized> AsymmetricJwsSignerSelector for Arc<T> {
    fn select_asymmetric_signer(&self) -> Arc<dyn AsymmetricJwsSigner> {
        (**self).select_asymmetric_signer()
    }

    fn select_signer_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<Arc<dyn AsymmetricJwsSigner>> {
        (**self).select_signer_by_thumbprint(thumbprint)
    }
}

impl<T: AsymmetricJwsSigner + ?Sized> AsymmetricJwsSigner for &T {
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk> {
        (**self).public_key_jwk()
    }
}

impl<T: AsymmetricJwsSigner + ?Sized> AsymmetricJwsSigner for Box<T> {
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk> {
        (**self).public_key_jwk()
    }
}

impl<T: AsymmetricJwsSigner + ?Sized> AsymmetricJwsSigner for Arc<T> {
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk> {
        (**self).public_key_jwk()
    }
}
