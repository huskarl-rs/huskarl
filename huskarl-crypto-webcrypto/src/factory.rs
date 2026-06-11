use std::sync::Arc;

use huskarl_core::{
    crypto::verifier::{CreateVerifierError, JwsVerifier, JwsVerifierPlatform},
    jwk,
    platform::MaybeSendBoxFuture,
};

/// A verifier platform that takes public JWK material and returns a
/// `WebCrypto`-backed [`JwsVerifier`].
#[derive(Debug, Clone, Copy, Default)]
pub struct WebCryptoVerifierPlatform;

impl JwsVerifierPlatform for WebCryptoVerifierPlatform {
    fn create_verifier_from_jwk(
        &self,
        jwk: jwk::PublicJwk,
    ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, CreateVerifierError>> {
        Box::pin(async {
            let key = crate::asymmetric::verifier::AsymmetricPublicKey::from_jwk(jwk);
            key.await
                .map_or(Err(CreateVerifierError::UnsupportedKey), |k| {
                    Ok(Arc::new(k) as Arc<dyn JwsVerifier>)
                })
        })
    }
}
