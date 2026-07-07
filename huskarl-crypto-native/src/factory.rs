use std::sync::Arc;

use huskarl_core::{
    crypto::verifier::{CreateVerifierError, JwsVerifier, JwsVerifierPlatform},
    jwk,
    platform::MaybeSendBoxFuture,
};

/// A verifier platform that takes public JWK material and returns a native-rust
/// [`JwsVerifier`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeVerifierPlatform;

impl JwsVerifierPlatform for NativeVerifierPlatform {
    fn create_verifier_from_jwk(
        &self,
        jwk: jwk::PublicJwk,
    ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, CreateVerifierError>> {
        let key = crate::asymmetric::verifier::AsymmetricPublicKey::from_jwk(jwk);

        Box::pin(async {
            key.map_or(Err(CreateVerifierError::UnsupportedKey), |k| {
                Ok(Arc::new(k) as Arc<dyn JwsVerifier>)
            })
        })
    }

    fn supported_signature_algorithms(&self) -> &[&str] {
        crate::asymmetric::verifier::SUPPORTED_SIGNATURE_ALGORITHMS
    }
}
