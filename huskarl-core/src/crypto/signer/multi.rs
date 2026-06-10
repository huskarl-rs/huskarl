use std::sync::Arc;

use crate::crypto::signer::{
    AsymmetricJwsSigner, AsymmetricJwsSignerSelector, JwsSigner, JwsSignerSelector,
};

/// A multi-key asymmetric signer selector that supports key selection by JWK thumbprint.
///
/// This is useful for `DPoP` scenarios where a client is bound to multiple keys and
/// the server specifies which one to use via `dpop_jkt`.
///
/// - [`select_signer`](JwsSignerSelector::select_signer) always returns the `default` signer.
/// - [`select_signer_by_thumbprint`](AsymmetricJwsSignerSelector::select_signer_by_thumbprint)
///   searches the default signer first, then the additional signers.
#[derive(Debug, Clone)]
pub struct MultiKeySigner {
    default: Arc<dyn AsymmetricJwsSigner>,
    additional: Vec<Arc<dyn AsymmetricJwsSigner>>,
}

impl MultiKeySigner {
    /// Creates a new `MultiKeySigner` with a default signer and additional signers.
    #[must_use]
    pub fn new(
        default: impl AsymmetricJwsSigner + 'static,
        additional: Vec<Arc<dyn AsymmetricJwsSigner>>,
    ) -> Self {
        Self {
            default: Arc::new(default),
            additional,
        }
    }
}

impl JwsSignerSelector for MultiKeySigner {
    fn select_signer(&self) -> Arc<dyn JwsSigner> {
        self.default.clone()
    }
}

impl AsymmetricJwsSignerSelector for MultiKeySigner {
    fn select_asymmetric_signer(&self) -> Arc<dyn AsymmetricJwsSigner> {
        self.default.clone()
    }

    fn select_signer_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<Arc<dyn AsymmetricJwsSigner>> {
        let all = std::iter::once(&self.default).chain(self.additional.iter());
        for signer in all {
            if signer.public_key_jwk().thumbprint() == thumbprint {
                return Some(signer.clone());
            }
        }
        None
    }
}
