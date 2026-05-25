use crate::crypto::signer::{
    AsymmetricJwsSigner, AsymmetricJwsSignerSelector, BoxedAsymmetricJwsSigner, JwsSignerSelector,
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
pub struct MultiKeySigner<S: AsymmetricJwsSigner = BoxedAsymmetricJwsSigner> {
    default: S,
    additional: Vec<S>,
}

impl<S: AsymmetricJwsSigner> MultiKeySigner<S> {
    /// Creates a new `MultiKeySigner` with a default signer and additional signers.
    #[must_use]
    pub fn new(default: S, additional: Vec<S>) -> Self {
        Self {
            default,
            additional,
        }
    }
}

impl<S: AsymmetricJwsSigner> JwsSignerSelector for MultiKeySigner<S> {
    type Signer = S;

    fn select_signer(&self) -> S {
        self.default.clone()
    }
}

impl<S: AsymmetricJwsSigner> AsymmetricJwsSignerSelector for MultiKeySigner<S> {
    fn select_signer_by_thumbprint(&self, thumbprint: &str) -> Option<S> {
        let all = std::iter::once(&self.default).chain(self.additional.iter());
        for signer in all {
            if signer.public_key_jwk().thumbprint().as_deref() == Some(thumbprint) {
                return Some(signer.clone());
            }
        }
        None
    }
}
