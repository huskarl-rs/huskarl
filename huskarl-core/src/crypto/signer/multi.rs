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

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::{
        error::Error,
        jwk::{EcPublicKey, PublicJwk},
        platform::MaybeSendBoxFuture,
    };

    #[derive(Debug)]
    struct FakeSigner {
        jwk: PublicJwk,
    }

    impl JwsSigner for FakeSigner {
        fn jws_algorithm(&self) -> Cow<'_, str> {
            "ES256".into()
        }
        fn key_id(&self) -> Option<Cow<'_, str>> {
            None
        }
        fn sign<'a>(&'a self, _input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
            Box::pin(async { Ok(vec![0x01]) })
        }
    }

    impl AsymmetricJwsSigner for FakeSigner {
        fn public_key_jwk(&self) -> Cow<'_, PublicJwk> {
            Cow::Borrowed(&self.jwk)
        }
    }

    /// A signer with distinct key material per `tag` (so distinct RFC 7638
    /// thumbprints).
    fn fake(tag: u8) -> FakeSigner {
        let jwk = PublicJwk::builder()
            .key(
                EcPublicKey::builder()
                    .crv("P-256")
                    .x(vec![tag; 32])
                    .y(vec![tag.wrapping_add(1); 32]),
            )
            .build();
        FakeSigner { jwk }
    }

    fn thumbprint(tag: u8) -> String {
        fake(tag).public_key_jwk().thumbprint()
    }

    #[test]
    fn select_returns_the_default_signer() {
        let multi = MultiKeySigner::new(
            fake(1),
            vec![Arc::new(fake(2)) as Arc<dyn AsymmetricJwsSigner>],
        );
        assert_eq!(
            multi
                .select_asymmetric_signer()
                .public_key_jwk()
                .thumbprint(),
            thumbprint(1)
        );
    }

    #[test]
    fn select_by_thumbprint_searches_default_then_additional() {
        let multi = MultiKeySigner::new(
            fake(1),
            vec![
                Arc::new(fake(2)) as Arc<dyn AsymmetricJwsSigner>,
                Arc::new(fake(3)) as Arc<dyn AsymmetricJwsSigner>,
            ],
        );

        // The default and every additional key are all reachable by thumbprint.
        for tag in [1u8, 2, 3] {
            let found = multi.select_signer_by_thumbprint(&thumbprint(tag));
            assert!(found.is_some(), "key {tag} not found");
            assert_eq!(
                found.unwrap().public_key_jwk().thumbprint(),
                thumbprint(tag)
            );
        }
    }

    #[test]
    fn select_by_thumbprint_returns_none_for_unknown_key() {
        let multi = MultiKeySigner::new(
            fake(1),
            vec![Arc::new(fake(2)) as Arc<dyn AsymmetricJwsSigner>],
        );
        assert!(
            multi
                .select_signer_by_thumbprint("not-a-real-thumbprint")
                .is_none()
        );
    }
}
