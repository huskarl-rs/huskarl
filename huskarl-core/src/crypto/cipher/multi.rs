use std::sync::Arc;

use futures_util::future::join_all;

use crate::{
    crypto::{
        KeyMatchStrength,
        cipher::{AeadDecryptor, AeadEncryptor, AeadEncryptorSelector, CipherMatch, DecryptError},
    },
    platform::{MaybeSendBoxFuture, MaybeSendSync},
};

/// An [`AeadDecryptor`] that holds multiple keys and applies [`CipherMatch`] /
/// [`KeyMatchStrength`] selection semantics.
///
/// This is the cipher analogue of
/// [`MultiKeyVerifier`](crate::crypto::verifier::MultiKeyVerifier).
///
/// # Key selection
///
/// [`cipher_match`](AeadDecryptor::cipher_match) follows [`KeyMatchStrength`] priority:
/// - A [`ByKeyId`](KeyMatchStrength::ByKeyId) match (algorithm + kid) is definitive.
/// - A single [`ByAlgorithm`](KeyMatchStrength::ByAlgorithm) match is used directly.
///
/// [`decrypt`](AeadDecryptor::decrypt) uses the optional [`CipherMatch`] to select
/// the correct key when available. When no `CipherMatch` is provided, keys are
/// tried in order.
///
/// Unlike [`MultiKeyVerifier`](crate::crypto::verifier::MultiKeyVerifier), which
/// fails closed on ambiguity, trying every candidate is safe here: an AEAD tag
/// self-authenticates, so a wrong key fails decryption rather than risking
/// wrong-key acceptance. Try-all is standard practice for rotated symmetric
/// keys (e.g. cookie-key rotation).
///
/// # Errors
///
/// When no candidate matches the criteria, decryption fails with
/// [`DecryptError::NoMatchingKey`] without attempting decryption — this is
/// what lets [`RetryingDecryptor`](crate::crypto::cipher::RetryingDecryptor)
/// trigger a key refresh. When candidates were attempted and all failed, the
/// last real failure is returned (non-retryable preferred over retryable),
/// matching the verifier's dispatch discipline.
#[derive(Debug)]
pub struct MultiKeyDecryptor {
    decryptors: Vec<Arc<dyn AeadDecryptor>>,
}

impl MultiKeyDecryptor {
    /// Creates a new `MultiKeyDecryptor` from the given decryptors.
    #[must_use]
    pub fn new(decryptors: Vec<Arc<dyn AeadDecryptor>>) -> Self {
        Self { decryptors }
    }
}

enum SelectedDecryptor<'a> {
    /// A single key matched definitively by key ID.
    ByKeyId(&'a Arc<dyn AeadDecryptor>),
    /// One or more keys matched by algorithm only.
    ByAlgorithm(Vec<&'a Arc<dyn AeadDecryptor>>),
    /// No keys matched.
    None,
}

impl MultiKeyDecryptor {
    fn select<'a>(&'a self, m: &CipherMatch<'_>) -> SelectedDecryptor<'a> {
        let mut by_algorithm: Vec<&'a Arc<dyn AeadDecryptor>> = Vec::new();

        for decryptor in &self.decryptors {
            match decryptor.cipher_match(m) {
                Some(KeyMatchStrength::ByKeyId) => {
                    return SelectedDecryptor::ByKeyId(decryptor);
                }
                Some(KeyMatchStrength::ByAlgorithm) => {
                    by_algorithm.push(decryptor);
                }
                None => {}
            }
        }

        if by_algorithm.is_empty() {
            SelectedDecryptor::None
        } else {
            SelectedDecryptor::ByAlgorithm(by_algorithm)
        }
    }

    async fn try_decrypt(
        decryptors: impl Iterator<Item = &Arc<dyn AeadDecryptor>>,
        cipher_match: Option<&CipherMatch<'_>>,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let mut last_retryable = None;
        let mut last_non_retryable = None;

        for decryptor in decryptors {
            match decryptor
                .decrypt(cipher_match, nonce, ciphertext, tag, aad)
                .await
            {
                Ok(plaintext) => return Ok(plaintext),
                // NoMatchingKey means the decryptor didn't attempt decryption —
                // it is the implicit fallback, not a result to prefer over others.
                Err(DecryptError::NoMatchingKey) => {}
                Err(e) => {
                    if e.is_retryable() {
                        last_retryable = Some(e);
                    } else {
                        last_non_retryable = Some(e);
                    }
                }
            }
        }

        Err(last_non_retryable
            .or(last_retryable)
            .unwrap_or(DecryptError::NoMatchingKey))
    }
}

impl AeadDecryptor for MultiKeyDecryptor {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        let mut by_algorithm = false;

        for decryptor in &self.decryptors {
            match decryptor.cipher_match(m) {
                Some(KeyMatchStrength::ByKeyId) => return Some(KeyMatchStrength::ByKeyId),
                Some(KeyMatchStrength::ByAlgorithm) => by_algorithm = true,
                None => {}
            }
        }

        by_algorithm.then_some(KeyMatchStrength::ByAlgorithm)
    }

    fn decrypt<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        Box::pin(async move {
            if let Some(m) = cipher_match {
                return match self.select(m) {
                    SelectedDecryptor::ByKeyId(decryptor) => {
                        decryptor
                            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
                            .await
                    }
                    SelectedDecryptor::ByAlgorithm(decryptors) => {
                        Self::try_decrypt(
                            decryptors.into_iter(),
                            cipher_match,
                            nonce,
                            ciphertext,
                            tag,
                            aad,
                        )
                        .await
                    }
                    SelectedDecryptor::None => Err(DecryptError::NoMatchingKey),
                };
            }

            // No cipher_match — try all keys in order.
            Self::try_decrypt(self.decryptors.iter(), None, nonce, ciphertext, tag, aad).await
        })
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        Box::pin(async move {
            join_all(self.decryptors.iter().map(AeadDecryptor::try_refresh))
                .await
                .into_iter()
                .any(|b| b)
        })
    }
}

/// An [`AeadEncryptorSelector`] + [`AeadDecryptor`] that encrypts with a
/// single primary key and decrypts with a [`MultiKeyDecryptor`].
///
/// This allows a single value to be passed where both encryption and decryption
/// capabilities are needed (e.g. encrypted cookies with key rotation).
#[derive(Debug)]
pub struct MultiKeyCipher<E> {
    encryptor: E,
    decryptor: MultiKeyDecryptor,
}

impl<E> MultiKeyCipher<E> {
    /// Creates a new `MultiKeyCipher`.
    pub fn new(encryptor: E, decryptor: MultiKeyDecryptor) -> Self {
        Self {
            encryptor,
            decryptor,
        }
    }
}

impl<E: AeadEncryptorSelector> AeadEncryptorSelector for MultiKeyCipher<E> {
    fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
        self.encryptor.select_encryptor()
    }
}

impl<E: std::fmt::Debug + MaybeSendSync> AeadDecryptor for MultiKeyCipher<E> {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.decryptor.cipher_match(m)
    }

    fn decrypt<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        self.decryptor
            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        self.decryptor.try_refresh()
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use rstest::rstest;

    use super::*;
    use crate::{
        Error,
        crypto::{
            KeyMatchStrength::*,
            cipher::{AeadOutput, AeadSealer, AeadSealerUnsealer, AeadUnsealer, AeadV1Cipher},
        },
        error::ErrorKind,
    };

    /// What a fake decryptor's `decrypt` returns.
    #[derive(Clone, Copy, Debug)]
    enum Outcome {
        Ok(&'static [u8]),
        NoMatchingKey,
        Retryable,
        NonRetryable,
    }

    #[derive(Debug)]
    struct FakeDecryptor {
        strength: Option<KeyMatchStrength>,
        outcome: Outcome,
        refresh: bool,
    }

    impl AeadDecryptor for FakeDecryptor {
        fn cipher_match(&self, _m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
            self.strength
        }

        fn decrypt<'a>(
            &'a self,
            _cipher_match: Option<&'a CipherMatch<'a>>,
            _nonce: &'a [u8],
            _ciphertext: &'a [u8],
            _tag: &'a [u8],
            _aad: &'a [u8],
        ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
            let outcome = self.outcome;
            Box::pin(async move {
                match outcome {
                    Outcome::Ok(b) => Ok(b.to_vec()),
                    Outcome::NoMatchingKey => Err(DecryptError::NoMatchingKey),
                    Outcome::Retryable => {
                        Err(Error::from(ErrorKind::Transport { retryable: true }).into())
                    }
                    Outcome::NonRetryable => Err(Error::from(ErrorKind::Crypto).into()),
                }
            })
        }

        fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
            let refresh = self.refresh;
            Box::pin(async move { refresh })
        }
    }

    fn dec(strength: Option<KeyMatchStrength>, outcome: Outcome) -> Arc<dyn AeadDecryptor> {
        Arc::new(FakeDecryptor {
            strength,
            outcome,
            refresh: false,
        })
    }

    fn cm() -> CipherMatch<'static> {
        CipherMatch {
            enc: Some("A256GCM"),
            kid: Some("k1"),
        }
    }

    async fn decrypt(
        d: &MultiKeyDecryptor,
        m: Option<&CipherMatch<'_>>,
    ) -> Result<Vec<u8>, DecryptError> {
        d.decrypt(m, b"nonce", b"ciphertext", b"tag", b"aad").await
    }

    // ── Selection with a CipherMatch ──────────────────────────────────────

    #[tokio::test]
    async fn by_key_id_match_is_used_exclusively() {
        // The kid match wins even though algorithm matches surround it.
        let d = MultiKeyDecryptor::new(vec![
            dec(Some(ByAlgorithm), Outcome::Ok(b"algo")),
            dec(Some(ByKeyId), Outcome::Ok(b"by-kid")),
            dec(Some(ByAlgorithm), Outcome::Ok(b"algo2")),
        ]);
        assert_eq!(decrypt(&d, Some(&cm())).await.unwrap(), b"by-kid");
    }

    #[tokio::test]
    async fn algorithm_matches_are_tried_in_order() {
        let d = MultiKeyDecryptor::new(vec![
            dec(Some(ByAlgorithm), Outcome::Ok(b"first")),
            dec(Some(ByAlgorithm), Outcome::Ok(b"second")),
        ]);
        assert_eq!(decrypt(&d, Some(&cm())).await.unwrap(), b"first");
    }

    #[tokio::test]
    async fn algorithm_match_skips_a_failing_key() {
        let d = MultiKeyDecryptor::new(vec![
            dec(Some(ByAlgorithm), Outcome::NonRetryable),
            dec(Some(ByAlgorithm), Outcome::Ok(b"second")),
        ]);
        assert_eq!(decrypt(&d, Some(&cm())).await.unwrap(), b"second");
    }

    #[tokio::test]
    async fn no_candidate_match_does_not_attempt_decryption() {
        // The only key would succeed if asked, but it doesn't match the criteria,
        // so decryption is never attempted and NoMatchingKey is returned.
        let d = MultiKeyDecryptor::new(vec![dec(None, Outcome::Ok(b"never"))]);
        let err = decrypt(&d, Some(&cm())).await.unwrap_err();
        assert!(matches!(err, DecryptError::NoMatchingKey));
    }

    // ── Selection without a CipherMatch (try-all) ─────────────────────────

    #[tokio::test]
    async fn without_cipher_match_tries_all_keys_in_order() {
        let d = MultiKeyDecryptor::new(vec![
            dec(None, Outcome::Ok(b"a")),
            dec(None, Outcome::Ok(b"b")),
        ]);
        assert_eq!(decrypt(&d, None).await.unwrap(), b"a");
    }

    #[tokio::test]
    async fn without_cipher_match_falls_through_no_matching_key() {
        let d = MultiKeyDecryptor::new(vec![
            dec(None, Outcome::NoMatchingKey),
            dec(None, Outcome::Ok(b"b")),
        ]);
        assert_eq!(decrypt(&d, None).await.unwrap(), b"b");
    }

    // ── Error preference when every attempted key fails ───────────────────

    #[tokio::test]
    async fn non_retryable_failure_is_preferred_over_retryable() {
        let d = MultiKeyDecryptor::new(vec![
            dec(Some(ByAlgorithm), Outcome::Retryable),
            dec(Some(ByAlgorithm), Outcome::NonRetryable),
        ]);
        let err = decrypt(&d, Some(&cm())).await.unwrap_err();
        assert!(!err.is_retryable(), "the non-retryable failure should win");
    }

    #[tokio::test]
    async fn retryable_failure_surfaces_when_it_is_the_only_real_error() {
        let d = MultiKeyDecryptor::new(vec![dec(Some(ByAlgorithm), Outcome::Retryable)]);
        let err = decrypt(&d, Some(&cm())).await.unwrap_err();
        assert!(err.is_retryable());
    }

    #[tokio::test]
    async fn no_matching_key_is_not_recorded_as_a_real_failure() {
        // A real failure (retryable) is preferred over a NoMatchingKey skip.
        let d = MultiKeyDecryptor::new(vec![
            dec(Some(ByAlgorithm), Outcome::NoMatchingKey),
            dec(Some(ByAlgorithm), Outcome::Retryable),
        ]);
        let err = decrypt(&d, Some(&cm())).await.unwrap_err();
        assert!(
            err.is_retryable(),
            "the retryable error, not NoMatchingKey, wins"
        );
    }

    // ── Aggregate cipher_match strength ───────────────────────────────────

    #[rstest]
    #[case::by_kid_wins(&[Some(ByAlgorithm), Some(ByKeyId)], Some(KeyMatchStrength::ByKeyId))]
    #[case::algorithm_when_no_kid(&[None, Some(ByAlgorithm)], Some(KeyMatchStrength::ByAlgorithm))]
    #[case::none_when_nothing_matches(&[None, None], None)]
    fn cipher_match_aggregates_strength(
        #[case] matches: &[Option<KeyMatchStrength>],
        #[case] expected: Option<KeyMatchStrength>,
    ) {
        let decryptors = matches
            .iter()
            .map(|m| dec(*m, Outcome::NoMatchingKey))
            .collect();
        assert_eq!(
            MultiKeyDecryptor::new(decryptors).cipher_match(&cm()),
            expected
        );
    }

    // ── try_refresh is the OR of inner refreshes ──────────────────────────

    #[rstest]
    #[case::one_refreshes(&[false, true], true)]
    #[case::none_refresh(&[false, false], false)]
    #[case::empty(&[], false)]
    #[tokio::test]
    async fn try_refresh_is_true_if_any_inner_refreshes(
        #[case] flags: &[bool],
        #[case] expected: bool,
    ) {
        let decryptors = flags
            .iter()
            .map(|&refresh| {
                Arc::new(FakeDecryptor {
                    strength: None,
                    outcome: Outcome::NoMatchingKey,
                    refresh,
                }) as Arc<dyn AeadDecryptor>
            })
            .collect();
        let d = MultiKeyDecryptor::new(decryptors);
        assert_eq!(d.try_refresh().await, expected);
    }

    // ── MultiKeyCipher delegation ─────────────────────────────────────────

    #[derive(Debug)]
    struct FakeEncryptor;

    /// Raw-key shape: a selector handing out its shared inner encryptor.
    #[derive(Debug)]
    struct FakeKey {
        inner: Arc<FakeEncryptor>,
    }

    impl FakeKey {
        fn new() -> Self {
            Self {
                inner: Arc::new(FakeEncryptor),
            }
        }
    }

    impl AeadEncryptorSelector for FakeKey {
        fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
            let snapshot: Arc<dyn AeadEncryptor> = self.inner.clone();
            Box::pin(async move { snapshot })
        }
    }

    impl AeadEncryptor for FakeEncryptor {
        fn enc_algorithm(&self) -> Cow<'_, str> {
            "A256GCM".into()
        }
        fn key_id(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed("enc-kid"))
        }
        fn encrypt<'a>(
            &'a self,
            plaintext: &'a [u8],
            _aad: &'a [u8],
        ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
            let ciphertext = plaintext.to_vec();
            Box::pin(async move {
                Ok(AeadOutput {
                    nonce: Vec::new(),
                    ciphertext,
                    tag: Vec::new(),
                })
            })
        }
    }

    #[tokio::test]
    async fn multi_key_cipher_delegates_each_direction() {
        let cipher = MultiKeyCipher::new(
            FakeKey::new(),
            MultiKeyDecryptor::new(vec![dec(None, Outcome::Ok(b"plaintext"))]),
        );

        // Encryptor side → delegates to the selected encryptor.
        let selected = cipher.select_encryptor().await;

        assert_eq!(selected.enc_algorithm().as_ref(), "A256GCM");
        assert_eq!(selected.key_id().as_deref(), Some("enc-kid"));
        let out = selected.encrypt(b"plaintext", b"aad").await.unwrap();
        assert_eq!(out.ciphertext, b"plaintext");

        // Decryptor side → delegates to the MultiKeyDecryptor.
        let recovered = cipher
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, b"aad")
            .await
            .unwrap();
        assert_eq!(recovered, b"plaintext");
    }

    // ── Rotated cookie keys (seal/unseal roundtrip) ───────────────────────

    /// A keyed AEAD cipher for the rotated-cookie-keys scenario: it stamps its
    /// `kid` into the authentication tag on the way out, and only opens a bundle
    /// whose tag is its own `kid`. So which key sealed a cookie is observable, and
    /// a cookie can only be unsealed by the key that sealed it.
    #[derive(Debug)]
    struct KeyedCookieEncryptor {
        kid: &'static str,
    }

    impl AeadEncryptor for KeyedCookieEncryptor {
        fn enc_algorithm(&self) -> Cow<'_, str> {
            "A256GCM".into()
        }
        fn key_id(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.kid))
        }
        fn encrypt<'a>(
            &'a self,
            plaintext: &'a [u8],
            _aad: &'a [u8],
        ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
            let ciphertext = plaintext.to_vec();
            let tag = self.kid.as_bytes().to_vec();
            Box::pin(async move {
                Ok(AeadOutput {
                    nonce: Vec::new(),
                    ciphertext,
                    tag,
                })
            })
        }
    }

    #[derive(Debug)]
    struct KeyedCookieCipher {
        inner: Arc<KeyedCookieEncryptor>,
    }

    impl KeyedCookieCipher {
        fn new(kid: &'static str) -> Self {
            Self {
                inner: Arc::new(KeyedCookieEncryptor { kid }),
            }
        }
    }

    impl AeadEncryptorSelector for KeyedCookieCipher {
        fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
            let snapshot: Arc<dyn AeadEncryptor> = self.inner.clone();
            Box::pin(async move { snapshot })
        }
    }

    impl AeadDecryptor for KeyedCookieCipher {
        fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
            m.strength_for("A256GCM", Some(self.inner.kid))
        }
        fn decrypt<'a>(
            &'a self,
            _cipher_match: Option<&'a CipherMatch<'a>>,
            _nonce: &'a [u8],
            ciphertext: &'a [u8],
            tag: &'a [u8],
            _aad: &'a [u8],
        ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
            let opens = tag == self.inner.kid.as_bytes();
            let plaintext = ciphertext.to_vec();
            Box::pin(async move {
                if opens {
                    Ok(plaintext)
                } else {
                    Err(Error::from(ErrorKind::Crypto).into())
                }
            })
        }
    }

    /// The rotated-cookie-keys shape: one `AeadV1Cipher<MultiKeyCipher>` seals
    /// every new cookie with the current primary key while still unsealing cookies
    /// sealed by any key left in the decryptor set — and a key dropped from the set
    /// can no longer open its old cookies. Erased to `Arc<dyn AeadSealerUnsealer>`,
    /// it is a single handle carrying both directions.
    #[tokio::test]
    async fn rotated_cookie_keys_seal_new_and_unseal_old() {
        // A cookie minted with v1 before the rotation, and one minted with a
        // since-retired key v0 that is no longer carried.
        let old_v1 = AeadV1Cipher::new(KeyedCookieCipher::new("v1"))
            .seal(b"session", b"aad")
            .await
            .unwrap();
        let retired_v0 = AeadV1Cipher::new(KeyedCookieCipher::new("v0"))
            .seal(b"session", b"aad")
            .await
            .unwrap();

        // After rotation: seal with v2, still decrypt v2 and v1 (v0 dropped).
        let cookies: Arc<dyn AeadSealerUnsealer> =
            Arc::new(AeadV1Cipher::new(MultiKeyCipher::new(
                KeyedCookieCipher::new("v2"),
                MultiKeyDecryptor::new(vec![
                    Arc::new(KeyedCookieCipher::new("v2")) as Arc<dyn AeadDecryptor>,
                    Arc::new(KeyedCookieCipher::new("v1")) as Arc<dyn AeadDecryptor>,
                ]),
            )));

        // New cookies are sealed with the current primary (v2)...
        let new_cookie = cookies.seal(b"session", b"aad").await.unwrap();
        assert_eq!(
            &new_cookie[new_cookie.len() - 2..],
            b"v2",
            "new cookies are sealed with the primary key"
        );

        // ...and every key still in the set opens the cookies it sealed, with no
        // out-of-band kid — the bundle carries none, so the decryptor tries keys
        // in turn until one authenticates.
        assert_eq!(
            cookies.unseal(None, &new_cookie, b"aad").await.unwrap(),
            b"session"
        );
        assert_eq!(
            cookies.unseal(None, &old_v1, b"aad").await.unwrap(),
            b"session"
        );

        // The retired key's cookie no longer opens once its key leaves the set.
        cookies
            .unseal(None, &retired_v0, b"aad")
            .await
            .expect_err("a key dropped from the set can no longer unseal");
    }
}
