#![cfg(feature = "tracing")]

#[path = "support/test_tracing.rs"]
mod test_tracing;

use huskarl_core::{
    crypto::{
        cipher::{AeadDecryptor as _, AeadEncryptorSelector as _},
        signer::AsymmetricJwsSignerSelector as _,
        verifier::{JwsVerifier as _, KeyMatch},
    },
    jwk,
};
use huskarl_crypto_native::{
    aead::AesGcmKey,
    asymmetric::{
        signer::{GenerateAlgorithm, PrivateKey},
        verifier::AsymmetricPublicKey,
    },
};

#[tokio::test]
async fn failures_are_nested_and_secrets_are_excluded() {
    for level in [
        tracing::Level::TRACE,
        tracing::Level::DEBUG,
        tracing::Level::INFO,
    ] {
        let (_, output) = test_tracing::capture(
            async {
                let key = PrivateKey::generate(
                    GenerateAlgorithm::Es256,
                    Some("private-signing-kid".into()),
                )
                .unwrap();
                let signer = key.select_asymmetric_signer().await;
                let verifier =
                    AsymmetricPublicKey::from_jwk(signer.public_key_jwk().into_owned()).unwrap();
                let signature = signer.sign(b"private-signed-input").await.unwrap();
                let key_match = KeyMatch::builder().alg("ES256").build();
                assert!(
                    verifier
                        .verify(b"private-tampered-input", &signature, &key_match)
                        .await
                        .is_err()
                );
                assert!(
                    verifier
                        .verify(
                            b"private-signed-input",
                            b"private-malformed-signature",
                            &key_match
                        )
                        .await
                        .is_err()
                );
                let jwk = jwk::SymmetricJwk::builder()
                    .key(
                        jwk::OctKey::builder()
                            .k(b"private-key-material-01234567890".to_vec())
                            .build(),
                    )
                    .kid("private-key-id")
                    .build();
                let mut invalid = jwk.clone();
                invalid.algorithm = Some("private-invalid-algorithm".into());
                assert!(AesGcmKey::from_jwk(invalid).is_err());
                let key = AesGcmKey::from_jwk(jwk).unwrap();
                let encryptor = key.select_encryptor().await;
                let sealed = encryptor
                    .encrypt(b"private-plaintext", b"private-aad")
                    .await
                    .unwrap();
                assert!(
                    key.decrypt(
                        None,
                        &sealed.nonce,
                        &sealed.ciphertext,
                        &sealed.tag,
                        b"private-wrong-aad"
                    )
                    .await
                    .is_err()
                );
            },
            level,
        )
        .await;
        if level == tracing::Level::INFO {
            assert!(output.is_empty(), "{output}");
        } else {
            let failure = output
                .lines()
                .find(|line| line.contains("reason=\"decryption_failed\""))
                .unwrap_or_else(|| panic!("{output}"));
            assert!(
                failure.contains("Cryptographic operation failed"),
                "{output}"
            );
            assert!(failure.contains("outcome=\"error\""), "{output}");
            if level == tracing::Level::TRACE {
                assert!(failure.contains("huskarl.native.aead.decrypt:"), "{output}");
                let malformed = output
                    .lines()
                    .find(|line| line.contains("reason=\"malformed_signature\""))
                    .unwrap();
                assert!(malformed.contains("huskarl.native.jws.verify:"), "{output}");
                let verification = output
                    .lines()
                    .find(|line| line.contains("reason=\"signature_mismatch\""))
                    .unwrap();
                assert!(
                    verification.contains("huskarl.native.jws.verify:"),
                    "{output}"
                );
                assert!(output.contains("key_type=\"EC\""), "{output}");
                assert!(output.contains("algorithm=\"A256GCM\""), "{output}");
            }
        }
        assert!(!output.contains("private-"), "{output}");
        assert!(
            !output.contains("112, 114, 105, 118, 97, 116, 101"),
            "{output}"
        );
    }
}
