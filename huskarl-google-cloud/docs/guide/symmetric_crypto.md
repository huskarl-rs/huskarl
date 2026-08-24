# Encrypting and signing with symmetric KMS keys

This crate supports two symmetric Cloud KMS key purposes:
`RAW_ENCRYPT_DECRYPT` for AEAD encryption and `MAC` for HMAC signing. Each pairs
a *write* side that pins one version with a *read* side that spans all enabled
versions, so ciphertext and MACs remain usable during rotation.

## AEAD encryption and decryption

[`CipherKey`](crate::kms::symmetric::cipher::CipherKey) is the combined key: it
encrypts with a single version chosen by the
[`VersionStrategy`](crate::kms::VersionStrategy) and decrypts with every enabled
version. It implements [`AeadEncryptor`](huskarl_core::crypto::cipher::AeadEncryptor)
and [`AeadDecryptor`](huskarl_core::crypto::cipher::AeadDecryptor):

```rust,no_run
use google_cloud_kms_v1::client::KeyManagementService;
use huskarl_core::crypto::cipher::{AeadDecryptor, AeadEncryptor};
use huskarl_google_cloud::kms::{VersionStrategy, symmetric::cipher::CipherKey};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let kms_client = KeyManagementService::builder().build().await?;

let cipher = CipherKey::builder()
    .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
    .kms_client(kms_client)
    // Encrypt with a label-pinned version, promoted only after it has
    // propagated to every decryptor — see the rotation explanation.
    .strategy(VersionStrategy::ByLabel("active".into()))
    .build()
    .await?;

let sealed = cipher.encrypt(b"plaintext", b"aad").await?;
let recovered = cipher
    .decrypt(None, &sealed.nonce, &sealed.ciphertext, &sealed.tag, b"aad")
    .await?;
assert_eq!(recovered, b"plaintext");
# Ok(())
# }
```

If encrypt and decrypt live on different services, use the one-sided
[`EncryptionKey`](crate::kms::symmetric::cipher::EncryptionKey) (pins one
version) and [`DecryptionKey`](crate::kms::symmetric::cipher::DecryptionKey)
(spans all enabled versions) instead of the combined `CipherKey`.

## HMAC signing and verification

For `MAC` keys, [`SigningKey`](crate::kms::symmetric::signer::SigningKey) signs
with one version and [`VerifyingKey`](crate::kms::symmetric::signer::VerifyingKey)
verifies against all enabled versions (`HmacSha256/384/512` map to
`HS256/HS384/HS512`):

```rust,no_run
use google_cloud_kms_v1::client::KeyManagementService;
use huskarl_core::crypto::signer::JwsSigner;
use huskarl_core::crypto::verifier::{JwsVerifier, KeyMatch};
use huskarl_google_cloud::kms::symmetric::signer::{SigningKey, VerifyingKey};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let kms_client = KeyManagementService::builder().build().await?;
let key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/mac";

let signer = SigningKey::builder()
    .key_name(key_name)
    .kms_client(kms_client.clone())
    .build()
    .await?;
let mac = signer.sign(b"protected.payload").await?;

let verifier = VerifyingKey::builder()
    .key_name(key_name)
    .kms_client(kms_client)
    .build()
    .await?;
verifier
    .verify(
        b"protected.payload",
        &mac,
        &KeyMatch::builder().alg("HS256").build(),
    )
    .await?;
# Ok(())
# }
```

Encryption and signing pin one version; decryption and verification span all
enabled versions — the asymmetry that makes rotation safe. See
[key versions and rotation](crate::_docs::explanation::versions_and_rotation)
for the strategy trade-offs, and the
[self-refreshing keys guide](crate::_docs::guide::refreshing_keys) to pick up
rotated versions automatically.
