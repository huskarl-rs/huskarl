<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme --manifest-path huskarl-crypto-webcrypto/Cargo.toml

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

`WebCrypto` (`SubtleCrypto`) implementations of huskarl’s crypto traits: JWS
signing and verification, plus AES-GCM AEAD. wasm32-only.

- [`asymmetric`](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/asymmetric/) provides the JWS signer/verifier key types
  ([`PrivateKey`](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/asymmetric/signer/struct.PrivateKey.html),
  [`AsymmetricPublicKey`](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/asymmetric/verifier/struct.AsymmetricPublicKey.html)).
- [`WebCryptoVerifierPlatform`](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/factory/struct.WebCryptoVerifierPlatform.html) builds a verifier from a public JWK; it is the
  default verifier platform on wasm targets.
- [`aead`](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/aead/) provides an AES-GCM AEAD cipher ([`AesGcmKey`](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/aead/struct.AesGcmKey.html)).

Because `WebCrypto` is async, signing, verification, and key import are `async`.

# Getting started

Generate a non-extractable signing key, then build and sign a JWT with it.
Every crypto call is `async`, and the key never leaves `SubtleCrypto`:

```rust
use huskarl_core::jwt::Jwt;
use huskarl_crypto_webcrypto::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

let signer = PrivateKey::generate(GenerateAlgorithm::Es256, Some("key-1".to_string())).await?;

let jwt = Jwt::builder()
    .issuer("https://issuer.example")
    .subject("user-123")
    .issued_now_expires_after(std::time::Duration::from_secs(300))
    .claims(serde_json::json!({ "scope": "read write" }))
    .build();

// A compact JWS string, ready for the wire.
let compact = jwt.to_jws_compact(&signer).await?;
```

To verify, build an [`AsymmetricPublicKey`](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/asymmetric/verifier/struct.AsymmetricPublicKey.html)
from a public JWK (or use [`WebCryptoVerifierPlatform`](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/factory/struct.WebCryptoVerifierPlatform.html) over a JWKS) and hand
it to `huskarl-core`’s JWT validator.

# Further reading

These pages live in `huskarl-core`, which defines the traits this crate
implements:

- [Building and signing a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/signing_a_jwt/index.html)
- [Validating a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/validating_a_jwt/index.html)
- [Composing crypto strategies](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/crypto_strategies/index.html)
  — how the multi-key, refreshable, and retrying wrappers stack on these keys.

<!-- cargo-reedme: end -->
