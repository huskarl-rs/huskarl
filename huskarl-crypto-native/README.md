<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Native (RustCrypto-backed) implementations of huskarl’s crypto traits: JWS
signing and verification, plus AEAD encryption.

- [`asymmetric`](https://docs.rs/huskarl-crypto-native/latest/huskarl_crypto_native/asymmetric/) and [`symmetric`](https://docs.rs/huskarl-crypto-native/latest/huskarl_crypto_native/symmetric/) provide the JWS signer/verifier key types
  ([`PrivateKey`](https://docs.rs/huskarl-crypto-native/latest/huskarl_crypto_native/asymmetric/signer/struct.PrivateKey.html),
  [`AsymmetricPublicKey`](https://docs.rs/huskarl-crypto-native/latest/huskarl_crypto_native/asymmetric/verifier/struct.AsymmetricPublicKey.html), and
  [`SymmetricKey`](https://docs.rs/huskarl-crypto-native/latest/huskarl_crypto_native/symmetric/struct.SymmetricKey.html)).
- [`NativeVerifierPlatform`](https://docs.rs/huskarl-crypto-native/latest/huskarl_crypto_native/factory/struct.NativeVerifierPlatform.html) builds a verifier from a public JWK; it is the
  feature-gated default verifier platform for the ecosystem.
- [`aead`](https://docs.rs/huskarl-crypto-native/latest/huskarl_crypto_native/aead/) provides an AES-GCM AEAD cipher ([`AesGcmKey`](https://docs.rs/huskarl-crypto-native/latest/huskarl_crypto_native/aead/struct.AesGcmKey.html)).

The following JWS algorithms are available:

- Asymmetric (Edwards-curve)
  - `Ed25519` (aka `EdDSA`)
- Asymmetric (NIST elliptic curves)
  - ES256
  - ES384
- Symmetric (HMAC)
  - HS256
  - HS384
  - HS512
- Asymmetric (RSA)
  - RS256
  - RS384
  - RS512
  - PS256
  - PS384
  - PS512

# Getting started

Generate a signing key, then build and sign a JWT with it:

```rust
use huskarl_core::jwt::Jwt;
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

// A signer backed by a freshly generated Ed25519 key.
let signer = PrivateKey::generate(GenerateAlgorithm::Ed25519, Some("key-1".to_string()))?;

let jwt = Jwt::builder()
    .issuer("https://issuer.example")
    .subject("user-123")
    .issued_now_expires_after(std::time::Duration::from_secs(300))
    .claims(serde_json::json!({ "scope": "read write" }))
    .build();

// A compact JWS string, ready for the wire.
let compact = jwt.to_jws_compact(&signer).await?;
```

To verify, build an [`AsymmetricPublicKey`](https://docs.rs/huskarl-crypto-native/latest/huskarl_crypto_native/asymmetric/verifier/struct.AsymmetricPublicKey.html)
from a public JWK (or use [`NativeVerifierPlatform`](https://docs.rs/huskarl-crypto-native/latest/huskarl_crypto_native/factory/struct.NativeVerifierPlatform.html) over a JWKS) and hand it
to `huskarl-core`’s JWT validator.

# Further reading

These pages live in `huskarl-core`, which defines the traits this crate
implements:

- [Building and signing a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/signing_a_jwt/index.html)
- [Validating a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/validating_a_jwt/index.html)
- [Composing crypto strategies](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/crypto_strategies/index.html)
  — how the multi-key, refreshable, and retrying wrappers stack on these keys.

<!-- cargo-reedme: end -->
