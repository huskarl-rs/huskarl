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

To sign, generate a non-extractable
[`PrivateKey`](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/asymmetric/signer/struct.PrivateKey.html) and hand it to `huskarl-core`’s
[`Jwt`](https://docs.rs/huskarl_core/latest/huskarl_core/jwt/builder/struct.Jwt.html) builder. To verify, build an
[`AsymmetricPublicKey`](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/asymmetric/verifier/struct.AsymmetricPublicKey.html) from a
public JWK (or use [`WebCryptoVerifierPlatform`](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/factory/struct.WebCryptoVerifierPlatform.html) over a JWKS).

# Documentation

- **Solve a task:** [sign a JWT in the browser](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/_docs/guide/signing_a_jwt/)
  with an async, non-extractable key.
- **Understand the design:** read the
  [platform constraints](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/_docs/explanation/platform_constraints/)
  that distinguish this backend from `huskarl-crypto-native`.
- **Look up the API:** use the crate modules and item pages in this reference.

Related how-to guides and explanation live in `huskarl-core`, which defines
the traits this crate implements:

- [Building and signing a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/signing_a_jwt/index.html)
- [Validating a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/validating_a_jwt/index.html)
- [Composing crypto strategies](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/crypto_strategies/index.html)
  — how the multi-key, refreshable, and retrying wrappers stack on these keys.

<!-- cargo-reedme: end -->
