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

<!-- cargo-reedme: end -->
