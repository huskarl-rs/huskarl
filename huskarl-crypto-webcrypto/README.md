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

- `asymmetric` provides the JWS signer/verifier key types, `PrivateKey` and
  `AsymmetricPublicKey`.
- `WebCryptoVerifierPlatform` builds a verifier from a public JWK; it is the
  default verifier platform on wasm targets.
- `aead` provides the `AesGcmKey` AES-GCM cipher.

Because `WebCrypto` is async, signing, verification, and key import are `async`.

To sign, generate a non-extractable `PrivateKey` and hand it to
`huskarl-core`’s [`Jwt`](https://docs.rs/huskarl_core/latest/huskarl_core/jwt/builder/struct.Jwt.html) builder. To verify, build an
`AsymmetricPublicKey` from a public JWK, or use
`WebCryptoVerifierPlatform` over a JWKS.

# Further reading

- [Signing a JWT in the browser](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/_docs/guide/signing_a_jwt/index.html)
  describes the async, non-extractable signing flow.
- [Platform constraints](https://docs.rs/huskarl-crypto-webcrypto/latest/huskarl_crypto_webcrypto/_docs/explanation/platform_constraints/index.html)
  explains why this backend does not support private-key import or
  `client_secret_jwt`.

These pages live in `huskarl-core`, which defines the traits this crate
implements:

- [Building and signing a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/signing_a_jwt/index.html)
- [Validating a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/validating_a_jwt/index.html)
- [Composing crypto strategies](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/crypto_strategies/index.html)
  — how the multi-key, refreshable, and retrying wrappers stack on these keys.

<!-- cargo-reedme: end -->
