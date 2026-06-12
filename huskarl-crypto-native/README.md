<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Native rust implementation of JWS signers.

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

<!-- cargo-reedme: end -->
