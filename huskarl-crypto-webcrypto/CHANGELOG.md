# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.1](https://github.com/huskarl-rs/huskarl/compare/huskarl-crypto-webcrypto-v0.10.0...huskarl-crypto-webcrypto-v0.10.1) - 2026-07-20

### Other

- *(crypto)* AEAD impls should avoid referring to sealing ([#252](https://github.com/huskarl-rs/huskarl/pull/252))
- *(crypto)* Split sealing into its own module. ([#249](https://github.com/huskarl-rs/huskarl/pull/249))

## [0.10.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-crypto-webcrypto-v0.9.0...huskarl-crypto-webcrypto-v0.10.0) - 2026-07-19

### Added

- *(crypto)* [**breaking**] Return diagnostic errors from AsymmetricPublicKey::from_jwk ([#234](https://github.com/huskarl-rs/huskarl/pull/234))
- *(crypto)* [**breaking**] Separate selectors from signers for JWS signers ([#229](https://github.com/huskarl-rs/huskarl/pull/229))
- *(crypto)* [**breaking**] Implement selector for AES-GCM key, split off sealing traits. ([#225](https://github.com/huskarl-rs/huskarl/pull/225))

### Other

- *(jwt)* [**breaking**] Unify claim naming on serialized name, builders and struct fields. ([#230](https://github.com/huskarl-rs/huskarl/pull/230))

## [0.9.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-crypto-webcrypto-v0.8.0...huskarl-crypto-webcrypto-v0.9.0) - 2026-07-08

### Added

- Add supported_signature_algorithms to JwsVerifierPlatform. ([#196](https://github.com/huskarl-rs/huskarl/pull/196))
- *(core)* Add ProvidedSecret for when you have a live secret to pass to secret API. ([#180](https://github.com/huskarl-rs/huskarl/pull/180))
- [**breaking**] Make key selection async and split refresh into miss/TTL paths ([#130](https://github.com/huskarl-rs/huskarl/pull/130))

### Fixed

- *(resource-server)* Escape the DPoP algs challenge value ([#203](https://github.com/huskarl-rs/huskarl/pull/203))
- *(crypto-webcrypto)* Validate RSA modulus by bit length with an upper bound ([#201](https://github.com/huskarl-rs/huskarl/pull/201))
- *(crypto-webcrypto)* Surface JS error details instead of an empty string ([#149](https://github.com/huskarl-rs/huskarl/pull/149))
- *(crypto-webcrypto)* Reject kid-mismatched tokens in verify() ([#148](https://github.com/huskarl-rs/huskarl/pull/148))

### Other

- Update documentation ([#195](https://github.com/huskarl-rs/huskarl/pull/195))
- Update documentation ([#193](https://github.com/huskarl-rs/huskarl/pull/193))
- *(crypto)* [**breaking**] Make PrivateJwk a sum type and route symmetric keys through the JWK funnel ([#188](https://github.com/huskarl-rs/huskarl/pull/188))
- *(crypto)* [**breaking**] Add Pkcs8Pem and remove the legacy key loaders ([#185](https://github.com/huskarl-rs/huskarl/pull/185))
- [**breaking**] Disambiguate crypto-native key-load error enums ([#183](https://github.com/huskarl-rs/huskarl/pull/183))
- Pay down the usability-review docs debt ([#179](https://github.com/huskarl-rs/huskarl/pull/179))
- Document that a particular AES-GCM key shoud be used at most 2^32 times ([#158](https://github.com/huskarl-rs/huskarl/pull/158))
- Document crypto strategies, JWT verification config, and revocation TTL ([#131](https://github.com/huskarl-rs/huskarl/pull/131))
- Require RSA keys to be 2024 bits or more for webcrypto. ([#120](https://github.com/huskarl-rs/huskarl/pull/120))
- Docs update ([#92](https://github.com/huskarl-rs/huskarl/pull/92))

 - Require RSA keys to be at least 2048 bits.

## [0.8.0] - 2026-06-15

### Changes

 - Bump huskarl-core to 0.7.0-pre.0 and adopt its dyn-trait design:
 - Ed25519 keys in webcrypto support both Ed25519 and EdDSA algorithms
 - Add WebCrypto AES-GCM AEAD

## [0.7.0] - 2026-05-25

### Changes

 - Bump to huskarl-core 0.6.

## [0.6.0] - 2026-05-06

### Changes

 - Actually bump to huskarl-core 0.5.

## [0.5.0] - 2026-05-06

### Changes

 - Bump to huskarl-core 0.5.

## [0.4.0] - 2026-04-28

### Changes

- Bump to huskarl-core 0.4.

## [0.3.0] - 2026-04-28

### Changes

- Bump to huskarl-core 0.3.

## [0.2.0] - 2026-04-06

### Changes

- Breaking: Update to huskarl-core 0.2.

### Bug Fixes

- Fix verification (data and signature arguments were in incorrect order).
- Serialize JWKs through serde_json to retain `kty` field.

## [0.1.0] - 2026-03-24

- Initial implementation.
