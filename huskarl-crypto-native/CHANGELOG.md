# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.1](https://github.com/huskarl-rs/huskarl/compare/huskarl-crypto-native-v0.10.0...huskarl-crypto-native-v0.10.1) - 2026-07-20

### Other

- *(crypto)* AEAD impls should avoid referring to sealing ([#252](https://github.com/huskarl-rs/huskarl/pull/252))

## [0.10.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-crypto-native-v0.9.0...huskarl-crypto-native-v0.10.0) - 2026-07-19

### Added

- *(crypto-native)* Add alg-dispatching AEAD constructors ([#239](https://github.com/huskarl-rs/huskarl/pull/239))
- *(crypto-native)* Add XChaCha20-Poly1305 AEAD cipher ([#238](https://github.com/huskarl-rs/huskarl/pull/238))
- *(crypto)* [**breaking**] Return diagnostic errors from AsymmetricPublicKey::from_jwk ([#234](https://github.com/huskarl-rs/huskarl/pull/234))
- *(crypto)* [**breaking**] Separate selectors from signers for JWS signers ([#229](https://github.com/huskarl-rs/huskarl/pull/229))
- *(crypto)* [**breaking**] Implement selector for AES-GCM key, split off sealing traits. ([#225](https://github.com/huskarl-rs/huskarl/pull/225))

### Other

- Add a few more references to XChaCha20-Poly1305. ([#246](https://github.com/huskarl-rs/huskarl/pull/246))
- *(jwt)* [**breaking**] Unify claim naming on serialized name, builders and struct fields. ([#230](https://github.com/huskarl-rs/huskarl/pull/230))

## [0.9.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-crypto-native-v0.8.5...huskarl-crypto-native-v0.9.0) - 2026-07-08

### Added

- Add supported_signature_algorithms to JwsVerifierPlatform. ([#196](https://github.com/huskarl-rs/huskarl/pull/196))
- *(crypto-native)* Bump p256, p384, ed25519-dalek to non-RC releases ([#194](https://github.com/huskarl-rs/huskarl/pull/194))
- *(crypto)* [**breaking**] Load private keys through JWKs ([#184](https://github.com/huskarl-rs/huskarl/pull/184))
- [**breaking**] Make key selection async and split refresh into miss/TTL paths ([#130](https://github.com/huskarl-rs/huskarl/pull/130))

### Fixed

- *(crypto-native)* Validate RSA modulus by bit length with an upper bound ([#200](https://github.com/huskarl-rs/huskarl/pull/200))
- *(crypto-native)* Return an error instead of panicking on fallible signing ([#137](https://github.com/huskarl-rs/huskarl/pull/137))

### Other

- Update documentation ([#206](https://github.com/huskarl-rs/huskarl/pull/206))
- RsaPublicKey::new already enforces 8192-bit max keys, remove check ([#202](https://github.com/huskarl-rs/huskarl/pull/202))
- Update documentation ([#195](https://github.com/huskarl-rs/huskarl/pull/195))
- Update documentation ([#193](https://github.com/huskarl-rs/huskarl/pull/193))
- *(crypto)* [**breaking**] Make PrivateJwk a sum type and route symmetric keys through the JWK funnel ([#188](https://github.com/huskarl-rs/huskarl/pull/188))
- Add extra docs on loading keys ([#187](https://github.com/huskarl-rs/huskarl/pull/187))
- *(crypto)* [**breaking**] Unify from_jwk on the core Error type ([#186](https://github.com/huskarl-rs/huskarl/pull/186))
- *(crypto)* [**breaking**] Add Pkcs8Pem and remove the legacy key loaders ([#185](https://github.com/huskarl-rs/huskarl/pull/185))
- [**breaking**] Disambiguate crypto-native key-load error enums ([#183](https://github.com/huskarl-rs/huskarl/pull/183))
- Extract common max-age handling to a shared function ([#161](https://github.com/huskarl-rs/huskarl/pull/161))
- Document that a particular AES-GCM key shoud be used at most 2^32 times ([#158](https://github.com/huskarl-rs/huskarl/pull/158))
- Document crypto strategies, JWT verification config, and revocation TTL ([#131](https://github.com/huskarl-rs/huskarl/pull/131))

## [0.8.5] - 2026-06-30

### Changes

 - Bump rustcrypto rc deps.

## [0.8.4] - 2026-06-29

### Changes

 - Bump aes-gcm to 0.11.

## [0.8.3] - 2026-06-23

### Changes

 - Bump rustcrypto rc deps.

## [0.8.2] - 2026-06-23

### Changes

 - Bump rustcrypto rc deps.

## [0.8.1] - 2026-06-18

### Changes

 - Bump rustcrypto rc deps.

## [0.8.0] - 2026-06-15

### Changes

 - Bump huskarl-core to 0.7.0-pre.0 and adopt its dyn-trait design.
 - Native AEAD: auto-detect AES key size, add AES-192; adopt strum for algorithm names

## [0.7.1] - 2026-06-04

### Changes

 - Bump rustcrypto deps.

## [0.7.0] - 2026-05-25

### Added

 - Added from_jwk and as_private_jwk methods for JWK-based conversion.

## Changes

 - Bump huskarl-core to 0.6.

## [0.6.0] - 2026-05-06

### Changes

 - Bump huskarl-core to 0.5.
 - Update rustcrypto deps.

## [0.5.0] - 2026-04-28

### Changes

- Bump huskarl-core to 0.4.

## [0.4.0] - 2026-04-28

### Changes

- Bump huskarl-core to 0.3.

## [0.3.0]

### Changes

- Pin rustcrypto RC versions to a working combination.

## [0.2.0]

### Added

- Added AEAD (AES-GCM) implementation.

### Changes

- Breaking: Update to huskarl-core 0.2, implement AsymmetricJwsSigningKey, remove HasPublicKey.

## [0.1.0] - 2026-03-24

- Initial implementation.
