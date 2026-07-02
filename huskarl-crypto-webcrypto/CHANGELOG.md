# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-crypto-webcrypto-v0.8.0...huskarl-crypto-webcrypto-v0.9.0) - 2026-07-02

### Added

- [**breaking**] Make key selection async and split refresh into miss/TTL paths ([#130](https://github.com/huskarl-rs/huskarl/pull/130))

### Other

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
