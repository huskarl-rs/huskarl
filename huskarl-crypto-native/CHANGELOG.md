# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
