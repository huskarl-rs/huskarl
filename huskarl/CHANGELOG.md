# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-04-28

### Improvements

- Extra claims are no longer wrapped in an option.

### Changes

- Bump huskarl-core to 0.3
- Bump huskarl-crypto-native to 0.4
- Bump huskarl-crypto-webcrypto to 0.3 

## [0.3.0]

### Changes

- Bump huskarl-crypto-native to 0.3 to bring pinned rustcrypto RC versions.

## [0.2.0]

### Improvements

- Support DPoP key binding throughout the session lifecycle.
- Add resource parameter to device authorization grant.

### Changes

- Breaking: Update to huskarl-core 0.2, implement AsymmetricJwsSigningKey, remove HasPublicKey.
- Limit authorization-flow-loopback to just non-WASM.
- Breaking: Move the token module from core.

## [0.1.0] - 2026-03-24

- Initial implementation.
