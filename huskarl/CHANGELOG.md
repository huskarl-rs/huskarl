# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changes

 - Update client auth on DPoP-based retry (private key jwt must have different jti if present).
 - Adds allowed_id_token_signed_response_algs to filter allowed algorithms for ID token signature algorithm.
 - Checks that azp has the client_id if the aud value of an ID token has multiple values.

## [0.6.0] - 2026-05-06

### Changes

 - Return BuildError when a JWS verifier factory but no platform is set for authorization code grant
 - Improve the error messages when ID tokens are unable to be verified due to insufficient configuration.
 - Bump huskarl-core to 0.5

## [0.5.2] - 2026-05-06

### Changes

 - Added huskarl_core::Error implementation for StartError in auth code grant.

## [0.5.1] - 2026-04-29

### Fixes

- Send dpop_jkt for device endpoint and PAR endpoint

## [0.5.0] - 2026-04-28

### Changes

- Bump huskarl-core to 0.4

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
