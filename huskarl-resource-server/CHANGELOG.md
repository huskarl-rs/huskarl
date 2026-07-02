# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-resource-server-v0.8.0...huskarl-resource-server-v0.9.0) - 2026-07-02

### Added

- [**breaking**] Make key selection async and split refresh into miss/TTL paths ([#130](https://github.com/huskarl-rs/huskarl/pull/130))

### Other

- Document crypto strategies, JWT verification config, and revocation TTL ([#131](https://github.com/huskarl-rs/huskarl/pull/131))
- Reduce version numbers to init release-plz without publishing.
- Update docs ([#124](https://github.com/huskarl-rs/huskarl/pull/124))
- Strip control chars from www-authenticate parameters ([#122](https://github.com/huskarl-rs/huskarl/pull/122))
- Add MultiIssuerValidator, box futures in AccessTokenValidator to make them dyn compatible. ([#121](https://github.com/huskarl-rs/huskarl/pull/121))
- Add non_exhaustive to more enums ([#107](https://github.com/huskarl-rs/huskarl/pull/107))
- Read allowed ID token signing algorithms from AS metadata. ([#104](https://github.com/huskarl-rs/huskarl/pull/104))
- Build the RFC 7662 introspection request via oauth_form ([#100](https://github.com/huskarl-rs/huskarl/pull/100))
- Add ability to refresh token cache ahead of expiry. ([#94](https://github.com/huskarl-rs/huskarl/pull/94))
- Split up some large files ([#93](https://github.com/huskarl-rs/huskarl/pull/93))
- Docs update ([#92](https://github.com/huskarl-rs/huskarl/pull/92))
- Simplify some code

 - Breaking: Make AccessTokenValidator dyn-compatible (with boxed futures).
 - Add MultiIssuerValidator which can route validator by iss value.
 - Add `non_exhaustive` to various error types.
 - Breaking: Add Debug bound to ToRfc6750Error.
 - Strip control chars from www-authenticate parameters.
 
## [0.8.0] - 2026-06-15

 - Breaking: ported to the dyn-first huskarl-core.
 - Check for audience with claims received from introspection.

## [0.7.0] - 2026-05-26

### Changes

- Breaking: Split out DPoP proof into a separate struct with its own errors
- Switch timestamp-based nonce to base64url encoding
- Bump huskarl-core to 0.6

## [0.6.1] - 2026-05-07

- Add Serialize impl for Rfc9068AccessTokenClaims

## [0.6.0] - 2026-05-06

### Changes

- Bump huskarl-core to 0.5

## [0.5.0] - 2026-04-28

### Improvements

- If custom claims from a JWT token fail to be parsed, there is a distinct error.
- Flatten configuration of custom resource server config to be more friendly.
- RFC 9728 resource identifer is no longer tied to the audience.

## Changes

- Bump huskarl-core to 0.4
- Breaking: some changes to the custom validator API.

## [0.4.0] - 2026-04-28

### Improvements

- Extra claims are no longer wrapped in an option.

### Changes

- Bump huskarl-core to 0.3
- Bump huskarl-crypto-native to 0.4
- Bump huskarl-crypto-webcrypto to 0.3 

## [0.3.0] - 2026-04-27

### Changes

- Make the DPoP nonce checker an optional field in validators (defaults to no check).

## [0.2.0] - 2026-04-06

### Additions

- Add JTI and DPoP nonce support.

### Changes

- Breaking: Update to huskarl-core 0.2.
- Improve the information used to generate www-authenticate headers

## [0.1.0] - 2026-03-24

- Initial implementation.
