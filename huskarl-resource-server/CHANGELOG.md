# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-resource-server-v0.9.1...huskarl-resource-server-v0.10.0) - 2026-07-19

### Added

- *(core)* [**breaking**] Move server-side DPoP nonce checking into core ([#245](https://github.com/huskarl-rs/huskarl/pull/245))
- *(crypto)* [**breaking**] Add back kid (optional string) for seal kid matching. ([#241](https://github.com/huskarl-rs/huskarl/pull/241))
- *(crypto-native)* Add XChaCha20-Poly1305 AEAD cipher ([#238](https://github.com/huskarl-rs/huskarl/pull/238))
- *(resource-server)* [**breaking**] Make validator metrics a decorator. ([#232](https://github.com/huskarl-rs/huskarl/pull/232))
- *(crypto)* [**breaking**] Separate selectors from signers for JWS signers ([#229](https://github.com/huskarl-rs/huskarl/pull/229))
- *(crypto)* [**breaking**] Implement selector for AES-GCM key, split off sealing traits. ([#225](https://github.com/huskarl-rs/huskarl/pull/225))

### Other

- *(jwt)* [**breaking**] Unify claim naming on serialized name, builders and struct fields. ([#230](https://github.com/huskarl-rs/huskarl/pull/230))

## [0.9.1](https://github.com/huskarl-rs/huskarl/compare/huskarl-resource-server-v0.9.0...huskarl-resource-server-v0.9.1) - 2026-07-10

### Fixed

- *(resource-server)* A JTI check error is not an invalid token. ([#215](https://github.com/huskarl-rs/huskarl/pull/215))

## [0.9.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-resource-server-v0.8.0...huskarl-resource-server-v0.9.0) - 2026-07-08

### Added

- *(core)* Let ClaimCheck fields accept plain strings ([#178](https://github.com/huskarl-rs/huskarl/pull/178))
- *(resource-server)* [**breaking**] Derive the RFC 9728 document from validator metadata ([#175](https://github.com/huskarl-rs/huskarl/pull/175))
- *(core)* Add RFC 9728 protected resource metadata URL derivation ([#172](https://github.com/huskarl-rs/huskarl/pull/172))
- *(resource-server)* Point WWW-Authenticate challenges at RFC 9728 resource metadata ([#167](https://github.com/huskarl-rs/huskarl/pull/167))
- *(resource-server)* Advertise mTLS-bound token support in validator metadata ([#166](https://github.com/huskarl-rs/huskarl/pull/166))
- *(resource-server)* Carry the required scope on InsufficientScope ([#164](https://github.com/huskarl-rs/huskarl/pull/164))
- *(resource-server)* Let validators carry the challenge realm ([#163](https://github.com/huskarl-rs/huskarl/pull/163))
- *(resource-server)* Helper to turn resource server validation failures into a response ([#162](https://github.com/huskarl-rs/huskarl/pull/162))
- *(resource-server)* Require that DPoP htu is an absolute URL ([#157](https://github.com/huskarl-rs/huskarl/pull/157))
- *(resource-server)* Refuse to validate DPoP keys that have a private component. ([#155](https://github.com/huskarl-rs/huskarl/pull/155))
- *(resource-server)* Add clock-skew leeway to all temporal checks ([#147](https://github.com/huskarl-rs/huskarl/pull/147))
- [**breaking**] Make key selection async and split refresh into miss/TTL paths ([#130](https://github.com/huskarl-rs/huskarl/pull/130))

### Fixed

- *(resource-server)* Escape the DPoP algs challenge value ([#203](https://github.com/huskarl-rs/huskarl/pull/203))
- *(resource-server)* Reject requests carrying more than one DPoP header ([#199](https://github.com/huskarl-rs/huskarl/pull/199))
- *(resource-server)* Preserve the rotated DPoP nonce when a later binding check fails ([#197](https://github.com/huskarl-rs/huskarl/pull/197))
- *(resource-server)* Make sure introspection can't panic from timestamp in server response ([#190](https://github.com/huskarl-rs/huskarl/pull/190))
- *(resource-server)* [**breaking**] Advertise DPoP challenge when DPoP is accepted but unrestricted ([#135](https://github.com/huskarl-rs/huskarl/pull/135))

### Other

- Update documentation ([#206](https://github.com/huskarl-rs/huskarl/pull/206))
- Update documentation ([#195](https://github.com/huskarl-rs/huskarl/pull/195))
- Update documentation ([#193](https://github.com/huskarl-rs/huskarl/pull/193))
- *(crypto)* [**breaking**] Make PrivateJwk a sum type and route symmetric keys through the JWK funnel ([#188](https://github.com/huskarl-rs/huskarl/pull/188))
- [**breaking**] Normalize DPoP capitalization across types. ([#182](https://github.com/huskarl-rs/huskarl/pull/182))
- [**breaking**] Make authentication_params a builder struct, rename authentication_context ([#181](https://github.com/huskarl-rs/huskarl/pull/181))
- Align the preludes on a call-side-traits principle ([#173](https://github.com/huskarl-rs/huskarl/pull/173))
- Add DPoP and client authentication how-to guides ([#165](https://github.com/huskarl-rs/huskarl/pull/165))
- Update README
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
