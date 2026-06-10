# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changes

 - Avoid panicking in JWT creation or validation (in time handling).
 - Timestamps in JWTs are represented by SystemTime instead of u64.
 - Burn JTI after all other JWT checks have passed.
 - Adds in-memory JTI uniqueness checker (especially for tests).
 - Add concrete error type (to replace trait).
 - Update traits to be dyn traits.
 - Add `KeyMatch::strength_for` and `CipherMatch::strength_for` helpers so
   single-key verifier/decryptor implementations can delegate the standard
   algorithm/kid matching rules instead of re-implementing them.

## [0.6.4] - 2026-05-29

### Changes

 - Added dpop_signing_alg_values_supported to server metadata.
 - Include body of response in error when an OAuth2 error couldn't be parsed.
 - Added serde utils for serializing vec-or-string, and SystemTime.

## [0.6.3] - 2026-05-26

### Changes

 - Fix path for OIDC/authorization server metadata.

## [0.6.1] - 2026-05-25

### Additions

 - Added FileSecret which lazily loads a secret from a path on disk (behind fs feature flag).

## [0.6.0] - 2026-05-25

### Additions

 - Added some extra OpenID fields to authorization server metadata for logout and userinfo.
 - Added a max JTI length check to the JWT validator.
 - Added MultiKeySigner that allows signer selection by thumbprint.
 - Breaking: Expanded JWK code to public/private types and conversions between them.

### Changes

 - Breaking: made AsymmetricJwsSignerSelector a subtype of JwsSignerSelector.
 - The builder method that fetches authorization server metadata is now called fetch().
 - The authorization server metadata method builder() is the actual struct builder.
 - Authorization server metadata is now non-exhaustive.
 - Made a number of public enums/structs non-exhaustive.
 - DPoP traits are now sealed (can only be implemented in huskarl-core).

## [0.5.1] - 2026-05-21

### Additions

 - Adds BoxedAeadCipher - boxed value that implements both encryption and decryption.

## [0.5.0] - 2026-05-06

### Additions

- Adds RefreshableSigner/ScheduledRefreshSigner to allow JWS signers to be reloaded.
- Adds MultiKeyDecryptor/MultiKeyCipher that handle routing of decryption with multiple keys.

### Changes

- TTL for verifier refresh changed from 5 minutes to 1 hour.
- RefreshingVerifier changed to ScheduledRefreshVerifier (with backwards compatible type alias for now).
- Breaking: AeadSealer gains tag/nonce length in the serialized value, removed from the AeadDecryptor trait.
- Breaking: AeadDecryptor adds a cipher_match parameter letting decryption occur without needing to try all keys.
- Breaking: The alg parameter of CipherMatch becomes an Option.

## [0.4.1] - 2026-04-28

### Fixes

- Handle deserializing claims into ()

## [0.4.0] - 2026-04-28

- Breaking: add an ExtraClaims error when parsing a JWT, which is returned if the custom claim type cannot be parsed into.

## [0.3.0] - 2026-04-28

### Changes

- Breaking: makes claims a non-optional type, renames the field to `claims`, type to `Claims`.

## [0.2.0] - 2026-04-06

### Additions

- Adds AEAD encryption/decryption traits (initially planned for DPoP nonces).
- Adds JTI cache trait, and adds a parameter for this to JwtValidator.

### Removals

- Removes `HasPublicKey` trait.
- Moved the token module to `huskarl`.

### Changes

- DPoP uses `AsymmetricJwsSigningKey` as a bound instead of `HasPublicKey`.
- Improves matching of wasm targets with actual ability.
- Split out use side of `JwsSigningKey` into `JwsSigner`, update boxed trait.
- Allow asymmetric signers to have secondary as well as primary signing keys (useful for DPoP key rotation).
- Generating DPoP proofs requires a known thumbprint to be provided.
- Moved validation from the token module to the jwt module.
- Moved the token module to `huskarl`.

## [0.1.0] - 2026-03-24

- Initial implementation.
