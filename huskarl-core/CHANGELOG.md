# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
