# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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
