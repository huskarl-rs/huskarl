# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-core-v0.7.1...huskarl-core-v0.8.0) - 2026-07-08

### Added

- Add supported_signature_algorithms to JwsVerifierPlatform. ([#196](https://github.com/huskarl-rs/huskarl/pull/196))
- *(crypto)* [**breaking**] Load private keys through JWKs ([#184](https://github.com/huskarl-rs/huskarl/pull/184))
- *(core)* Add ProvidedSecret for when you have a live secret to pass to secret API. ([#180](https://github.com/huskarl-rs/huskarl/pull/180))
- *(core)* Let ClaimCheck fields accept plain strings ([#178](https://github.com/huskarl-rs/huskarl/pull/178))
- *(core)* Add the RFC 9728 ProtectedResourceMetadata document ([#174](https://github.com/huskarl-rs/huskarl/pull/174))
- *(core)* Add RFC 9728 protected resource metadata URL derivation ([#172](https://github.com/huskarl-rs/huskarl/pull/172))
- *(core)* Reject non-http(s) schemes and userinfo in EndpointUrl ([#169](https://github.com/huskarl-rs/huskarl/pull/169))
- *(core)* Give EndpointUrl Display and Uri conversions ([#168](https://github.com/huskarl-rs/huskarl/pull/168))
- *(resource-server)* Refuse to validate DPoP keys that have a private component. ([#155](https://github.com/huskarl-rs/huskarl/pull/155))
- *(core)* [**breaking**] Enable mapping of secret output, make b64/hex more forgiving. ([#153](https://github.com/huskarl-rs/huskarl/pull/153))
- [**breaking**] Make key selection async and split refresh into miss/TTL paths ([#130](https://github.com/huskarl-rs/huskarl/pull/130))
- *(core)* Add configurable TTL to JwksSource ([#129](https://github.com/huskarl-rs/huskarl/pull/129))

### Fixed

- *(dpop)* Stop setting exp on client DPoP proofs by default ([#205](https://github.com/huskarl-rs/huskarl/pull/205))
- *(oidc)* Guard ID-token auth_time overflow and default clock leeway ([#189](https://github.com/huskarl-rs/huskarl/pull/189))
- *(core)* Don't reject future-iat tokens via the max_token_age check ([#140](https://github.com/huskarl-rs/huskarl/pull/140))
- *(core)* Skip malformed JWKS entries instead of failing the whole set ([#139](https://github.com/huskarl-rs/huskarl/pull/139))
- *(core)* Enforce refresh policy under the single-flight lock ([#138](https://github.com/huskarl-rs/huskarl/pull/138))
- *(core)* Remove fuzz Cargo.lock
- *(core)* Bound metrics alg label to registered JWS algorithms ([#125](https://github.com/huskarl-rs/huskarl/pull/125))

### Other

- Update documentation ([#206](https://github.com/huskarl-rs/huskarl/pull/206))
- Update documentation ([#195](https://github.com/huskarl-rs/huskarl/pull/195))
- Update documentation ([#193](https://github.com/huskarl-rs/huskarl/pull/193))
- *(crypto)* [**breaking**] Make PrivateJwk a sum type and route symmetric keys through the JWK funnel ([#188](https://github.com/huskarl-rs/huskarl/pull/188))
- [**breaking**] Normalize DPoP capitalization across types. ([#182](https://github.com/huskarl-rs/huskarl/pull/182))
- [**breaking**] Make authentication_params a builder struct, rename authentication_context ([#181](https://github.com/huskarl-rs/huskarl/pull/181))
- Pay down the usability-review docs debt ([#179](https://github.com/huskarl-rs/huskarl/pull/179))
- Align the preludes on a call-side-traits principle ([#173](https://github.com/huskarl-rs/huskarl/pull/173))
- *(core)* Serialize EndpointUrl without an intermediate allocation ([#170](https://github.com/huskarl-rs/huskarl/pull/170))
- Extract common max-age handling to a shared function ([#161](https://github.com/huskarl-rs/huskarl/pull/161))
- Document that a particular AES-GCM key shoud be used at most 2^32 times ([#158](https://github.com/huskarl-rs/huskarl/pull/158))
- Document crypto strategies, JWT verification config, and revocation TTL ([#131](https://github.com/huskarl-rs/huskarl/pull/131))
- *(core)* [**breaking**] Remove dead UnsealError::AuthenticationFailed variant ([#128](https://github.com/huskarl-rs/huskarl/pull/128))
- Update docs ([#124](https://github.com/huskarl-rs/huskarl/pull/124))
- Limit body size of responses (default 1Mb) ([#123](https://github.com/huskarl-rs/huskarl/pull/123))

## [0.7.1] - 2026-06-29

### Changes

 - Added oauth_form, a serde serializer/deserializer for OAuth 2.1
 - Set a max limit on the number of keys loaded by `JwksSource` (100 by default).
 - Default client credentials auth changes to form rather than basic. Adds a
   builder parameter to allow this to be altered.

## [0.7.0] - 2026-06-15

### Changes

 - Major breaking change: Update traits to be dyn traits.
 - `AeadV1Sealer`/`AeadV1Unsealer` are replaced by a single `AeadV1Cipher<C>`.
 - `ClientAuthentication::authentication_params`: the `token_endpoint`
   parameter is renamed to `endpoint` — it is whatever endpoint is being
   authenticated to (token, PAR, revocation, introspection).
 - Avoid panicking in JWT creation or validation (in time handling).
 - Timestamps in JWTs are represented by SystemTime instead of u64.
 - Burn JTI after all other JWT checks have passed.
 - Adds in-memory JTI uniqueness checker (especially for tests).
 - Add concrete error type (to replace trait).
 - Add `KeyMatch::strength_for` and `CipherMatch::strength_for` helpers so
   single-key verifier/decryptor implementations can delegate the standard
   algorithm/kid matching rules instead of re-implementing them.
 - Add reloading support to ciphers.
 - `HttpClient::execute` takes a new `Idempotency` parameter declaring
   whether the request is known to be safe to re-send.
 - Add `Error::is_dpop_nonce_required` accessor.
 - Breaking: `Audience::PreferIssuer` is now `Audience::Issuer` and fails
   closed (`ErrorKind::Config`, `MissingIssuer` source) when no issuer is
   configured, per draft-ietf-oauth-rfc7523bis (endpoint URLs are disallowed
   as client-assertion audiences). `Audience::PreferTokenEndpoint` is renamed
   to `Audience::TokenEndpoint` and documented as legacy.
 - Client assertion JWTs are explicitly typed `client-authentication+jwt`
   (draft-ietf-oauth-rfc7523bis); opt out with `explicit_typ(false)` on the
   `JwtBearer` builder for servers that reject it.
 - Remove `IntoEndpointUrl`, add TryFrom/From impls for `EndpointUrl`.

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
