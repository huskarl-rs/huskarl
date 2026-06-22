# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changes

 - Breaking: Update HttpAuthorizer to accept a GrantTokenSource which is capable
   of regenerating grant parameters (e.g. useful for JWT bearer grant). Also this
   unifies with the idea of priming the token source.
 - Allow token cache to refresh before the token actually expires, while all but
   one request use the existing still valid token.
 - Save RAR `authorization_details` as an extra field in token response.

## [0.8.0] - 2026-06-15

### Changes

 - Major Breaking change: ported to the dyn-first huskarl-core.
 - Make client auth optional for JWT bearer and token exchange grants.
 - Add `JwtBearer` grant.
 - Breaking: `HttpAuthorizer` reworked with recommendations around retries and
   challenge handling.
 - `RawTokenResponse` (with its builder), `into_token_response`, and
   `InvalidTokenResponse` are now exported from `grant::core`, so tests and
   integrations can fabricate a `TokenResponse` — e.g. to `prime` a token
   cache without running a real exchange. Production cold-start should still
   persist only the refresh token via a `RefreshTokenStore`.
 - `RefreshTokenStore` gained `&`/`Box`/`Arc` forwarding impls, so a shared
   `Arc<MyStore>` handle can be passed to a cache builder directly.
 - Breaking: `UserInfoClient` and `UserInfo` lost the `Extra` type parameter.
 - Breaking: `IdTokenClaims` and `AuthorizationCodeGrant` likewise lost their
   claim type parameters.
 - Breaking: grants hold the HTTP client as a required `http_client`.
 - Breaking: reworked error handling completely.
 - Breaking: mTLS endpoint aliases (RFC 8705 §5) are resolved at grant build
   time against the grant's HTTP client. `OAuth2ExchangeGrant` loses
   `mtls_token_endpoint`/`effective_token_endpoint`; `token_endpoint()` returns
   the already-resolved endpoint. Also fixes `to_refresh_grant()` dropping the
   mTLS alias, and client assertions now consistently use the effective
   endpoint as their audience.
 - The `dpop` builder field on all grants (and on `UserInfoClient`) defaults to
   `NoDPoP`, and `jar` on the authorization code grant defaults to `NoJar`;
   they no longer need to be set explicitly. `client_auth` stays required —
   building a public client remains an explicit decision.
 - Don't throw away refresh token in inmemory store unless invalid_grant was returned.
 - Avoid panicking in access token expiry time calculation.
 - Send PKCE by default, unless AS explicitly says it doesn't support it.
 - Only allow some grants to exchange parameters more than once (token cache).

## [0.7.2] - 2026-06-04

### Changes

 - Fix refresh form serialization, add tests.

## [0.7.1] - 2026-05-29

### Changes

 - Make UserInfoClaims serializable.

## [0.7.0] - 2026-05-26

### Improvements

 - Adds a userinfo client.

### Changes

 - Update client auth on DPoP-based retry (private key jwt must have different jti if present).
 - Adds allowed_id_token_signed_response_algs to filter allowed algorithms for ID token signature algorithm.
 - Checks that azp has the client_id if the aud value of an ID token has multiple values.
 - Support form_post response mode in loopback server.
 - Skip serializing None fields in various requests.
 - Bump huskarl-core to 0.6.
 - Set JAR typ and nbf claims.

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
