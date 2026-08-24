# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-v0.10.1...huskarl-v0.11.0) - 2026-08-24

### Added

- *(device)* apply retry advice while polling ([#294](https://github.com/huskarl-rs/huskarl/pull/294))
- *(cache)* [**breaking**] expose token recovery decisions ([#293](https://github.com/huskarl-rs/huskarl/pull/293))
- *(core)* introduce retry advice and OAuth verdicts ([#283](https://github.com/huskarl-rs/huskarl/pull/283))
- [**breaking**] Make builder_from_metadata/etc. return Result instead of Option ([#282](https://github.com/huskarl-rs/huskarl/pull/282))
- *(userinfo)* [**breaking**] from_grant becomes a builder accepting verifier, can require signing ([#281](https://github.com/huskarl-rs/huskarl/pull/281))
- *(client)* [**breaking**] Default jws_verifier_factory to a JwksSource ([#269](https://github.com/huskarl-rs/huskarl/pull/269))
- *(client)* Make auth code redirect_uri public. ([#267](https://github.com/huskarl-rs/huskarl/pull/267))
- *(client)* [**breaking**] Carry error_uri alongside the OAuth error code ([#261](https://github.com/huskarl-rs/huskarl/pull/261))
- *(client)* [**breaking**] Return CompleteOutput from auth completion. ([#260](https://github.com/huskarl-rs/huskarl/pull/260))
- *(client)* [**breaking**] Support signed JARM authorization responses ([#259](https://github.com/huskarl-rs/huskarl/pull/259))
- *(core)* [**breaking**] Carry error_description alongside the OAuth error code ([#257](https://github.com/huskarl-rs/huskarl/pull/257))

### Fixed

- *(cache)* Use monotonic Instant instead of SystemTime ([#279](https://github.com/huskarl-rs/huskarl/pull/279))
- *(client)* Redact secret fields from Debug of CompleteInput. ([#277](https://github.com/huskarl-rs/huskarl/pull/277))
- *(client)* Be more careful about choosing IPv4 vs IPv6 loopback. ([#276](https://github.com/huskarl-rs/huskarl/pull/276))
- Improve the panic story of the crate. ([#275](https://github.com/huskarl-rs/huskarl/pull/275))
- *(client)* Don't fail device auth flow on 5xx ([#274](https://github.com/huskarl-rs/huskarl/pull/274))
- *(client)* Forward normal and mtls token endpoints to refresh grant. ([#273](https://github.com/huskarl-rs/huskarl/pull/273))
- *(cache)* Improve circuit breaker handling. ([#272](https://github.com/huskarl-rs/huskarl/pull/272))
- *(auth)* Set more headers as sensitive if they have sensitive information. ([#270](https://github.com/huskarl-rs/huskarl/pull/270))

### Other

- [**breaking**] Update dependencies and update crate descriptions. ([#304](https://github.com/huskarl-rs/huskarl/pull/304))
- Improve some documentation ([#302](https://github.com/huskarl-rs/huskarl/pull/302))
- Improve docs discovery ([#300](https://github.com/huskarl-rs/huskarl/pull/300))
- explain classified errors and recovery ([#297](https://github.com/huskarl-rs/huskarl/pull/297))
- [**breaking**] remove error migration compatibility ([#296](https://github.com/huskarl-rs/huskarl/pull/296))
- *(huskarl)* [**breaking**] classify registration and userinfo failures ([#292](https://github.com/huskarl-rs/huskarl/pull/292))
- *(huskarl)* [**breaking**] classify authorization flow failures ([#291](https://github.com/huskarl-rs/huskarl/pull/291))
- *(huskarl)* [**breaking**] classify token endpoint failures ([#290](https://github.com/huskarl-rs/huskarl/pull/290))
- *(core)* [**breaking**] migrate internal errors to classifications ([#288](https://github.com/huskarl-rs/huskarl/pull/288))
- *(client)* [**breaking**] Implement authorization code callback handling implementation. ([#258](https://github.com/huskarl-rs/huskarl/pull/258))
- *(client)* Fix doc building on docs.rs ([#255](https://github.com/huskarl-rs/huskarl/pull/255))

## [0.10.1](https://github.com/huskarl-rs/huskarl/compare/huskarl-v0.10.0...huskarl-v0.10.1) - 2026-07-20

### Added

- Get local Cargo dev-deps by path reference. ([#251](https://github.com/huskarl-rs/huskarl/pull/251))

## [0.10.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-v0.9.2...huskarl-v0.10.0) - 2026-07-19

### Added

- *(dpop)* [**breaking**] Support per-session DPoP keys via grant-level binding. ([#248](https://github.com/huskarl-rs/huskarl/pull/248))
- *(client)* [**breaking**] Require ID token when openid scope requested. ([#244](https://github.com/huskarl-rs/huskarl/pull/244))
- *(client)* Add function to make client decision on DPoP nonce. ([#236](https://github.com/huskarl-rs/huskarl/pull/236))
- *(client)* Extract callback query parsing into `CompleteInput`. ([#233](https://github.com/huskarl-rs/huskarl/pull/233))
- *(crypto)* [**breaking**] Separate selectors from signers for JWS signers ([#229](https://github.com/huskarl-rs/huskarl/pull/229))

### Other

- *(client)* Collapse dpop_nonce_action into a dpop_resend_advised predicate. ([#237](https://github.com/huskarl-rs/huskarl/pull/237))
- *(jwt)* [**breaking**] Unify claim naming on serialized name, builders and struct fields. ([#230](https://github.com/huskarl-rs/huskarl/pull/230))

## [0.9.2](https://github.com/huskarl-rs/huskarl/compare/huskarl-v0.9.1...huskarl-v0.9.2) - 2026-07-16

### Fixed

- *(client)* Set authentication headers (Authorization/DPoP) as sensitive. ([#221](https://github.com/huskarl-rs/huskarl/pull/221))
- *(client)* Make sure the same DPoP key thumbprint is used in PAR body. ([#220](https://github.com/huskarl-rs/huskarl/pull/220))

## [0.9.1](https://github.com/huskarl-rs/huskarl/compare/huskarl-v0.9.0...huskarl-v0.9.1) - 2026-07-08

### Other

- Give resource-server both version and path dep in root Cargo.toml - doc fix

## [0.9.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-v0.8.0...huskarl-v0.9.0) - 2026-07-08

### Added

- *(client)* [**breaking**] Rename `scopes` builder to `scope` and make `Vec<String>` for consistency. ([#207](https://github.com/huskarl-rs/huskarl/pull/207))
- *(client)* Auth-code StartOutput carries an absolute PAR expiry ([#177](https://github.com/huskarl-rs/huskarl/pull/177))
- *(cache)* Require an explicit grant-parameters choice on GrantTokenSource ([#176](https://github.com/huskarl-rs/huskarl/pull/176))
- *(core)* Give EndpointUrl Display and Uri conversions ([#168](https://github.com/huskarl-rs/huskarl/pull/168))
- *(resource-server)* Helper to turn resource server validation failures into a response ([#162](https://github.com/huskarl-rs/huskarl/pull/162))
- *(client)* When require PAR is set, don't downgrade ([#159](https://github.com/huskarl-rs/huskarl/pull/159))
- *(client)* Support expires_in as fractions, be more lenient for device authorization. ([#156](https://github.com/huskarl-rs/huskarl/pull/156))
- *(client)* Accept RFC 8693 token_type N_A in token-exchange responses ([#144](https://github.com/huskarl-rs/huskarl/pull/144))
- [**breaking**] Make key selection async and split refresh into miss/TTL paths ([#130](https://github.com/huskarl-rs/huskarl/pull/130))

### Fixed

- *(client)* Keep the refresh token when a 5xx response carries an OAuth error code ([#198](https://github.com/huskarl-rs/huskarl/pull/198))
- *(client)* [**breaking**] Remove `sub` from ID token claims (already in base token claims) ([#192](https://github.com/huskarl-rs/huskarl/pull/192))
- *(client)* Don't validate azp, but check audience is client id or another trusted audience ([#191](https://github.com/huskarl-rs/huskarl/pull/191))
- *(oidc)* Guard ID-token auth_time overflow and default clock leeway ([#189](https://github.com/huskarl-rs/huskarl/pull/189))
- *(client)* Don't abort the loopback login on a single connection's read error ([#146](https://github.com/huskarl-rs/huskarl/pull/146))
- Classify registration 5xx responses as retryable transport errors ([#145](https://github.com/huskarl-rs/huskarl/pull/145))
- *(client)* [**breaking**] Only validate the ID-token nonce when a nonce was sent ([#143](https://github.com/huskarl-rs/huskarl/pull/143))
- *(client)* [**breaking**] Require audience on IdTokenValidator ([#142](https://github.com/huskarl-rs/huskarl/pull/142))
- *(client)* Don't reject future auth_time in the max_age check ([#141](https://github.com/huskarl-rs/huskarl/pull/141))
- *(client)* Serialize authorization-request max_age as seconds ([#133](https://github.com/huskarl-rs/huskarl/pull/133))

### Other

- Update documentation ([#206](https://github.com/huskarl-rs/huskarl/pull/206))
- *(client)* Make the PKCE verifier tests exercise real output ([#204](https://github.com/huskarl-rs/huskarl/pull/204))
- Update documentation ([#195](https://github.com/huskarl-rs/huskarl/pull/195))
- Update documentation ([#193](https://github.com/huskarl-rs/huskarl/pull/193))
- *(crypto)* [**breaking**] Add Pkcs8Pem and remove the legacy key loaders ([#185](https://github.com/huskarl-rs/huskarl/pull/185))
- [**breaking**] Disambiguate crypto-native key-load error enums ([#183](https://github.com/huskarl-rs/huskarl/pull/183))
- [**breaking**] Normalize DPoP capitalization across types. ([#182](https://github.com/huskarl-rs/huskarl/pull/182))
- [**breaking**] Make authentication_params a builder struct, rename authentication_context ([#181](https://github.com/huskarl-rs/huskarl/pull/181))
- Pay down the usability-review docs debt ([#179](https://github.com/huskarl-rs/huskarl/pull/179))
- Align the preludes on a call-side-traits principle ([#173](https://github.com/huskarl-rs/huskarl/pull/173))
- Use ? instead of unwrap in doc examples ([#171](https://github.com/huskarl-rs/huskarl/pull/171))
- Add DPoP and client authentication how-to guides ([#165](https://github.com/huskarl-rs/huskarl/pull/165))
- Extract common max-age handling to a shared function ([#161](https://github.com/huskarl-rs/huskarl/pull/161))
- *(client)* Redact device_code from Debug output of device auth grant pending state. ([#154](https://github.com/huskarl-rs/huskarl/pull/154))
- *(client)* Fix clippy errors ([#152](https://github.com/huskarl-rs/huskarl/pull/152))
- Update README
- *(client)* Fix clippy ([#150](https://github.com/huskarl-rs/huskarl/pull/150))
- Document crypto strategies, JWT verification config, and revocation TTL ([#131](https://github.com/huskarl-rs/huskarl/pull/131))
- Reduce version numbers to init release-plz without publishing.
- Update docs ([#124](https://github.com/huskarl-rs/huskarl/pull/124))
- Update integration tests to support keycloak/dex/node-oidc-provider/Okta. ([#119](https://github.com/huskarl-rs/huskarl/pull/119))
- Prefer form over basic client credentials auth (aligning with OAuth 2.1). ([#117](https://github.com/huskarl-rs/huskarl/pull/117))
- Add DCR fields from OIDC DCR. ([#116](https://github.com/huskarl-rs/huskarl/pull/116))
- Add Dynamic Client Registration (RFC 7591) ([#115](https://github.com/huskarl-rs/huskarl/pull/115))
- Tighten documentation across grants, cache, and authorizer ([#113](https://github.com/huskarl-rs/huskarl/pull/113))
- Add cache state reporting, refresh jitter, and shared-store-safe refresh. ([#112](https://github.com/huskarl-rs/huskarl/pull/112))
- Implement PartialEq/Eq for RefreshToken ([#111](https://github.com/huskarl-rs/huskarl/pull/111))
- Include client_id in the PAR request body (RFC 9126) ([#110](https://github.com/huskarl-rs/huskarl/pull/110))
- Some API visibility updates ([#109](https://github.com/huskarl-rs/huskarl/pull/109))
- Add non_exhaustive to more enums ([#107](https://github.com/huskarl-rs/huskarl/pull/107))
- Add TokenResponse::get_extra for non-standard token fields ([#106](https://github.com/huskarl-rs/huskarl/pull/106))
- Gate the OIDC nonce parameter on the openid scope ([#105](https://github.com/huskarl-rs/huskarl/pull/105))
- Read allowed ID token signing algorithms from AS metadata. ([#104](https://github.com/huskarl-rs/huskarl/pull/104))
- Read granted authorization_details from the token response ([#102](https://github.com/huskarl-rs/huskarl/pull/102))
- Add RFC 9396 Rich Authorization Requests on the request side ([#101](https://github.com/huskarl-rs/huskarl/pull/101))
- Replace serde_html_form with oauth_form across the client ([#99](https://github.com/huskarl-rs/huskarl/pull/99))
- Remove raw data from some debug implementations. ([#96](https://github.com/huskarl-rs/huskarl/pull/96))
- Harden www-authenticate parsing. ([#95](https://github.com/huskarl-rs/huskarl/pull/95))
- Add ability to refresh token cache ahead of expiry. ([#94](https://github.com/huskarl-rs/huskarl/pull/94))
- Split up some large files ([#93](https://github.com/huskarl-rs/huskarl/pull/93))
- Docs update ([#92](https://github.com/huskarl-rs/huskarl/pull/92))
- New HttpAuthorizer approach - adds GrantTokenSource. ([#91](https://github.com/huskarl-rs/huskarl/pull/91))
- Simplify some code

### Changes

 - Breaking: Update HttpAuthorizer to accept a GrantTokenSource which is capable
   of regenerating grant parameters (e.g. useful for JWT bearer grant). Also this
   unifies with the idea of priming the token source.
 - Allow token cache to refresh before the token actually expires, while all but
   one request use the existing still valid token.
 - Save RAR `authorization_details` as an extra field in token response.
 - Read allowed ID tokens algorithms from AS metadata.
 - Only send `nonce` value in authorization request for openid scope (overrideable).
 - Always include `client_id` parameter in PAR requests.
 - Add Dynamic Client Registration client (RFC 7591).

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
