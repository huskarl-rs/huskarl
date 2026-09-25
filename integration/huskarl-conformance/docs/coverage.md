# Conformance coverage

[Run instructions](../README.md). All commands use the repository root.

## OIDC

The OIDC tests run Basic, Form Post Basic, and Configuration certification with static registration,
plain authorization requests, and `client_secret_basic`. Configuration covers
provider discovery, JWKS discovery, issuer mismatch, and both signing-key rotation
scenarios. Discovery-only modules stop after the required discovery/key retrieval;
the two-flow rotation module reuses the same grant and cached verifier across both
authorizations and UserInfo calls.

Form Post Basic sets `ResponseMode::FormPost`. The HTTP browser parses the returned
HTML form and submits its hidden fields to the registered loopback callback using
`application/x-www-form-urlencoded`, without executing JavaScript. It preserves
duplicate fields and decodes HTML entities before form encoding, so negative
responses reach the library's normal callback validation.

Basic also runs with `request_type=request_object`: a fresh RS256 key signs the
request, its public JWK is registered with the suite, and optional PAR is disabled
to exercise direct delivery in the authorization URL's `request` parameter.
Client authentication remains `client_secret_basic`.

Basic and Configuration also run with `client_registration=dynamic_client`.
Each module that performs authorization first uses `ClientRegistration` to register
its loopback redirect URI, authorization-code grant, and `client_secret_basic`
authentication. The grant uses the returned client ID and secret. The two-flow
key-rotation scenario reuses that module's registration and grant. Discovery-only
modules do not register; issuer mismatch stops before registration.

This exercises dynamic registration within Basic and Configuration, not the full
Dynamic certification profile, which also needs WebFinger and request-by-URI flows.
Configuration additionally runs with static registration and each of
`client_secret_post`, `client_secret_jwt` (HS256), and `private_key_jwt` (RS256).
Basic and Form Post Basic fix authentication to `client_secret_basic` in the suite;
Configuration permits selecting these additional methods. Its key-rotation modules
exercise authenticated token exchanges and UserInfo, including two consecutive flows.
The secret-JWT run generates a fresh 64-byte ASCII secret instead of using
`CONFORMANCE_CLIENT_SECRET`; the private-key run registers only its public JWK.
JWT assertions use the target endpoint as their audience.

The OIDC `mise` task and CI automatically include all nine runs across three plans.

## FAPI 2 authorization code

Authorization-code runs use `plain_fapi`. The matrix covers `private_key_jwt`
and mTLS authentication with DPoP or certificate-bound tokens.
OIDC variants validate UserInfo through `UserInfoClient`, sharing the grant's
DPoP and verifier state and matching the response subject to the validated ID
token. A rejected UserInfo response stops the scenario before the accounts call.

| Rust test | Client | Suite plan | Request / response |
|---|---|---|---|
| `fapi2_security_profile_plain` | OIDC | Security Profile Final | Unsigned / plain |
| `fapi2_security_profile_plain_oauth` | OAuth | Security Profile Final | Unsigned / plain |
| `fapi2_message_signing_plain` | OIDC | Message Signing Final | Signed / plain |
| `fapi2_message_signing_plain_oauth` | OAuth | Message Signing Final | Signed / plain |
| `fapi2_message_signing_jarm` | OIDC | Message Signing Final | Signed / JARM (`query.jwt`) |
| `fapi2_message_signing_jarm_oauth` | OAuth | Message Signing Final | Signed / JARM (`query.jwt`) |
| `fapi2_security_profile_rar` | OIDC | Security Profile Final | Unsigned PAR with RAR / plain |
| `fapi2_message_signing_jarm_rar` | OIDC | Message Signing Final | Signed PAR with RAR / JARM (`query.jwt`) |
| `fapi2_security_profile_private_key_jwt_mtls` | OIDC | Security Profile Final | Unsigned / plain; JWT authentication, mTLS tokens |
| `fapi2_security_profile_mtls_dpop` | OIDC | Security Profile Final | Unsigned / plain; mTLS authentication, DPoP tokens |
| `fapi2_security_profile_mtls_mtls` | OIDC | Security Profile Final | Unsigned / plain; mTLS authentication and tokens |

Message Signing runs all three mTLS combinations below with both OIDC and
plain-OAuth clients, each with plain responses and JARM (`query.jwt`): twelve
additional variants. These use signed PAR requests with ES256, retaining the same
request signing independently of the client authentication method.

| Test suffix | Client authentication | Token binding |
|---|---|---|
| `private_key_jwt_mtls` | JWT assertion | mTLS |
| `mtls_dpop` | mTLS | DPoP |
| `mtls_mtls` | mTLS | mTLS |

Test names start with `fapi2_message_signing_plain_` or
`fapi2_message_signing_jarm_`, followed by the suffix above; plain-OAuth tests
add `_oauth`. They use simple authorization requests; the existing RAR Message
Signing variant continues to use JWT authentication and DPoP.

The mTLS variants generate a fresh self-signed client certificate and key in
memory for each plan, register the public certificate with the suite, and install
the identity through `MtlsPem`. No certificate files or external certificate
generation commands are required. TLS server verification still follows
`CONFORMANCE_INSECURE_TLS`.

These variants declare `client.use_mtls_endpoint_aliases=true` and use discovery's
aliases for PAR and token requests. mTLS client authentication sends the client ID
with `NoAuth`, relying on the transport certificate for authentication. For
certificate-bound tokens, UserInfo and accounts requests use the same certificate;
the accounts URL comes from the running module's exposed `accounts_endpoint`.
For certificate-bound tokens, its HTTPS origin must match discovery's mTLS token
endpoint alias; a missing alias or mismatched origin fails the scenario. With
mTLS authentication plus DPoP tokens, resource requests use a separate HTTP client
without a certificate and retain the grant's DPoP state. Management API and browser
clients do not receive the identity.

RAR variants select `authorization_request_type=rar` and send an
`account_information` authorization detail with `list_accounts` and `read_balances`
actions. The suite's supported authorization-detail types are derived from the
same request configuration. These runs exercise both JSON-in-form PAR and native
JSON inside signed request objects, followed by UserInfo and accounts requests.

Plain-OAuth variants select `fapi_client_type=plain_oauth`, explicitly disable
OIDC on the grant, request only the `accounts` scope, and call the accounts resource
without calling UserInfo. JARM response validation remains enabled in its OAuth
variant even though ID tokens are not required.

The JARM variant exercises signed authorization responses and the suite's negative
checks for missing/invalid issuer, audience, expiration, and signature. The suite
selects the applicable modules, so its total need not equal the plain-response
module count plus the JARM cases.

## Client credentials

`tests/client_credentials.rs` runs the Security Profile with
`fapi_profile=fapi_client_credentials_grant`, `private_key_jwt`, and DPoP. It
exchanges client credentials for an `accounts` token and calls the accounts resource,
including DPoP nonce recovery, without authorization or UserInfo requests.
The driver uses Huskarl's standard metadata discovery and issuer validation.
For token-only metadata, an omitted `response_types_supported` defaults to an
empty list; see [RFC 8414 erratum 7793](https://errata.rfc-editor.org/eid7793/).

The FAPI `mise` task and CI workflow include all twenty-three authorization-code variants
and the client-credentials run.

