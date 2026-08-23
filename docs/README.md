# Huskarl documentation

Choose a page by what you need now. The documentation follows
[Diátaxis](https://diataxis.fr): tutorials teach through a complete learning
experience, how-to guides solve a specific task, reference describes the API,
and explanation develops the ideas behind the design.

## Tutorial

Start here if you are new to huskarl:

- [Get your first access token](../huskarl/docs/tutorial/first_token.md) — run a
  local authorization server, create a client, and complete one token exchange.

The tutorial deliberately follows one path. Once it works, use the how-to
guides to adapt that path to your application.

## How-to guides

### Build an OAuth client

- [Set up HTTP and client authentication](../huskarl/docs/guide/setup.md)
- Use a grant:
  [authorization code](../huskarl/docs/guide/authorization_code.md),
  [client credentials](../huskarl/docs/guide/client_credentials.md),
  [device authorization](../huskarl/docs/guide/device_authorization.md),
  [refresh token](../huskarl/docs/guide/refresh.md),
  [token exchange](../huskarl/docs/guide/token_exchange.md), or
  [JWT bearer](../huskarl/docs/guide/jwt_bearer.md)
- [Choose client authentication](../huskarl/docs/guide/client_authentication.md)
- [Register a client dynamically](../huskarl/docs/guide/registration.md)
- [Sender-constrain tokens with DPoP](../huskarl/docs/guide/dpop.md)
- [Cache tokens and wire an authorizer](../huskarl/docs/guide/caching.md)
- [Make authenticated requests](../huskarl/docs/guide/authorizer.md)
- [Handle errors](../huskarl/docs/guide/handling_errors.md)
- [Implement token infrastructure](../huskarl/docs/guide/implementing_token_infrastructure.md)

### Protect a resource server

- Validate access tokens as
  [RFC 9068 JWTs](../huskarl-resource-server/docs/guide/rfc9068.md),
  [custom JWTs](../huskarl-resource-server/docs/guide/custom.md), or by
  [introspection](../huskarl-resource-server/docs/guide/introspection.md)
- [Accept tokens from several issuers](../huskarl-resource-server/docs/guide/multi_issuer.md)
- [Validate DPoP-bound tokens](../huskarl-resource-server/docs/guide/dpop.md)

### Work with shared infrastructure

- [Build and sign a JWT](../huskarl-core/docs/guide/signing_a_jwt.md)
- [Validate a JWT](../huskarl-core/docs/guide/validating_a_jwt.md)
- [Configure JWT verification](../huskarl-core/docs/guide/configuring_jwt_verification.md)
- [Provide secrets](../huskarl-core/docs/guide/providing_secrets.md)
- [Implement a transport or cryptographic backend](../huskarl-core/docs/guide/implementing_a_backend.md)
- [Return errors from an extension](../huskarl-core/docs/guide/returning_errors.md)
- [Load a native signing key](../huskarl-crypto-native/docs/guide/loading_a_signing_key.md)
- [Sign a JWT in the browser](../huskarl-crypto-webcrypto/docs/guide/signing_a_jwt.md)

## Reference

Use the API reference when you know the crate or type you need:

| Crate | API reference | Purpose |
| --- | --- | --- |
| `huskarl` | [docs.rs](https://docs.rs/huskarl) | Grants, token caching, authenticated requests, and dynamic registration |
| `huskarl-resource-server` | [docs.rs](https://docs.rs/huskarl-resource-server) | Access-token validation and HTTP rejection metadata |
| `huskarl-core` | [docs.rs](https://docs.rs/huskarl-core) | Shared JWT, JWK, cryptography, secrets, HTTP, and metadata types |
| `huskarl-crypto-native` | [docs.rs](https://docs.rs/huskarl-crypto-native) | RustCrypto-backed signing, verification, and AEAD |
| `huskarl-crypto-webcrypto` | [docs.rs](https://docs.rs/huskarl-crypto-webcrypto) | WebCrypto-backed signing, verification, and AEAD |
| `huskarl-reqwest` | [docs.rs](https://docs.rs/huskarl-reqwest) | `reqwest` HTTP transport and mTLS configuration |
| `huskarl-redis` | [docs.rs](https://docs.rs/huskarl-redis) | Redis-backed replay prevention |
| `huskarl-macros` | [docs.rs](https://docs.rs/huskarl-macros) | Error-classification and metadata-builder macros |

The [supported-specifications list](../README.md#supported-specifications) is
the protocol-level reference for the workspace.

## Explanation

Read these when you want to understand a design choice or reason about a
trade-off.

### OAuth clients

- [The client error model](../huskarl/docs/explanation/error_handling.md)
- [How a grant token source resolves a token](../huskarl/docs/explanation/token_source_resolution.md)
- [Refresh-ahead and jitter](../huskarl/docs/explanation/refresh_timing.md)
- [Sharing a refresh token store](../huskarl/docs/explanation/sharing_a_token_store.md)
- [Why the prelude is trait-only](../huskarl/docs/explanation/prelude.md)

### Resource servers

- [Choosing a validator](../huskarl-resource-server/docs/explanation/choosing_a_validator.md)
- [The resource-server error model](../huskarl-resource-server/docs/explanation/error_handling.md)
- [Multi-issuer routing](../huskarl-resource-server/docs/explanation/multi_issuer_routing.md)

### Cryptography and shared design

- [The core error model](../huskarl-core/docs/explanation/error_handling.md)
- [Handling keys from untrusted sources](../huskarl-core/docs/explanation/untrusted_keys.md)
- [Composing cryptographic strategies](../huskarl-core/docs/explanation/crypto_strategies.md)
- [Why JWK is the native key format](../huskarl-crypto-native/docs/explanation/jwk_as_key_format.md)
- [WebCrypto platform constraints](../huskarl-crypto-webcrypto/docs/explanation/platform_constraints.md)

## Project and interoperability documentation

These pages describe this repository and its test environments rather than the
library API:

- [Provider interoperability matrix](../integration/README.md)
- [OpenID conformance setup](../integration/huskarl-conformance/README.md)
- [Workspace status and support policy](../README.md#status)
