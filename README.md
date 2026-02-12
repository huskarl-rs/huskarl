# Huskarl - Elite Access and Protection for your Services

A húskarl was a well-paid, well-trained household bodyguard in medieval northern Europe.
Similarly, huskarl delivers enterprise-grade OAuth2 access control and token validation
for services near and dear to you.

## So what is it?

Huskarl provides a suite of rust libraries that implement many of the RFCs around
`OAuth2` and `OpenID Connect`. They focus not on creating tokens, but on requesting
and validating access tokens; the two jobs that writers of clients, and deployers of
services need to think about every day.

Also, modern extensions to `OAuth2` should not be considered "nice to have" features.
Security is not a checkbox in order to pass regulation; it is something that responsible
system designers and operators should continually think about. A lot of recent extensions
to `OAuth2` are marketed as "for high security and regulated environments", but if they
are easy to add, why not? So Huskarl tries to make features like sender-bound tokens
accessible with minimal ceremony.

### What is an access token?

A token is a piece of data that is sent from a client, and used to authorize a
request. It is meant to provide enough information that the server can provide
access to the requested service or resource.

So in these terms, huskarl can play both sides of that story; provide authorization,
and validate that authorization.

### What is `OAuth2`?

`OAuth2` is a suite of compatible standards for authorizing (usually HTTP) requests,
with various branching extensions that add security (e.g. DPoP token binding), or
extend the usable scenarios of the suite.

### What is `OpenID Connect`?

To contrast with `OAuth2`, which is about authorizing requests ("this token proves that
I can access this"), `OpenID Connect` is about authentication, in particular, providing the
identity, and information about the identity, that just authenticated (what might be
called "logged on", or "signed on").

### `OAuth2` roles

This library helps with handling two central roles in `OAuth2`:

- The _client_ wants to get tokens which allow access to resources, on behalf of a user.
  The client mediates interactions (the set of interactions can be called a flow or grant)
  that allow the user to authenticate; and finally get an access token.
  In `OpenID Connect`, this may be called a `relying party`.

- The _resource server_ gets an access token, and needs to validate that it follows
  certain criteria to be a valid authorization source.

## Core Design

### Type-safe builders

Huskarl makes extensive use of `bon` builders to smooth the often complex configuration options
in authentication and authorization. Bon models required and optional values on the type level,
so a missing configuration option is a compile error. Also, once a grant is built, all this
builder type machinery is no longer required, and is not present in the types after construction.

### A struct per grant

Every grant is a separate struct (built with bon). This allows it to have full knowledge of what
it requires to operate, and means that unneeded configuration is not even mentioned. Each
struct may also have extra generic parameters, on a case-by-case basis, to help with its
configuration and functionality.

### Crypto platforms

Grants (or other parts of the library) that need to do JWS verification (verifying signatures
on JWTs) generally need a "crypto platform"; this explains how to create cryptographic keys
in a low-level way. Currently, there are two implementations; one for native code, and one
for `WebCrypto`. Where possible, a reasonable default value is passed to the builders.

### JWS factories

A factory allows the creation of JWT verifiers by a high-level strategy, making use of the platform.
For example, this could implement requesting JWKs (JSON Web Keys) for a JWKS URI, appropriately
caching and refreshing the underlying keys.

### Async First

Where useful, functions are async, including secret access and cryptographic operations. This
enables some useful abilities; for example, signing and verification can be done via `WebCrypto`,
or a cloud KMS, or a HSM (hardware security module).

### Traits for extensibility

Most functions of the suite are implemented over traits which are open for creation externally.
For example: crypto, secret providers, grants, authentication methods, JWKS fetchers, refresh
token stores, HTTP clients: are all possible to define yourself if the existing implementations
fail to match your needs.

### Choice of opaque or granular errors

The majority of error types are written using `snafu`, allowing fine-grained chains for handling
errors. These can optionally be wrapped in `BoxedError` when an opaque error type is preferable
to a granular one.

## Core Libraries

- `huskarl-core` implements the functionality needed by higher layers. Here, you can find the
  core traits, JWT/JWK handling, authorization server metadata handling, encoding/decoding
  support. One way to look at it is: if both an `OAuth2` resource server, and an `OAuth2`
  client (or relying party) might need the functionality, it should go here.
- `huskarl` implements functionality required by an `OAuth2` client (OIDC relying party).
- `huskarl-resource-server` implements functionality required by an `OAuth2` resource server.
  This includes access token validation and introspection.

## Support Libraries

- `huskarl-crypto-native` implements core cryptography operations in rust code. The library
  relies heavily on the `rustcrypto` suite of crates.
- `huskarl-crypto-webcrypto` implements core cryptography operations in `WebCrypto`. This
  utilizes `wasm-bindgen` and `web-sys` for binding to the `WebCrypto` operations in the
  current WASM environment.
- `huskarl-reqwest` implements support for the `reqwest` HTTP client (allowing it to be
  used for operations by the huskarl crates).

## Platform Support

Huskarl supports most `std` platforms, including WASM.

# Supported RFCs

### Core Framework

- RFC 6749 - OAuth 2.0 Authorization Framework
- RFC 6750 - Bearer Token Usage

### Token Management

- RFC 7009 - Token Revocation
- RFC 7662 - Token Introspection
- RFC 9701 - JWT Response for Token Introspection

### JWT / Cryptography

- RFC 7515 - JSON Web Signature (JWS)
- RFC 7517 - JSON Web Key (JWK)
- RFC 7518 - JSON Web Algorithms (JWA)
- RFC 7519 - JSON Web Token (JWT)
- RFC 7521 - Assertion Framework for OAuth 2.0
- RFC 7523 - JWT Profile for Client Authentication
- RFC 7800 - Proof-of-Possession Key Semantics for JWTs

### Security Extensions

- RFC 7636 - PKCE
- RFC 8705 - mTLS Client Auth & Certificate-Bound Tokens
- RFC 8707 - Resource Indicators
- RFC 9126 - Pushed Authorization Requests (PAR)
- RFC 9449 - DPoP

### Authorization Flows

- RFC 8252 - OAuth 2.0 for Native Apps
- RFC 8628 - Device Authorization Grant
- RFC 8693 - Token Exchange

### Discovery & Metadata

- RFC 8414 - Authorization Server Metadata
- RFC 9207 - Authorization Server Issuer Identification
- RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens

### OpenID Connect

- OpenID Connect Core 1.0

### JAR

- RFC 9101 - JWT-Secured Authorization Request (JAR)
