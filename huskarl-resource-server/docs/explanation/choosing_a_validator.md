# Choosing a validator

A resource server has two jobs: validate the access token presented with a
request, and decide whether that token authorizes the request. This crate does
the first. Which [`AccessTokenValidator`](crate::validator::AccessTokenValidator)
you reach for depends on how your authorization server's tokens are verified.

## [`Rfc9068Validator`](crate::validator::rfc9068::Rfc9068Validator)

Use this when your authorization server issues
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT access tokens — the `typ`
header is `at+jwt` and the token carries `iss`, `exp`, `aud`, `sub`, `iat`,
`jti`, and `client_id`. The token is self-contained, so validation is a local
signature and claim check using cached keys from the authorization server's
JWKS. Key refresh can make network requests during validation. OAuth servers
are not required to issue RFC 9068 tokens; check the issuer's token format. See the [RFC 9068
guide](crate::_docs::guide::rfc9068).

## [`CustomValidator`](crate::validator::custom::CustomValidator)

Use this when the tokens are JWTs but do not conform to RFC 9068 — for example,
they omit `client_id`, use a different `typ`, or follow an authorization
server's own conventions. You declare which claims are required and how each is
checked via
[`AccessTokenValidationRules`](crate::validator::custom::AccessTokenValidationRules).
Like the RFC 9068 validator, verification is local against the JWKS. See the
[custom validator guide](crate::_docs::guide::custom).

## [`IntrospectionValidator`](crate::validator::introspection::IntrospectionValidator)

Use this when tokens are opaque (not JWTs), or when you need authoritative
revocation status on every request. Validation calls the authorization server's
[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) introspection endpoint rather
than verifying a signature locally. It adds a network round trip and uses the
server's current view of token activity; revocation propagation depends on the
server. See the [introspection
guide](crate::_docs::guide::introspection).

## [`MultiIssuerValidator`](crate::validator::multi_issuer::MultiIssuerValidator)

Use this to accept JWT-shaped tokens from more than one issuer with a single
validator. It reads the unverified `iss` claim to select a configured validator.
Opaque tokens cannot be routed this way because they expose no issuer claim.
See the [multi-issuer routing
explanation](crate::_docs::explanation::multi_issuer_routing).
