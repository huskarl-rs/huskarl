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
signature and claim check against the authorization server's published JWKS,
with no per-request network call. This is the default choice for a standards-
compliant authorization server. See the [RFC 9068
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
than verifying a signature locally, which costs a network round trip per request
but reflects revocation immediately. See the [introspection
guide](crate::_docs::guide::introspection).

## [`MultiIssuerValidator`](crate::validator::multi_issuer::MultiIssuerValidator)

Use this to accept tokens from more than one issuer with a single validator. It
routes each request to one of the validators above by the token's `iss` claim.
See the [multi-issuer routing
explanation](crate::_docs::explanation::multi_issuer_routing).
