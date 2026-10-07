# Multi-issuer routing

[`MultiIssuerValidator`](crate::validator::multi_issuer::MultiIssuerValidator)
reads each token's `iss` claim to select a per-issuer validator, then delegates
the full validation to it. It implements
[`AccessTokenValidator`](crate::validator::AccessTokenValidator), so it drops
into a `ValidatorLayer`, Pingora guard, or any other consumer exactly like a
single-issuer validator.

## How routing stays safe

The issuer is read from the token's payload **without verifying the
signature**, and is used only to select a registered validator. Routing grants
no trust and does not add claim checks to the selected validator. Opaque tokens
cannot use this routing mechanism.

When configuring the router, configure each selected validator to verify the
token's authenticity, issuer, audience, and sender constraints. In particular,
set an explicit issuer and audience policy for each `CustomValidator`.

Require the audience of your API and the issuer's access-token profile. Audience
validation alone does not distinguish an access token from an OIDC ID token;
configure token-type and claim checks to prevent that substitution.

## Unifying claim types

Per-issuer validators usually have different claims types. The library attaches
no authorization semantics to their claims; the application defines a common
type and maps each validator's claims into it with
[`MapClaims`](crate::validator::multi_issuer::MapClaims), or
[`TryMapClaims`](crate::validator::multi_issuer::TryMapClaims) when mapping can
reject the request. For a worked two-issuer example, see the [multi-issuer
guide](crate::_docs::guide::multi_issuer).

## Subjects and other token fields

The claims type excludes the fields the library validates itself (`iss`, `sub`,
`aud`, `cnf`); to use those, map the whole request with
[`MapRequest`](crate::validator::multi_issuer::MapRequest) or
[`TryMapRequest`](crate::validator::multi_issuer::TryMapRequest). A `sub` is
only unique within its issuer ([RFC 7519
§4.1.2](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2)), so identify
principals by (`iss`, `sub`) or namespace the subject per issuer.

Mapped fields are not revalidated: downstream code sees a rewritten `aud` or
`cnf` as-is, and a namespaced `sub` replaces the issuer's original unless the
mapper keeps it. Leave `iss` unchanged:
[`ObservedValidator`](crate::validator::observe::ObservedValidator) labels
metrics with it, so a rewritten value changes those labels and a per-request one
can explode their cardinality.
