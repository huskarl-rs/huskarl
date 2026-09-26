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
no trust. Configure each selected validator to verify the token's authenticity,
issuer, audience, and sender constraints. In particular, a `CustomValidator`
needs an explicit issuer and audience policy; routing does not add those checks.
Opaque tokens cannot use this routing mechanism.

Require the audience of your API and the issuer's access-token profile. Audience
validation alone does not distinguish an access token from an OIDC ID token;
configure token-type and claim checks to prevent that substitution.

## Unifying claim types

Per-issuer validators usually have different claims types. Give them a common
type `C` by wrapping each in
[`MapClaims`](crate::validator::multi_issuer::MapClaims), whose mapping is a
plain `Fn(SourceClaims) -> C`. The library attaches no semantics to that
mapping — any authorization model your application layers on top of `C` is its
own concern. For a worked two-issuer example, see the [multi-issuer
guide](crate::_docs::guide::multi_issuer).
