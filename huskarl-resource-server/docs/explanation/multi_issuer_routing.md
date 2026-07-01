# Multi-issuer routing

[`MultiIssuerValidator`](crate::validator::multi_issuer::MultiIssuerValidator)
reads each token's `iss` claim to select a per-issuer validator, then delegates
the full validation to it. It implements
[`AccessTokenValidator`](crate::validator::AccessTokenValidator), so it drops
into a `ValidatorLayer`, Pingora guard, or any other consumer exactly like a
single-issuer validator.

## How routing stays safe

The issuer is read from the token's payload **without verifying the
signature**, and is used *only* to select a validator. The selected validator
independently re-checks `iss`, the signature (against its own JWKS), the
audience, and any sender-constraint binding — so a token that lies about its
issuer is merely routed to a validator that rejects it. Routing grants no
trust; verification is still done in full by the chosen validator.

Each per-issuer validator carries its own audience: pin it exactly, because the
audience check is the access boundary. This matters most when a validator
accepts tokens (such as OIDC ID tokens) that a different relying party could
also obtain.

## Unifying claim types

Per-issuer validators usually have different claims types. Give them a common
type `C` by wrapping each in
[`MapClaims`](crate::validator::multi_issuer::MapClaims), whose mapping is a
plain `Fn(SourceClaims) -> C`. The library attaches no semantics to that
mapping — any authorization model your application layers on top of `C` is its
own concern. For a worked two-issuer example, see the [multi-issuer
guide](crate::_docs::guide::multi_issuer).
