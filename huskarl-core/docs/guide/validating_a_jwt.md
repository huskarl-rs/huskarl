# Validating a JWT

[`JwtValidator`](crate::jwt::validator::JwtValidator) verifies a compact JWS and
checks the registered claims in one call: it confirms the signature with a
[`JwsVerifier`](crate::crypto::verifier::JwsVerifier), enforces the temporal
claims (`exp`/`nbf`/`iat`), and applies whatever per-claim policy you configure
for `iss`/`sub`/`aud`/`typ`. On success it returns a
[`ValidatedJwt`](crate::jwt::validator::ValidatedJwt) carrying the claims,
deserialized into a type of your choosing.

This guide covers the claim policy; for where the
[`JwsVerifier`](crate::crypto::verifier::JwsVerifier) itself comes from — wiring
the default JWKS-backed stack or swapping it — see [configuring JWT
verification](crate::_docs::guide::configuring_jwt_verification).

Build a validator with the [builder](crate::jwt::validator::JwtValidator::builder),
then call [`validate`](crate::jwt::validator::JwtValidator::validate):

```rust
# use std::sync::Arc;
# use huskarl_core::crypto::{
#     KeyMatchStrength,
#     verifier::{JwsVerifier, KeyMatch, VerifyError},
# };
# use huskarl_core::platform::MaybeSendBoxFuture;
# // Stand-in for the verifier your crypto backend (or a JWKS source) provides.
# #[derive(Debug)]
# struct BackendVerifier;
# impl JwsVerifier for BackendVerifier {
#     fn key_match(&self, _m: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
#         Some(KeyMatchStrength::ByAlgorithm)
#     }
#     fn verify<'a>(
#         &'a self,
#         _input: &'a [u8],
#         _signature: &'a [u8],
#         _key_match: &'a KeyMatch<'a>,
#     ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
#         Box::pin(async move { Ok(()) })
#     }
# }
use huskarl_core::jwt::validator::{ClaimCheck, JwtValidator};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
struct Claims {
    scope: String,
}

# async fn example(verifier: BackendVerifier, token: &str) -> Result<(), Box<dyn std::error::Error>> {
let validator = JwtValidator::builder()
    .verifier(verifier)
    .iss(ClaimCheck::required_value("https://issuer.example"))
    .aud(ClaimCheck::require_any(["https://api.example"]))
    .require_exp(true)
    .allowed_algorithms(["ES256".to_string(), "RS256".to_string()])
    .build();

let validated = validator.validate::<Claims>(token).await?;
println!("scope: {}", validated.claims.scope);
# Ok(())
# }
```

## Claim policy

Each of `iss`, `sub`, `aud`, and `typ` takes a [`ClaimCheck`](crate::jwt::validator::ClaimCheck):

- [`required_value`](crate::jwt::validator::ClaimCheck::required_value) — the
  claim must be present and equal this value.
- [`require_any`](crate::jwt::validator::ClaimCheck::require_any) — present and
  one of these values (the usual choice for `aud`).
- [`if_present`](crate::jwt::validator::ClaimCheck::if_present) — checked only
  when the claim is present.
- [`present`](crate::jwt::validator::ClaimCheck::present) — must be present, any
  value. The default is no check.

## Safe defaults

`exp` is **not** required by default — a validly-signed token with no expiry is
accepted. Call `require_exp(true)` unless non-expiring tokens are intentional.
Restrict accepted algorithms with `allowed_algorithms` to pin an allowlist;
regardless, the `none` algorithm is always rejected. To reject replayed tokens,
supply a [`JtiUniquenessChecker`](crate::jwt::JtiUniquenessChecker) via
`jti_checker`, and set `clock_leeway` to tolerate small clock skew.
