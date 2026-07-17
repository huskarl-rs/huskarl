# Validating DPoP-bound tokens

DPoP (RFC 9449) binds an access token to a key held by the client; a request
must prove possession of that key with a signed `DPoP` header. The built-in
validators do the server side of this **by default** — this page covers what
that means and the knobs on top of it.

## What happens with no configuration

Every built-in validator accepts both token presentations:

- `Authorization: Bearer …` with an unbound token — validated as usual.
- `Authorization: DPoP …` with a DPoP-bound token (a `cnf.jkt` claim) — the
  accompanying `DPoP` proof header is required and fully checked: proof
  signature against the embedded key, key thumbprint against the token's
  `cnf.jkt`, `htm`/`htu` against the request's method and URI, `ath` against
  the access token, and proof freshness (`iat` within
  [`max_dpop_proof_age`](crate::validator::rfc9068::Rfc9068Validator::builder),
  default one minute).

A bound token presented without a valid proof is rejected — that is the
point of the binding.

One integration requirement carries over from [validating a
request](crate::_docs::guide::rfc9068): the `uri` passed to
`validate_request` must be the **absolute external URI** the client
addressed — scheme, authority, and path — because it is compared against the
proof's `htu` claim (RFC 9449 §4.3). Framework request objects usually carry
only the origin-form path (`/resource`), and once TLS-terminating or rewriting
proxies sit in front only the deployment knows the external URI: reconstruct it
from a configured public base URL, or from forwarded headers you trust. A
non-absolute URI surfaces as a server-side integration error rather than
per-request mismatches.

## Requiring DPoP

To reject plain Bearer tokens outright — every token must be sender-bound —
set `require_dpop(true)`. To constrain which proof algorithms you accept,
set `allowed_dpop_signing_algorithms`:

```rust
# use std::sync::Arc;
# use huskarl_resource_server::{core::jwk::JwksSource, validator::rfc9068::Rfc9068Validator};
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;
let validator = Rfc9068Validator::builder()
    .issuer("https://my-issuer")
    .audience("api://my-resource")
    .jwks_uri("https://my-issuer/.well-known/jwks.json".parse()?)
    .require_dpop(true)
    .allowed_dpop_signing_algorithms(vec!["ES256".to_string()])
    .jws_verifier_factory(Arc::new(
        JwksSource::builder().http_client(http_client.clone()).build(),
    ))
    .build()
    .await?;
# let _ = validator;
# Ok(())
# }
```

Both choices are advertised automatically: they surface in the validator's
[metadata](crate::validator::metadata::ProvideValidatorMetadata) as
`dpop_bound_access_tokens_required` and
`dpop_signing_alg_values_supported` (RFC 9728), and shape the `DPoP`
challenge in `WWW-Authenticate` responses.

## Enforcing proof freshness with nonces

Proof `iat` freshness limits replay to a window of the *client's* clock. A
server-issued nonce (RFC 9449 §8) closes that: proofs must echo a value your
server chose recently. Enable it with a
[`DpopNonceChecker`](crate::validator::dpop_nonce::DPoPNonceChecker); the
batteries-included
[`SealedTimestampNonce`](crate::validator::dpop_nonce::SealedTimestampNonce)
needs no storage — nonces are AEAD-sealed timestamps, so any replica holding
the key can validate them:

```rust
# use std::sync::Arc;
# use huskarl_resource_server::core::crypto::cipher::AeadV1Cipher;
# use huskarl_resource_server::core::jwk::{JwksSource, OctBytes};
# use huskarl_resource_server::core::prelude::*;
# use huskarl_resource_server::core::secrets::{EnvVarSecret, encodings::Base64Encoding};
# use huskarl_resource_server::validator::{dpop_nonce::SealedTimestampNonce, rfc9068::Rfc9068Validator};
# use huskarl_crypto_native::aead::AesGcmKey;
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;
// A stable AEAD key, shared by every replica (32 base64 bytes).
let nonce_key = AesGcmKey::from_secret(
    EnvVarSecret::new("DPOP_NONCE_KEY", &Base64Encoding)?.mapped(OctBytes::new("A256GCM")),
)
.await?;

let validator = Rfc9068Validator::builder()
    .issuer("https://my-issuer")
    .audience("api://my-resource")
    .jwks_uri("https://my-issuer/.well-known/jwks.json".parse()?)
    .dpop_nonce_checker(
        SealedTimestampNonce::builder()
            .sealer(AeadV1Cipher::new(nonce_key))
            .build(),
    )
    .jws_verifier_factory(Arc::new(
        JwksSource::builder().http_client(http_client.clone()).build(),
    ))
    .build()
    .await?;
# let _ = validator;
# Ok(())
# }
```

With a checker configured, validation results carry nonces the client must
receive: a missing or stale nonce rejects the request with
`use_dpop_nonce`, and a still-valid nonce nearing expiry is rotated **on a
successful validation**. Either way the nonce arrives on
[`ValidationResult::dpop_nonce`](crate::validator::ValidationResult) and
must be echoed in the response's `DPoP-Nonce` header — on rejections
[`rejection`](crate::validator::ValidationResult::rejection) carries it
automatically; on success responses it is yours to send (see [rejecting a
request](crate::_docs::guide::rfc9068#4-reject-a-request)). Compliant
clients (including huskarl's) retry once with the new nonce.

## Proof replay protection

Nonces bound proof age; they do not make proofs single-use. For strict
one-use proofs, configure `dpop_jti_checker` with a
[`JtiUniquenessChecker`](crate::core::jwt::JtiUniquenessChecker)
backed by shared state (e.g. Redis `SET NX`). This is opt-in because it is
the one DPoP check that needs cross-replica state — see the trait docs for
the trade-offs.
