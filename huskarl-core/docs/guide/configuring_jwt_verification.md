# Configuring JWT verification

[`JwtValidator`](crate::jwt::validator::JwtValidator) verifies a token against a
[`JwsVerifier`](crate::crypto::verifier::JwsVerifier). This guide is about where
that verifier comes from: how to wire the opinionated default stack for the
common case — an authorization server's JWKS endpoint — and how to swap it for
something else. For the claim policy the validator applies *after* the signature
checks out, see [validating a JWT](crate::_docs::guide::validating_a_jwt); for
*why* the stack is layered the way it is, see [composing crypto
strategies](crate::_docs::explanation::crypto_strategies).

## What verification needs: a platform and a factory

Signing is the easy direction: you hand the builder a concrete
[`JwsSigner`](crate::crypto::signer::JwsSigner) that already carries its key and
its crypto, and that is all. Verification is heavier because the verifier must be
*built* from key material discovered at runtime — an AS's JWKS — which takes two
collaborators, configured differently:

- A **platform** — a [`JwsVerifierPlatform`](crate::crypto::verifier::JwsVerifierPlatform),
  the crypto backend that turns a JWK into a per-key verifier. Its *availability*
  is a feature-flag decision: with the `default-jws-verifier-platform` feature (on
  by default) the builder's `jws_verifier_platform` defaults to the platform
  backend — `huskarl-crypto-native` off-wasm, `huskarl-crypto-webcrypto` on wasm —
  so you never name it. Disable the feature and the field becomes required: pass
  your own with `.jws_verifier_platform(...)`, or verification is unavailable.
- A **factory** — a [`JwsVerifierFactory`](crate::crypto::verifier::JwsVerifierFactory),
  passed as `.jws_verifier_factory(...)`. This is the *selection* you make: it is
  handed the discovered `jwks_uri` and the platform, and returns the composed
  `Arc<dyn JwsVerifier>`. There is no default factory — you always supply one, and
  choosing a stack means choosing it.

So the split is: the platform is *available* (feature-gated, usually implicit),
the factory is *selected* (always explicit). The rest of this guide is about that
selection.

## The default: a JWKS-backed stack

[`JwksSource`](crate::jwk::JwksSource) is the batteries-included factory. It
builds a [`RetryingVerifier`](crate::crypto::verifier::RetryingVerifier) around a
[`ScheduledRefreshVerifier`](crate::crypto::verifier::ScheduledRefreshVerifier)
around a [`MultiKeyVerifier`](crate::crypto::verifier::MultiKeyVerifier): keys are
fetched from the endpoint on first use, the whole keyset is reloaded on the read
path once older than the `ttl`, and an unknown-`kid` miss triggers one reload and
retry.

```rust,no_run
use std::sync::Arc;

use huskarl_core::{jwk::JwksSource, platform::Duration};
# use huskarl_core::http::HttpClient;

# fn example(http_client: impl HttpClient + 'static) {
// `http_client` is your HTTP backend — for example `huskarl_reqwest::ReqwestClient`.
let verifier_factory = Arc::new(
    JwksSource::builder()
        .http_client(http_client)
        // The TTL (default 1h) bounds how long a key removed from the JWKS keeps
        // verifying its own tokens: it stays trusted until the keyset is reloaded,
        // so lower this to shorten that window. `max_keys` bounds an untrusted
        // document's size.
        .ttl(Duration::from_secs(5 * 60))
        .build(),
);
# let _ = verifier_factory;
# }
```

Hand `verifier_factory` to a client or resource-server builder with
`.jws_verifier_factory(verifier_factory)` — the builder calls the factory for
you, passing it the discovered `jwks_uri` and the platform. The platform is
implicit here (the `default-jws-verifier-platform` feature is on), so only the
factory is named; each crate's setup guide shows the call in context.

The `ttl` is the one knob you should set deliberately — it is a trust decision,
not a performance one.

## Selecting a different stack

Supply your own [`JwsVerifierFactory`](crate::crypto::verifier::JwsVerifierFactory)
instead. Return any `Arc<dyn JwsVerifier>` — compose the wrappers you need and
erase the result; the validator above only ever sees the base trait. Implement it
on a type, or (via the blanket impl) pass a closure with the same signature.

This factory ignores the JWKS URI and instead presents fixed keys (from a KMS, an
enclave, or a local file), still wrapped in `RetryingVerifier` so an unknown-`kid`
miss can drive a reload:

```rust
# #[derive(Debug)]
# struct BackendVerifier;
# impl huskarl_core::crypto::verifier::JwsVerifier for BackendVerifier {
#     fn key_match(&self, _m: &huskarl_core::crypto::verifier::KeyMatch<'_>)
#         -> Option<huskarl_core::crypto::KeyMatchStrength> {
#         Some(huskarl_core::crypto::KeyMatchStrength::ByAlgorithm)
#     }
#     fn verify<'a>(
#         &'a self,
#         _input: &'a [u8],
#         _signature: &'a [u8],
#         _m: &'a huskarl_core::crypto::verifier::KeyMatch<'a>,
#     ) -> huskarl_core::platform::MaybeSendBoxFuture<'a, Result<(), huskarl_core::crypto::verifier::VerifyError>> {
#         Box::pin(async move { Ok(()) })
#     }
# }
use std::sync::Arc;

use huskarl_core::{
    EndpointUrl,
    crypto::verifier::{
        JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform, MultiKeyVerifier, RetryingVerifier,
    },
    error::Error,
    platform::MaybeSendBoxFuture,
};

#[derive(Debug)]
struct StaticKeyStack {
    keys: Vec<Arc<dyn JwsVerifier>>,
}

impl JwsVerifierFactory for StaticKeyStack {
    fn build(
        &self,
        _jwks_uri: Option<&EndpointUrl>,
        _platform: Arc<dyn JwsVerifierPlatform>,
    ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, Error>> {
        let keys = self.keys.clone();
        Box::pin(async move {
            let verifier = RetryingVerifier::new(MultiKeyVerifier::new(keys));
            Ok(Arc::new(verifier) as Arc<dyn JwsVerifier>)
        })
    }
}

# fn example() {
let factory = StaticKeyStack {
    keys: vec![Arc::new(BackendVerifier) as Arc<dyn JwsVerifier>],
};
# let _: &dyn JwsVerifierFactory = &factory;
# }
```

### Mixing a JWKS with non-JWKS keys

To trust both an AS's rotating JWKS *and* a fixed KMS or enclave key, compose the
lower-level wrappers yourself and apply `RetryingVerifier` **once** at the top
(see [composing crypto strategies](crate::_docs::explanation::crypto_strategies)
for why the retry belongs at the outermost layer):

```rust,ignore
// A refreshing JWKS keyset, combined with a fixed KMS key, under one MultiKeyVerifier.
let jwks_keys = ScheduledRefreshVerifier::builder()
    .ttl(Duration::from_secs(300))
    .factory(move || {
        // fetch the JWKS, then MultiKeyVerifier::from_jwks(&jwks, platform)
    })
    .build()
    .await?;

let combined = MultiKeyVerifier::new(vec![
    Arc::new(jwks_keys) as Arc<dyn JwsVerifier>,
    kms_verifier, // an Arc<dyn JwsVerifier>, e.g. from huskarl-google-cloud
]);

let verifier: Arc<dyn JwsVerifier> = Arc::new(RetryingVerifier::new(combined));
```

## If you already hold a verifier

When you have an `Arc<dyn JwsVerifier>` in hand rather than a factory — a single
static key, say — skip the factory entirely and pass it straight to the validator
with [`verifier`](crate::jwt::validator::JwtValidator::builder), as shown in
[validating a JWT](crate::_docs::guide::validating_a_jwt). The factory seam exists
for the case where the verifier must be *built* from a discovered `jwks_uri` and a
platform the consumer supplies.
