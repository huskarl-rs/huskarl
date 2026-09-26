# Configuring JWT verification

Use [`JwksSource`](crate::jwk::JwksSource) to verify tokens against an
authorization server's published keys. Supply a custom factory when keys come
from another source. For issuer, audience, and other claim checks, see
[validating a JWT](crate::_docs::guide::validating_a_jwt).

For a comparison of fixed keys, file-loaded keys, and remote verification, see
[how verification fits together](crate::_docs::explanation::verification).

## Prerequisites

The examples assume an HTTP client and a builder that accepts
`jws_verifier_factory`. The `default-jws-verifier-platform` feature selects the
native or WebCrypto backend in the consuming crate. If you disable that
feature, supply `jws_verifier_platform` explicitly.

## The default: a JWKS-backed stack

[`JwksSource`](crate::jwk::JwksSource) is the batteries-included factory. It
builds a [`RetryingVerifier`](crate::crypto::verifier::RetryingVerifier) around a
[`ScheduledRefreshVerifier`](crate::crypto::verifier::ScheduledRefreshVerifier)
around a [`MultiKeyVerifier`](crate::crypto::verifier::MultiKeyVerifier): keys are
fetched when the factory builds the verifier, the whole keyset is reloaded on the read
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
        // Attempt refresh on use after five minutes (default: one hour).
        // Failed refreshes retain the previous keys.
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

Choose `ttl` to control how soon requests trigger a scheduled refresh. It is
not a maximum key age: rate limits, failed fetches, and concurrent refreshes
can leave older keys in use. See [refresh policy](crate::_docs::explanation::crypto_strategies)
for the availability and key-retirement trade-off.

## Selecting a different stack

Supply your own [`JwsVerifierFactory`](crate::crypto::verifier::JwsVerifierFactory)
instead. Return any `Arc<dyn JwsVerifier>` — compose the wrappers you need and
erase the result; the validator above only ever sees the base trait. Implement it
on a type, or (via the blanket impl) pass a closure with the same signature.

This factory ignores the JWKS URI and presents keys supplied by the application.
It does not reload them; use a refreshable wrapper if the key set can change:

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
        JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform, MultiKeyVerifier,
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
            let verifier = MultiKeyVerifier::new(keys);
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
