# Implementing a backend

`huskarl-core` is deliberately free of any transport or cryptographic
implementation. Instead it defines traits at each seam, and a backend crate (or
your own code) plugs in the concrete behaviour. The crates in this ecosystem do
exactly this — `huskarl-reqwest` implements [`HttpClient`](crate::http::HttpClient),
the native and WebCrypto crates implement the [`crypto`](crate::crypto) traits.
This guide covers the shape common to all of them.

## The common shape

Every extension trait is **dyn-capable**: the library stores implementations
behind `Arc<dyn Trait>` (or `&dyn Trait`), so async methods return a boxed
future. Write each body as `Box::pin(async move { ... })`. Most seams return the
concrete [`Error`](crate::error::Error); verification and decryption retain small
specialized enums because composing layers branch on their variants. See
[returning errors from an extension](crate::_docs::guide::returning_errors) for
the leaf, propagation, typed-enum, and specialized-error recipes.

## Implementing `HttpClient`

[`HttpClient`](crate::http::HttpClient) is the transport seam. Run the request,
read the **entire** body (responses are small JSON/JWKS/metadata documents —
there is no streaming), and return an [`HttpResponse`](crate::http::HttpResponse):

```rust
use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};
use huskarl_core::{
    error::Error,
    http::{HttpClient, HttpResponse, Idempotency},
    platform::MaybeSendBoxFuture,
};

#[derive(Debug)]
struct MyClient {
    // ... your underlying HTTP client ...
}

impl HttpClient for MyClient {
    fn execute(
        &self,
        request: Request<Bytes>,
        idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async move {
            // Translate `request`, await the call, and read a bounded body.
            // Classify failures using `idempotency` as described below.
            let _ = (request, idempotency);
            Ok(HttpResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"{}"),
            })
        })
    }
}
```

Classify request and body-read failures with
[`RetryAdvice::retry_if`](crate::error::RetryAdvice::retry_if), and decide its
argument carefully. A failure is retryable only when re-sending is safe:
either the request provably never reached the server, or the caller declared it
[`Idempotency::Idempotent`](crate::http::Idempotency::Idempotent) and the failure
was transient. With [`Idempotency::Unknown`](crate::http::Idempotency::Unknown)
the server may already have processed a first attempt (consuming a one-shot
authorization code or rotated refresh token), so only never-delivered failures
are retryable.

Enforce a response-body size limit while streaming from the transport, before
constructing `HttpResponse`. Return `Error::new(RetryAdvice::No, cause)` for an
oversized response. Do not read an unbounded body and truncate it afterward,
because the limit protects memory rather than only diagnostics.

## Implementing cryptographic traits

The [`crypto`](crate::crypto) traits use `Error` for signing and encryption. A
local failure normally carries [`RetryAdvice::No`](crate::error::RetryAdvice::No),
while a transient remote-keystore failure carries
[`RetryAdvice::Retry`](crate::error::RetryAdvice::Retry). Verification and
decryption instead return specialized errors for key-selection and validation
control flow; their `Other` variants preserve an underlying `Error`:

- [`JwsSigner`](crate::crypto::signer::JwsSigner) /
  [`JwsSignerSelector`](crate::crypto::signer::JwsSignerSelector) — produce JWS
  signatures.
- [`JwsVerifier`](crate::crypto::verifier::JwsVerifier) — verify them, reporting
  match quality through [`key_match`](crate::crypto::verifier::JwsVerifier::key_match).
- [`AeadEncryptorSelector`](crate::crypto::cipher::AeadEncryptorSelector) /
  [`AeadEncryptor`](crate::crypto::cipher::AeadEncryptor) /
  [`AeadDecryptor`](crate::crypto::cipher::AeadDecryptor) — content encryption;
  the key type is the selector, handing out its shared inner encryptor.

You usually implement only the single-key trait; the [composable
wrappers](crate::_docs::explanation::crypto_strategies) (multi-key, refreshable,
retrying) are provided and stack on top of your implementation.

## Other seams

- [`Secret`](crate::secrets::Secret) — supply credentials from a custom source;
  see [providing secrets](crate::_docs::guide::providing_secrets).
- [`JtiUniquenessChecker`](crate::jwt::JtiUniquenessChecker) — back the
  replay-detection check the [JWT validator](crate::_docs::guide::validating_a_jwt)
  uses (e.g. against a shared cache).

(`DPoP` proofs, by contrast, are not a backend seam — the
[`dpop`](crate::dpop) traits are sealed and driven by the configured
implementations rather than implemented by external crates.)
