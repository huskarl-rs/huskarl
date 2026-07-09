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
future. Write each body as `Box::pin(async move { ... })`, and map every failure
onto the one concrete [`Error`](crate::error::Error) using the
[`ErrorKind`](crate::error::ErrorKind) that tells callers what to do next (see
[the error model](crate::_docs::explanation::error_handling)).

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
            // Translate `request` into your client's call, await it, and read
            // the full body. On failure, return `ErrorKind::Transport` — see
            // the note on `idempotency` below.
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

Classify request and body-read failures as
[`ErrorKind::Transport`](crate::error::ErrorKind::Transport), and set
`retryable` carefully. A failure is retryable only when re-sending is safe:
either the request provably never reached the server, or the caller declared it
[`Idempotency::Idempotent`](crate::http::Idempotency::Idempotent) and the failure
was transient. With [`Idempotency::Unknown`](crate::http::Idempotency::Unknown)
the server may already have processed a first attempt (consuming a one-shot
authorization code or rotated refresh token), so only never-delivered failures
are retryable.

## The cryptographic seams

The [`crypto`](crate::crypto) traits follow the same pattern; classify signing,
verification, and decryption failures as
[`ErrorKind::Crypto`](crate::error::ErrorKind::Crypto), and a remote keystore's
transient failure (KMS, HSM) as
[`ErrorKind::Transport`](crate::error::ErrorKind::Transport):

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
