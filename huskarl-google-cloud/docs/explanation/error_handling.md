# Error handling

The crate has two families of errors: setup errors returned while building a
key, and runtime errors returned by `huskarl` trait methods.

## Setup errors

Building a key or fetching versions returns a crate-specific error:

- KMS: [`asymmetric::signer::SetupError`](crate::kms::asymmetric::signer::SetupError),
  [`asymmetric::jwks::JwksError`](crate::kms::asymmetric::jwks::JwksError),
  [`symmetric::SetupError`](crate::kms::symmetric::SetupError) and
  [`symmetric::KeyError`](crate::kms::symmetric::KeyError) (shared by the symmetric
  builders), and the underlying
  [`VersionResolutionError`](crate::kms::version::VersionResolutionError).
- Secret Manager:
  [`SecretVersionsError`](crate::secretmanager::SecretVersionsError).

These non-exhaustive error types describe the specific failure, such as the API
call that failed, an unsupported algorithm, or the absence of enabled versions.
Each exposes [`retry_advice()`](crate::kms::symmetric::KeyError::retry_advice)
and [`is_retryable()`](crate::kms::symmetric::KeyError::is_retryable). Prefer
`retry_advice()`: unlike the coarse Boolean result from `is_retryable()`, it
preserves any minimum delay supplied by the service. See [how failures are
classified](#how-failures-are-classified).

A refresh factory must return a
[`huskarl_core::Error`](huskarl_core::Error). KMS setup errors implement the
required conversion and preserve their full retry advice, so the factory can
forward the conversion directly:

```rust,no_run
use huskarl_core::Error;
use huskarl_google_cloud::kms::symmetric::cipher::CipherKey;

# async fn example(
#     builder_result: Result<CipherKey, huskarl_google_cloud::kms::symmetric::KeyError>,
# ) -> Result<CipherKey, Error> {
builder_result.map_err(Error::from)
# }
```

For an error without this conversion—`JwksError`, `VersionResolutionError`, or
`SecretVersionsError`—construct the `huskarl_core::Error` explicitly. Read the
advice before moving the source error:

```rust,no_run
use huskarl_core::Error;
use huskarl_google_cloud::kms::version::VersionResolutionError;

# fn convert(source: VersionResolutionError) -> Error {
let advice = source.retry_advice();
Error::new(advice, source)
# }
```

The [self-refreshing keys guide](crate::_docs::guide::refreshing_keys) shows
this conversion in context.

## Runtime errors

Once built, a key is used through a `huskarl` trait method such as `sign`,
`verify`, `encrypt`, `decrypt`, or `get_secret_value`. These methods return
[`huskarl_core::Error`](huskarl_core::Error) directly. The operation-specific
errors convert to `huskarl_core::Error` with one of three forms of
[`RetryAdvice`](huskarl_core::RetryAdvice):

- [`RetryAdvice::retry_after(d)`](huskarl_core::RetryAdvice::retry_after) when
  the service told us how long to wait.
- [`RetryAdvice::RETRY`](huskarl_core::RetryAdvice::RETRY) for a transient KMS
  or Secret Manager failure with no specified delay. The caller chooses a delay
  according to its backoff policy.
- [`RetryAdvice::No`](huskarl_core::RetryAdvice::No) for conclusive failures,
  such as a malformed signature response, mismatched key information, or a
  missing secret payload. Repeating the operation is not expected to help.

The types involved are
[`asymmetric::signer::SigningError`](crate::kms::asymmetric::signer::SigningError),
[`symmetric::cipher::EncryptionError`](crate::kms::symmetric::cipher::EncryptionError)
/ [`DecryptionError`](crate::kms::symmetric::cipher::DecryptionError),
[`symmetric::signer::SigningError`](crate::kms::symmetric::signer::SigningError)
/ [`VerificationError`](crate::kms::symmetric::signer::VerificationError), and
[`SecretError`](crate::secretmanager::SecretError). Callers usually receive a
`huskarl_core::Error` instead of naming these types directly. Read its
[`retry_advice()`](huskarl_core::Error::retry_advice), or downcast its
[`cause()`](huskarl_core::Error::cause) when the specific failure matters.

The advice classifies the failed operation only. Your own retry budget,
deadline, and backoff policy still apply on top of it.

## How failures are classified

Google Cloud failures are classified consistently during both setup and
runtime. The classification answers one narrow question:

> Could repeating the same request succeed without external intervention?

An operator raising a quota, re-enabling a key, or rebuilding a stale signer
does not make the failed request itself retryable. The layer capable of that
intervention should decide whether to perform it.

Applied to a failed RPC that means:

1. **A `RetryInfo` detail takes precedence.** A Google API may attach a minimum
   retry delay to a failed request ([AIP-193]). The delay becomes
   `RetryAdvice::retry_after(d)`, even when the status code would otherwise be
   classified as permanent.
2. **Otherwise, the failure category determines the advice.** `UNAVAILABLE`,
   `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED`, HTTP 503, I/O failures, and
   failures raised before the RPC begins are retryable. So are the timeout and
   attempt-limit errors reported when gax's internal retry loop stops: reaching
   either condition means gax had already classified the underlying failures as
   transient.
3. **All other failures advise `No`.** Permission errors, malformed requests,
   and missing resources require more than another attempt.

Step 2 is broader than the gax `Aip194Strict` implementation of [AIP-194],
which retries only `UNAVAILABLE`. It excludes `RESOURCE_EXHAUSTED` to avoid
adding load to an overloaded service; callers address that concern with a retry
budget and backoff policy. It excludes `DEADLINE_EXCEEDED` because a server may
have acted on a request whose response was lost, making a repeated
non-idempotent request unsafe.

Every request made by this crate is safe to repeat, including reading a secret
version, listing versions, fetching key metadata, and performing KMS signing,
verification, encryption, or decryption.

[AIP-193]: https://google.aip.dev/193
[AIP-194]: https://google.aip.dev/194

## `MismatchedKeyInfo` rejects an inconsistent response

A signing or encryption response must name the same canonical key version as
the request. A different name produces `MismatchedKeyInfo` with
[`RetryAdvice::No`](huskarl_core::RetryAdvice::No), and the returned signature,
MAC, or ciphertext is discarded. This protects the binding between the output
and the configured key version.

Cloud KMS key versions are immutable, so normal rotation does not change the
version named by an existing key instance. A mismatch instead indicates an
inconsistent response and is not expected to become trustworthy when the same
operation is repeated.
