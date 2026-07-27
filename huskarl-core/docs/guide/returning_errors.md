# Returning errors from an extension

Use this guide when implementing a transport, secret provider, cryptographic
backend, store, or another layer that returns huskarl errors. The choice depends
on whether the failure is new at your layer or already classified below it.

| Situation | Return |
| --- | --- |
| A foreign library or your own backend failed here | `Error::new(advice, cause)` |
| You are adding context around an existing `Error` | Preserve its `Classification` |
| An error enum contains both leaf and wrapper variants | Derive `Classify` |
| The trait returns `VerifyError` or `DecryptError` | Use its control-flow variant or wrap `Error` in `Other` |
| You are implementing `TokenSource` | Return `TokenError` at that higher-level boundary |

## Return a new backend failure

Use [`Error::new`](crate::error::Error::new) when the cause has not already been
classified by huskarl:

```rust
# use huskarl_core::{Error, RetryAdvice};
# #[derive(Debug)] struct VaultTimeout;
# impl std::fmt::Display for VaultTimeout {
#     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
#         f.write_str("the vault request timed out")
#     }
# }
# impl std::error::Error for VaultTimeout {}
let error = Error::new(RetryAdvice::RETRY, VaultTimeout);
# let _ = error;
```

Choose the advice for the operation represented by the trait method:

- `RetryAdvice::RETRY` when repeating that operation may succeed later.
- `RetryAdvice::retry_after(delay)` when the backend gives a minimum delay.
- `RetryAdvice::No` when repeating the same operation is not expected to help.

The advice is not an application retry policy. Callers still apply attempt
limits, deadlines, jitter, and knowledge of alternative operations.

## Add context without reclassifying

When a lower layer has already returned `Error`, do not pass a wrapper around it
to `Error::new`. That would replace its retry delay, OAuth verdict, and any future
classification member. Take the complete classification before moving the
error, then propagate it:

```rust
use huskarl_core::Error;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(display("loading the signing key"))]
struct LoadingKey {
    source: Error,
}

fn loading_key(source: Error) -> Error {
    let classification = source.classification();
    Error::propagate(classification, LoadingKey { source })
}
```

This is the manual form. For an error enum with several variants, prefer the
derive below so propagation is checked per variant.

## Classify a typed error enum

Add `snafu` and `huskarl-macros` as dependencies, derive `Snafu` and `Classify`,
and classify only leaf variants:

```rust,ignore
use huskarl_core::Error;
use huskarl_macros::Classify;
use snafu::Snafu;

#[derive(Debug, Snafu, Classify)]
enum ProviderError {
    #[snafu(display("the provider rejected its configuration"))]
    #[classify(no)]
    BadConfiguration,

    #[snafu(display("fetching the key from the provider"))]
    FetchingKey { source: Error },
}

fn into_huskarl(error: ProviderError) -> Error {
    error.into()
}
```

The `Error` field makes `FetchingKey` propagate automatically. The derive
rejects a conflicting `#[classify(...)]` on that variant, and adding a new leaf
without a classification is a compile error.

Use `#[classify(retry)]` for an unconditionally transient leaf. Use
`#[classify(with = path)]` when the decision depends on a value, such as an I/O
error kind, HTTP response, or an `Error` nested inside another public error
type. The derive passes references to the selected variant's fields, in
declaration order; the handler returns [`Origin`](crate::error::propagation::Origin),
choosing either `Establishes` or `Propagates` explicitly.

The optional `strict-propagation` feature catches less direct mistakes—such as
an `Error` hidden behind an alias or nested cause—during tests. Enable it in CI
for an extension crate that defines its own classified wrapper enums.

## Respect specialized trait errors

Some crypto traits keep a small error enum because wrapper implementations
branch on its variants:

- [`JwsVerifier`](crate::crypto::verifier::JwsVerifier) returns
  [`VerifyError`](crate::crypto::verifier::VerifyError). Return
  `NoMatchingKey`, `KeysUnavailable`, `AmbiguousKeyMatch`,
  `MalformedSignature`, or `SignatureMismatch` only for the condition each
  variant names. Wrap an already classified backend failure in
  `VerifyError::Other { source }`.
- [`AeadDecryptor`](crate::crypto::cipher::AeadDecryptor) returns
  [`DecryptError`](crate::crypto::cipher::DecryptError). Return `NoMatchingKey`
  only when no key matched and decryption was not attempted; wrap other backend
  failures in `DecryptError::Other { source }`.
- Signing and encryption methods return `Error` directly, so use the leaf or
  propagation rules above.

Do not flatten these control-flow variants into generic backend errors. Key
selection, refreshing, and multi-key dispatch rely on their distinction.

## Stop at the token-source boundary

`Error` describes one failed operation. A token source also knows whether it
has another credential or acquisition path, so
[`huskarl::cache::TokenSource`](https://docs.rs/huskarl/latest/huskarl/cache/trait.TokenSource.html)
returns `TokenError` with a `Recovery` decision. Do not introduce `Recovery` in
a transport, provider, crypto backend, store, or grant.

See [implementing token infrastructure](https://docs.rs/huskarl/latest/huskarl/_docs/guide/implementing_token_infrastructure/)
for that boundary.
