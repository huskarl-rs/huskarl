# Implementing token infrastructure

This guide covers the error boundary for custom token sources and refresh-token
stores. For transports, secrets, and cryptographic backends, see
[returning errors from an extension](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/returning_errors/).

## Implement a token source

A [`TokenSource`](crate::cache::TokenSource) returns [`TokenError`](crate::cache::TokenError),
not a bare [`Error`](crate::core::Error). Lower-level transports, signers, KMS
clients, and grants return `Error`; the token source is the boundary that can
also say what the caller should do about the acquisition as a whole.

When the failure alone determines recovery, convert it directly:

```rust
use huskarl::{TokenError, core::Error};

fn from_backend(error: Error) -> TokenError {
    error.into()
}
```

This derives recovery from the error's retry advice and OAuth verdict and
preserves a retry interval supplied by the backend.

If the source knows about alternatives, establish recovery explicitly while
retaining the lower-level error unchanged:

```rust
use huskarl::{Recovery, TokenError, core::Error};

fn failed_assertion_with_another_available(error: Error) -> TokenError {
    TokenError::new(Recovery::Retry { after: None }, error)
}
```

Use this only for knowledge owned by the source: whether it can mint another
assertion, retain a refresh token, change parameters, or has exhausted every
automatic path. Do not rewrite the underlying `Error`'s retry advice or verdict;
those continue to describe the operation that actually failed.

When composing another `TokenSource`, call
[`TokenError::into_error`](crate::cache::TokenError::into_error) before attaching
your own recovery decision. This keeps the original cause, verdict, retry delay,
and construction location.

## Implement a refresh-token store

A [`RefreshTokenStore`](crate::cache::RefreshTokenStore) returns `Error` because
each method is one storage operation; it does not know whether the surrounding
token source has another acquisition path.

Create a leaf error with the retry advice known by the storage backend:

```rust
# use huskarl::core::{Error, RetryAdvice};
# #[derive(Debug)] struct StoreUnavailable;
# impl std::fmt::Display for StoreUnavailable {
#     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
#         f.write_str("the token store is unavailable")
#     }
# }
# impl std::error::Error for StoreUnavailable {}
let error = Error::new(RetryAdvice::RETRY, StoreUnavailable);
# let _ = error;
```

Use `RetryAdvice::No` for a permanent configuration, permission, encoding, or
data-integrity failure. Use `RetryAdvice::retry_after` when the store supplies a
minimum cooldown. `GrantTokenSource` will combine this operation-level fact
with the other acquisition paths it owns.

## Implement a grant

[`OAuth2ExchangeGrant`](crate::grant::core::OAuth2ExchangeGrant) uses the common
token-endpoint exchange machinery. Its accessors and `build_form` describe the
request; failures from client authentication, DPoP, transport, and response
handling already return classified `Error` values.

If custom grant preparation introduces another fallible operation, treat it as
an ordinary extension boundary: establish classification for a new foreign
failure and propagate an existing `Error`. Do not choose `Recovery` in the
grant—the same grant can be called directly or owned by token sources with
different alternatives.
