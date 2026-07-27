# Handling errors

This guide is for applications consuming tokens. If you are implementing a
token source, refresh-token store, or grant, see
[implementing token infrastructure](crate::_docs::guide::implementing_token_infrastructure).

Choose the error type from the operation you are calling:

| Operation | Error type | What to inspect |
| --- | --- | --- |
| [`TokenSource::token`](crate::cache::TokenSource::token), a token cache, or [`HttpAuthorizer::get_headers`](crate::authorizer::HttpAuthorizer::get_headers) | [`TokenError`](crate::cache::TokenError) | [`Recovery`](crate::cache::Recovery) |
| A grant called directly, registration, metadata, or another individual operation | [`Error`](crate::core::Error) | [`RetryAdvice`](crate::core::RetryAdvice) and [`verdict`](crate::core::Error::verdict) |
| Device polling, callback parsing, and other documented protocol control flow | The operation's dedicated error enum | Its variants |

## Map token failures onto your own error type

Acquiring a token through a token source, cache, or authorizer returns
[`TokenError`](crate::cache::TokenError). Add variants for the recovery actions
your application supports, then match
[`TokenError::recovery`](crate::cache::TokenError::recovery):

```rust
use huskarl::cache::{Recovery, TokenError};
use huskarl::core::platform::Duration;

enum AppError {
    RetryLater(Option<Duration>, TokenError),
    AdjustRequest(TokenError),
    LoginRequired,
    Auth(TokenError),
}

impl From<TokenError> for AppError {
    fn from(err: TokenError) -> Self {
        match err.recovery() {
            Recovery::Retry { after } => AppError::RetryLater(after, err),
            Recovery::AdjustRequest => AppError::AdjustRequest(err),
            Recovery::Reauthenticate => AppError::LoginRequired,
            _ => AppError::Auth(err), // `Recovery` is non-exhaustive.
        }
    }
}
```

Use `?` on `HttpAuthorizer::get_headers` or `TokenSource::token`; the `From`
implementation routes each failure to your application policy. For
`Recovery::Retry`, wait for `after` when present before calling the token source
again. The delay governs the next acquisition attempt as a whole, not only the
underlying operation that failed. For `AdjustRequest`, change the requested
scope, resource, or other rejected parameter before trying again.

## Read what the server said

Inspect [`TokenError::verdict`](crate::cache::TokenError::verdict) only when your
application must branch on a specific OAuth error code. For example, confirm
that the authorization server rejected a credential with `invalid_grant`:

```rust
# use huskarl::cache::TokenError;
# use huskarl::core::OAuthErrorCode;
# fn handle(err: &TokenError) {
if err.verdict().is_some_and(|v| *v.code() == OAuthErrorCode::InvalidGrant) {
    // Do not submit this credential again.
}
# }
```

Treat `None` as no server verdict. Codes found in `429` and `5xx` responses are
not exposed as verdicts, because gateways can echo OAuth-shaped bodies during
an outage.

## Map other operations

Grants, registration and metadata fetches return
[`Error`](crate::core::Error), which carries the retry advice and the verdict
but no token-source recovery action. Map it separately in your application
error type and use [`Error::retry_advice`](crate::core::Error::retry_advice)
when deciding whether to repeat that operation.

## Log the whole chain

Format errors with `{err:#}` to include their source chains:

```rust
# use huskarl::core::{Error, RetryAdvice};
# let err = Error::new(RetryAdvice::No, "the token endpoint refused the request");
eprintln!("token acquisition failed: {err:#}");
```

To recover an error type supplied by your `HttpClient`, signer, or store, call
[`TokenError::as_error`](crate::cache::TokenError::as_error), then
[`Error::cause`](crate::core::Error::cause), and downcast:

```rust
# use huskarl::core::{Error, RetryAdvice};
# #[derive(Debug)] struct KeychainLocked;
# impl std::fmt::Display for KeychainLocked {
#     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("locked") }
# }
# impl std::error::Error for KeychainLocked {}
# let token_error = huskarl::cache::TokenError::from(
#     Error::new(RetryAdvice::No, KeychainLocked)
# );
if token_error
    .as_error()
    .cause()
    .downcast_ref::<KeychainLocked>()
    .is_some()
{
    // prompt for the keychain password
}
```

## Observe failures on a dashboard

Enable the `metrics` feature and configure deployment-specific labels on the
token-source builder. Monitor `huskarl.token.acquire`; its `outcome` label uses
the bounded [`TokenOutcome`](crate::TokenOutcome) values. OAuth codes and other
attacker-controlled values are not emitted as labels.
