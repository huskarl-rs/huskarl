# Error handling

Every operation in this crate returns the one concrete
[`Error`](crate::core::Error) type, which embeds in your own error enum
(hand-rolled as below, or with `thiserror`'s `#[from]`). Because the workflow
types carry no type parameters, this stays true no matter which grant or cache
you wire up.

Errors carry three stable signals, checked in this order:

- [`is_retryable`](crate::core::Error::is_retryable) means the failure is
  transient and the same call may succeed later — back off and retry, do **not**
  re-run the interactive flow.
- [`ReauthRequired`](crate::core::ErrorKind::ReauthRequired) means no token can
  be obtained automatically and the interactive flow must run again.
- Everything else is a genuine failure to log and surface.

Mapping the library error into an application error enum, distinguishing those
three cases:

```rust
use huskarl::core::ErrorKind;

enum AppError {
    /// Transient failure — retry the request later.
    RetryLater(huskarl::core::Error),
    /// The user must log in again.
    LoginRequired,
    /// Any other authorization failure.
    Auth(huskarl::core::Error),
}

impl From<huskarl::core::Error> for AppError {
    fn from(err: huskarl::core::Error) -> Self {
        if err.is_retryable() {
            AppError::RetryLater(err)
        } else if err.kind() == ErrorKind::ReauthRequired {
            AppError::LoginRequired
        } else {
            AppError::Auth(err)
        }
    }
}
```

With this `From` in place, `?` on any authorizer, cache, or grant call lands in
your error enum with re-login distinguished from a transient failure. See
[caching tokens and wiring an authorizer](crate::_docs::guide::caching) for the
surrounding setup.
