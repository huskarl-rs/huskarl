# The error model

Every fallible operation in the huskarl ecosystem returns the one concrete
[`Error`](crate::error::Error) type. It follows the [`std::io::Error`] model: a
single non-generic struct carrying a matchable [`ErrorKind`](crate::error::ErrorKind),
optional context, and a type-erased source. Because it is not generic, it embeds
cleanly in your own error enum, and a value crossing several layers keeps one
shape the whole way up.

Programmatic handling — retry decisions, "re-run the interactive flow", surfacing
the RFC 6749 error code — goes through [`ErrorKind`](crate::error::ErrorKind) and
the accessors on [`Error`](crate::error::Error). They are the stable contract;
the variants are kept deliberately coarse so that additions are non-breaking.

## What to do next

Applications consuming tokens (through a token cache or authorizer) need a small
set of signals, checked in this order:

1. **Retry** — [`Error::is_retryable`](crate::error::Error::is_retryable). The
   failure is transient and the same call may succeed if re-attempted (with
   backoff). No user involvement is needed; in particular this is *not* a reason
   to re-run the interactive flow.
2. **Back off, then retry** — [`ErrorKind::Backoff`](crate::error::ErrorKind::Backoff).
   No token right now, but the source expects to recover on its own, so a later
   automatic call may succeed. Like retry, no user involvement is needed; unlike
   retry, an *immediate* re-attempt will not help — wait for the cooldown first.
   This is *not* a reason to re-run the interactive flow.
3. **Adjust the request** — [`ErrorKind::RequestRejected`](crate::error::ErrorKind::RequestRejected).
   The credential is intact but the request was wrong (e.g. an over-broad scope
   or a bad resource indicator). Narrow the request and retry with the *same*
   credential; re-authentication will not help.
4. **Re-authenticate** — [`ErrorKind::ReauthRequired`](crate::error::ErrorKind::ReauthRequired).
   No token can be obtained automatically; the interactive flow must run again.
5. **Fail** — everything else is a genuine failure: log it and surface it. The
   remaining kinds classify *what* failed (configuration, protocol, crypto, …)
   for diagnostics and error reports, not what to do next.

The three signals that matter to most application code — retry, re-authenticate,
fail — are the intended consumption pattern. Reach for individual
[`ErrorKind`](crate::error::ErrorKind) variants only when you need finer control.

## Source chains and downcasting

[`Error::source`](std::error::Error::source) chains preserve the concrete
underlying error (for example a transport crate's error type) for diagnostics,
logging, and error-report rendering. Downcasting a source to a concrete type is
**not** supported API surface: the type behind `source()` may change in any
release. Match on [`ErrorKind`](crate::error::ErrorKind) instead.
