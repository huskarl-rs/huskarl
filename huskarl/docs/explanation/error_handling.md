# Error handling

This page explains why token acquisition has a specialized error and where the
line falls between "log in again" and "nothing to be done". For application
code, see
[handling errors](crate::_docs::guide::handling_errors); the generic type itself
is [core's page](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/error_handling/).

## Where the remedy lives

[`Error`](crate::core::Error) says whether re-attempting *one operation* can
help, and what the server said if it judged the request. It cannot say what to
do next, because "retry", "adjust the request", "log in again" and "give up" are
statements about the alternatives a *token source* holds — a stored refresh
token, a reusable credential, a grant parameter source.

So the answer lives on the source's own error,
[`TokenError`](crate::cache::TokenError), as a
[`Recovery`](crate::cache::Recovery). It is opaque: the variants underneath are
this crate's business, and exposing them would make every future split of one a
breaking change.

The boundary is:

```text
transport, KMS, signer, grant  -> Error
TokenSource                    -> TokenError { Recovery, Error }
TokenCache and HttpAuthorizer  -> preserve TokenError
```

`TokenError::from(Error)` is the default conversion at the `TokenSource`
boundary. Lower layers return `Error`; they do not need to know about
`Recovery`.

The two layers can legitimately disagree. If an authorization server rejects
one dynamically generated assertion, repeating that exchange is futile
(`RetryAdvice::No`), but asking the token source again can mint another assertion
(`Recovery::Retry`). Conversely, an HTTP attempt may be retryable even though an
authorization code was consumed and the source now requires reauthentication.
The underlying classification remains unchanged in both cases.

For a simple source with no alternatives, the default conversion derives
recovery directly and preserves details such as a KMS cooldown. A source that
owns alternatives establishes recovery explicitly with
[`TokenError::new`](crate::cache::TokenError::new). A memoizing cache and the
authorizer preserve that decision rather than deriving it again.

## Why reauthentication is narrow

**A source with nothing left.** Only the source knows whether its refresh token,
grant parameters, and other acquisition paths are exhausted. A generic error
from one attempt cannot establish this.

**A server rejecting silent authorization.** A `prompt=none` request answered
`login_required`, `interaction_required`, `consent_required` or
`account_selection_required` is the authorization server saying it cannot
proceed without a human. This is a direct protocol instruction rather than a
local inference about credentials.

A user who *was* asked and pressed deny is `access_denied`, which is
[`Fail`](crate::cache::Recovery::Fail): re-running the flow shows them the same
page. The line is not whether a human is involved, but whether one has yet had
the chance to act.

## The operations with their own error type

An operation returns its own type when callers are expected to branch on its
variants rather than merely report a failure:

- [`PollError`](crate::grant::device_authorization::PollError) — `AccessDenied`
  and `TokenExpired` are branches a device-flow UI takes.
- `LoopbackError` — an `access_denied` decides what the browser page says. Not
  linked, because it exists only under the `authorization-flow-loopback` feature
  (and off browser wasm), so a link here would break every build without it.
- [`ParseCallbackError`](crate::grant::authorization_code::ParseCallbackError) —
  carries no `Error`, because parsing redirect parameters never reaches a
  server. An OAuth error response is not a parse failure: it parses, and
  completion surfaces it as a rejection.
