# How a grant token source resolves a token

A [`GrantTokenSource`](crate::cache::GrantTokenSource) can use a primed token, a
stored refresh token, or a grant-parameter source. Its resolution policy
minimizes credential replay, avoids unnecessary exchanges, and reports
reauthentication only after automatic paths are exhausted.

## Why refresh comes before the parameter source

Each [`token`](crate::cache::TokenSource::token) call tries, in order: a primed
token, a refresh of the stored refresh token, then a fresh exchange using the
configured [`GrantParametersSource`](crate::cache::GrantParametersSource).

Producing grant parameters can be expensive or destructive: a
[`from_fn`](crate::cache::from_fn) source re-signs a JWT-bearer assertion, a
[`single_use`](crate::cache::single_use) source is spent by reading it. A usable
refresh token avoids that work, so refresh precedes parameter acquisition.

## Why credentials are abandoned

Credentials are dropped only when replay cannot succeed:

- The **refresh token** is discarded after an `invalid_grant` verdict. Reusing a
  refresh token that the authorization server has invalidated is futile and can
  interfere with refresh-token rotation policies.
- A **fixed parameter source** is spent on `invalid_grant`, *provided it opts in*
  via
  [`discard_after_rejection`](crate::cache::GrantParametersSource::discard_after_rejection).
  A fixed value that was rejected is dead (true for concrete values); a
  [`from_fn`](crate::cache::from_fn) source is *not* spent, because its next value
  may differ (a freshly minted assertion). A
  [`single_use`](crate::cache::single_use) source is consumed on first use and
  never replayed regardless.

Because a spent fixed source's rejected value cannot become valid again, neither
[`prime`](crate::cache::GrantTokenSource::prime) nor
[`clear`](crate::cache::TokenSource::clear) revives it. To supply a fresh
credential, build a new source or use a [`from_fn`](crate::cache::from_fn) source,
which mints a new value per exchange and is never spent.

A **request-parameter rejection** — a code for which
[`parameters_at_fault`](crate::core::OAuthErrorCode::parameters_at_fault) holds:
`invalid_scope`, `invalid_target`, `invalid_resource` — says that the request,
not the credential, must change. Retaining the credential lets the caller retry
with a narrower scope or a different target without unnecessary login.

Reauthentication is disruptive and cannot repair transient failures or bad
request parameters. The source therefore returns
[`Reauthenticate`](crate::cache::Recovery::Reauthenticate) only when no
automatic path remains. A retryable failure, retained refresh token,
request-parameter rejection, or live dynamic source prevents that conclusion.

Recovery describes the whole acquisition attempt, while the underlying
[`Error`](crate::core::Error) continues to describe the selected failed
operation. For example, a dynamic source converts a terminal rejection of one
generated value into [`Retry`](crate::cache::Recovery::Retry), because its next
value may differ. A KMS or signer-provided retry interval is preserved when that
path is selected. If all paths are exhausted, the source can instead report
`Reauthenticate` without rewriting the underlying retry advice or verdict.

## Why there is a backoff breaker

Some dynamic sources can fail non-recoverably on every fresh exchange. For
example, a
[`from_fn`](crate::cache::from_fn) re-signing against a revoked key: every fresh
value is rejected with `invalid_grant`, the source is never spent (its next value
*might* differ), and so each call hits the signer and the token endpoint again.
Without a bound, request traffic can become a hot loop against the signer and
authorization server.

A breaker caps it: after `breaker_threshold` consecutive non-recoverable failures
(transient and request-shape failures don't count) the source backs off for
`breaker_cooldown`, then allows one trial per cooldown until it succeeds. Any
success, or a fresh [`prime`](crate::cache::GrantTokenSource::prime), resets it.

The breaker gates only the **from-scratch exchange** — a refresh is still
attempted first on every call, so a usable refresh token always recovers
independently. While the breaker is open the from-scratch path short-circuits
with a [`Backoff`](crate::TokenOutcome::Backoff) outcome under
a [`Retry`](crate::cache::Recovery::Retry) carrying the remaining cooldown as
its `after`, without re-running the signer or the exchange.

The cooldown is reported as [`Retry`](crate::cache::Recovery::Retry), not
[`Reauthenticate`](crate::cache::Recovery::Reauthenticate). Logging in again
cannot repair an application-configured assertion key or signer; delayed retry
avoids involving the user in an operational failure.
