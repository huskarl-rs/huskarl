# How a grant token source resolves a token

A [`GrantTokenSource`](crate::cache::GrantTokenSource) turns three possible
inputs — a primed token, a stored refresh token, and a grant-parameter source —
into a single token, and decides what to keep or abandon when one of them fails.
The [reference docs](crate::cache::GrantTokenSource) state the rules; this page
explains why they are the way they are.

## Why refresh comes before the parameter source

Each [`token`](crate::cache::TokenSource::token) call tries, in order: a primed
token, a refresh of the stored refresh token, then a fresh exchange using the
configured [`GrantParametersSource`](crate::cache::GrantParametersSource).

The parameter source is consulted **last**, only after the refresh attempt,
because producing parameters can be expensive or lossy — a
[`from_fn`](crate::cache::from_fn) source re-signs a JWT-bearer assertion, a
[`single_use`](crate::cache::single_use) source is spent by reading it. A usable
refresh token should avoid that work entirely, so it is tried first.

## Why credentials are abandoned

Two inputs are dropped once they provably cannot succeed again, so the source
stops replaying a dead credential on every call:

- The **refresh token** is discarded on `invalid_grant` — the server has
  rejected it, and a rejected refresh token never becomes valid again.
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

A **request-shape rejection**
([`RequestRejected`](crate::core::ErrorKind::RequestRejected): `invalid_scope`,
`invalid_target`, `invalid_resource`) is deliberately *not* treated as a
credential failure. The credential is fine; the *request* asked for something the
server would not grant, so the source is kept and the error surfaced unchanged,
letting a caller retry with a narrower request using the same credential.

The source returns
[`ReauthRequired`](crate::core::ErrorKind::ReauthRequired) **only when no
automatic recovery path remains** — a retryable transport failure, a retained
refresh token, a request-shape rejection, or a still-live dynamic source each
keeps its own classification instead, so an application only forces a user back
through login when nothing else can recover.

## Why there is a backoff breaker

Some sources keep failing non-recoverably from scratch — most often a
[`from_fn`](crate::cache::from_fn) re-signing against a revoked key: every fresh
value is rejected with `invalid_grant`, the source is never spent (its next value
*might* differ), and so each call hits the signer and the token endpoint again.
Without a bound this is a hot loop against your own signer and the authorization
server.

A breaker caps it: after `breaker_threshold` consecutive non-recoverable failures
(transient and request-shape failures don't count) the source backs off for
`breaker_cooldown`, then allows one trial per cooldown until it succeeds. Any
success, or a fresh [`prime`](crate::cache::GrantTokenSource::prime), resets it.

The breaker gates only the **from-scratch exchange** — a refresh is still
attempted first on every call, so a usable refresh token always recovers
independently. While the breaker is open the from-scratch path short-circuits
with `GetTokenError::Backoff` under
[`Backoff`](crate::core::ErrorKind::Backoff), without re-running the signer or the
exchange.

That [`Backoff`](crate::core::ErrorKind::Backoff) is deliberately not
[`ReauthRequired`](crate::core::ErrorKind::ReauthRequired): the failure is a dead
credential the *application* configured, not something a user can fix by logging
in again, so the caller should retry on a delay rather than bouncing the user
through an interactive login.
