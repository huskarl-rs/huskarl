# Refresh timing: refresh-ahead and jitter

[`InMemoryTokenCache`](crate::cache::InMemoryTokenCache) uses two thresholds:
one for starting a refresh and one for retiring the cached token. Refresh is
driven by calls to this cache; it does not run a background task. These are
implementation choices of `InMemoryTokenCache`, not requirements of
[`TokenCache`](crate::cache::TokenCache). Other implementations could refresh
in a background task or thread.

## Which clock controls lifetimes

For locally received tokens, `expires_in` and the default lifetime start when
the HTTP response arrives. Parsing, validation, priming, and cache insertion do
not restart the lifetime. Cloned responses and nested caches retain the original
receipt timestamp.

Expiry is a wall-clock deadline: `received_at + expires_in` (or the default
lifetime). Every expiry and refresh-window check compares the cache’s wall
clock with that deadline, adjusted by the applicable margin. System suspension
counts naturally. Clock adjustments affect expiry: moving the wall clock backward
can delay expiry, while moving it forward can retire a token early. This also
applies when the clock moves backward past the receipt timestamp; the original
deadline remains unchanged.

Absolute JWT claims such as `exp`, `nbf`, and `iat` also use wall time. Monotonic
timers are used separately for scheduling, polling, and cooldowns. Advancing only
`ManualTime`'s monotonic timeline does not age tokens; advance its wall clock to
test expiry.

Caches default to `source.clock()`, which comes from the grant for a
`GrantTokenSource`. An explicit cache `.clock(...)` controls that cache's expiry
and refresh-window checks. Configure producers and caches with consistent wall
time, including a shared `ManualTime` timeline in tests.

Custom producers can use
[`TokenReceipt::capture`](crate::grant::core::TokenReceipt::capture)
to capture the wall timestamp at receipt, then pass it to
[`RawTokenResponse::into_token_response_with_receipt`](crate::grant::core::RawTokenResponse::into_token_response_with_receipt).
Responses supplied with only a wall timestamp preserve that timestamp as well,
so delayed insertion and cloning do not restart the lifetime. Refresh persisted
credentials when their remaining lifetime is uncertain.

## When a token stops being served

[`expires_margin`](crate::cache::InMemoryTokenCacheBuilder::expires_margin)
retires a token before its actual expiry. It defaults to 30 seconds and is
capped at half the token's lifetime. For example, a 20-second token has an
effective margin of 10 seconds, rather than being retired immediately.

Once the cached token reaches this threshold, callers wait for acquisition.
If the token has no `expires_in`, the cache uses `default_expires_in` (one hour
by default) to calculate its lifetime. The lifetime and margin are combined before
timestamp arithmetic, so large values can cancel without intermediate overflow.
Deadlines beyond Jiff's timestamp range saturate at its boundaries: oversized
lifetimes (including `default_expires_in`) remain far-future deadlines, while
oversized margins produce far-past deadlines. The wall-time
`AccessToken::effective_expiry` API returns a `SystemTime`, additionally clamped to
the platform's representable range. Equality with the deadline counts as expired.

## When an early refresh starts

The refresh threshold is measured backwards from token expiry:

```text
refresh threshold = refresh_ahead (or the effective expires_margin) + jitter
```

[`refresh_ahead`](crate::cache::InMemoryTokenCacheBuilder::refresh_ahead) is an
alternative margin before expiry, not an extra duration added to
`expires_margin`. A value larger than the effective expiry margin creates an
early-refresh window. The cache does not clamp it to the lifetime: a
sufficiently large value puts every newly acquired token in that window.

While the cached token is still valid, one caller acquires the refresh lock
without waiting and performs the refresh inline. **That caller waits for the
refresh; concurrent callers receive the cached token.** If the refresh fails,
the elected caller receives the existing token and a later call retries.

## Why jitter is enabled by default

Instances started together often obtain tokens with similar expiry times.
Jitter spreads their refresh attempts across time; the acquisition lock only
coordinates callers sharing one cache instance.

Each cache picks a random fraction once. For each token, it multiplies that
fraction by the smaller of 10% of the token's lifetime and
[`refresh_jitter`](crate::cache::InMemoryTokenCacheBuilder::refresh_jitter)
(default `Some(30s)`). The fraction is stable, but the resulting offset can
change when token lifetimes change.

Jitter starts refresh earlier without changing the retirement threshold.

To refresh only at that threshold, leave `refresh_ahead` unset and set
`refresh_jitter` to `None`.
