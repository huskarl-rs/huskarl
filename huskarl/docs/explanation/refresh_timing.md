# Refresh timing: refresh-ahead and jitter

[`InMemoryTokenCache`](crate::cache::InMemoryTokenCache) uses two thresholds:
one for starting a refresh and one for retiring the cached token. Refresh is
driven by calls to this cache; it does not run a background task. These are
implementation choices of `InMemoryTokenCache`, not requirements of
[`TokenCache`](crate::cache::TokenCache). Other implementations could refresh
in a background task or thread.

## When a token stops being served

[`expires_margin`](crate::cache::InMemoryTokenCacheBuilder::expires_margin)
retires a token before its actual expiry. It defaults to 30 seconds and is
capped at half the token's lifetime. For example, a 20-second token has an
effective margin of 10 seconds, rather than being retired immediately.

Once the cached token reaches this threshold, callers wait for acquisition.
If the token has no `expires_in`, the cache uses `default_expires_in` (one hour
by default) to calculate its lifetime.

## When an early refresh starts

The refresh threshold is measured backwards from token expiry:

```text
refresh threshold = refresh_ahead (or the effective expires_margin) + jitter
```

[`refresh_ahead`](crate::cache::InMemoryTokenCacheBuilder::refresh_ahead) is an
alternative margin before expiry, not an extra duration added to
`expires_margin`. Set it larger than the effective expiry margin to create an
early-refresh window. It is not clamped to the lifetime: a sufficiently large
value puts every newly acquired token in that window.

While the cached token is still valid, one caller acquires the refresh lock
without waiting and performs the refresh inline. **That caller waits for the
refresh; concurrent callers receive the cached token.** If the refresh fails,
the elected caller also receives the existing token.

## Why jitter is enabled by default

Instances started together often obtain tokens with similar expiry times.
Jitter spreads their refresh attempts across time; the acquisition lock only
coordinates callers sharing one cache instance.

Each cache picks a random fraction once. For each token, it multiplies that
fraction by the smaller of 10% of the token's lifetime and
[`refresh_jitter`](crate::cache::InMemoryTokenCacheBuilder::refresh_jitter)
(default `Some(30s)`). The fraction is stable, but the resulting offset can
change when token lifetimes change.

Jitter starts refresh earlier without changing the retirement threshold. To
refresh only at that threshold, leave `refresh_ahead` unset and set
`refresh_jitter` to `None`.
