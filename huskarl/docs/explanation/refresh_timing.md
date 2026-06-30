# Refresh timing: refresh-ahead and jitter

The three timing knobs on
[`InMemoryTokenCache`](crate::cache::InMemoryTokenCache) —
[`expires_margin`](crate::cache::InMemoryTokenCacheBuilder::expires_margin),
[`refresh_ahead`](crate::cache::InMemoryTokenCacheBuilder::refresh_ahead), and
[`refresh_jitter`](crate::cache::InMemoryTokenCacheBuilder::refresh_jitter) —
form one "when to refresh" decision. Each is an *absolute* value tuned for
minutes-to-hours tokens. Two of them — the hard margin and the jitter band — are
additionally clamped to a fraction of each token's own lifetime so very
short-lived tokens degrade smoothly: the hard margin is capped at half a token's
life (a 20s token is still served ~10s, not
retired at issuance into a blocking refetch loop) and the jitter band scales to
~10% of it (see [Jitter](#jitter)); for normal lifetimes these clamps are inert.
`refresh_ahead` is deliberately left unclamped — it only pulls the proactive
refresh earlier, so a value larger than the token's lifetime simply puts every
served token in the refresh window immediately.

## Refresh-ahead

At its most conservative — `refresh_ahead` unset **and**
[`refresh_jitter`](crate::cache::InMemoryTokenCacheBuilder::refresh_jitter) set
to [`None`] — a token is refreshed only once it reaches the hard
[`expires_margin`](crate::cache::InMemoryTokenCacheBuilder::expires_margin),
where the acquiring caller blocks on the source. (By default jitter is on, so
even with `refresh_ahead` unset the refresh is pulled slightly earlier and runs
without blocking — see [Jitter](#jitter).) Set
[`refresh_ahead`](crate::cache::InMemoryTokenCacheBuilder::refresh_ahead) to a
*larger* margin to refresh proactively while the token is still valid: the
request that observes the window refreshes it *without blocking other callers* —
one is elected via a non-blocking lock, the rest are served the still-valid
token, and a failed attempt is non-fatal because that token still covers it.
This needs no background task and works anywhere, including serverless — the
work is driven by the request that observes the window, just moved earlier while
the token has slack.

For strictly synchronous-at-margin behaviour (block only at `expires_margin`,
never refresh early), leave `refresh_ahead` unset **and** set `refresh_jitter`
to [`None`] — the default jitter triggers an early refresh on its own.

## Jitter

A fleet of independent instances deployed together mints tokens at about the
same time with the same lifetime, so without jitter they all hit the refresh
trigger at once and stampede the token endpoint (the single-flight lock only
coalesces callers *within* one process). Each instance instead picks a stable
random point in its band — once, never changed — and brings its trigger forward
by that much.

The band is proportional to the token's lifetime, capped at
[`refresh_jitter`](crate::cache::InMemoryTokenCacheBuilder::refresh_jitter)
(default `Some(30s)`; [`None`] disables it). Scaling to the lifetime stops a
fixed offset — a rounding error on a 1h token — from swallowing most of a 60s
token's life, mirroring how certificate-rotation systems renew at a random
fraction of the credential's lifetime. A jittered refresh runs on the same
non-blocking, failure-tolerant path as [refresh-ahead](#refresh-ahead), so it
only moves *when* a refresh starts, never how long a token is served.
