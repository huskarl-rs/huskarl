//! The source a [`TokenCache`](crate::cache::TokenCache) pulls tokens from.

use std::sync::Arc;

use crate::{
    core::{
        Error,
        dpop::{NoDPoP, ResourceServerDPoP},
        platform::{MaybeSendBoxFuture, MaybeSendSync},
    },
    grant::core::TokenResponse,
};

/// Where a cache obtains its tokens.
///
/// Everything about *how* a token is produced — refreshing, exchanging a grant,
/// or receiving one from elsewhere — lives behind this one trait, so there is a
/// single token-production concept. Caching is itself a `TokenSource` (see
/// [`InMemoryTokenCache`](crate::cache::InMemoryTokenCache)), layered on top.
///
/// The built-in producer is
/// [`GrantTokenSource`](crate::cache::GrantTokenSource), which refreshes or runs
/// a grant exchange. Implement it yourself for other producers (for example a
/// channel fed by a separate task).
///
/// An [`HttpAuthorizer`](crate::authorizer::HttpAuthorizer) does not consume a
/// bare `TokenSource`; it requires the memoizing
/// [`TokenCache`](crate::cache::TokenCache) marker (see there for why).
///
/// This trait is dyn-capable and is implemented for `Arc<T>`, `Box<T>`, and
/// `&T`, so a source can be shared: hand an `Arc<GrantTokenSource>` to the cache
/// and keep a clone to prime or inspect it on a live instance.
pub trait TokenSource: MaybeSendSync {
    /// Produces a token, returned in an `Arc` for cheap shared access on the
    /// request hot path.
    ///
    /// A caching source serves a memoized token; a producer mints a fresh one.
    fn token(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, Error>>;

    /// The `DPoP` binding for resource-server requests made with these tokens.
    ///
    /// A `DPoP`-bound token must be proven with the *same* key it is bound to —
    /// the token's `jkt` is that key's thumbprint. The source that issues such
    /// tokens is exactly the thing that owns the matching proof key, so keeping
    /// the two together guarantees the key and the `jkt` agree. Defaults to a
    /// no-op binding ([`NoDPoP`]); a source that issues `DPoP`-bound tokens
    /// (e.g. [`GrantTokenSource`](crate::cache::GrantTokenSource)) overrides it.
    fn resource_server_dpop(&self) -> &dyn ResourceServerDPoP {
        &NoDPoP
    }

    /// Drops any memoized token, forcing the next [`token`](Self::token) call to
    /// re-produce. Defaults to a no-op — only caching sources memoize.
    fn invalidate(&self) {}

    /// Whether the source holds a token that must be served in preference to a
    /// memoized one — e.g. one just handed in via
    /// [`prime`](crate::cache::GrantTokenSource::prime).
    ///
    /// A memoizing wrapper ([`InMemoryTokenCache`](crate::cache::InMemoryTokenCache))
    /// checks this before serving its cache, so a freshly-injected token is not
    /// shadowed by a still-valid cached one. Defaults to `false` — a source with
    /// no injection path never supersedes the cache.
    fn has_pending_token(&self) -> bool {
        false
    }

    /// Clears any persisted credential state (e.g. a stored refresh token), so
    /// the next [`token`](Self::token) starts fresh. Defaults to a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error if clearing underlying durable state fails.
    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        Box::pin(async { Ok(()) })
    }
}

macro_rules! forward_token_source {
    ($wrapper:ty) => {
        impl<T: TokenSource + ?Sized> TokenSource for $wrapper {
            fn token(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, Error>> {
                (**self).token()
            }

            fn resource_server_dpop(&self) -> &dyn ResourceServerDPoP {
                (**self).resource_server_dpop()
            }

            fn invalidate(&self) {
                (**self).invalidate();
            }

            fn has_pending_token(&self) -> bool {
                (**self).has_pending_token()
            }

            fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
                (**self).clear()
            }
        }
    };
}

forward_token_source!(&T);
forward_token_source!(Box<T>);
forward_token_source!(Arc<T>);
