# Caching tokens and wiring an authorizer

Wrap a grant in a [`GrantTokenSource`](crate::cache::GrantTokenSource), cache
its tokens with [`InMemoryTokenCache`](crate::cache::InMemoryTokenCache), and
pass the cache to [`HttpAuthorizer`](crate::authorizer::HttpAuthorizer). This
lets requests reuse tokens and acquire replacements when needed.

The source takes grant parameters and a refresh-token store. The authorizer
erases the cache's type parameters, so it can be stored directly in application
state:

```rust
# use huskarl::core::client_auth::NoAuth;
# use huskarl::core::http::HttpClient;
# use huskarl::grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters};
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache},
};

/// Plain types, no parameters: this struct names cleanly in app state.
struct App {
    authorizer: HttpAuthorizer,
}

# async fn example(http_client: impl HttpClient + 'static) -> Result<(), huskarl::core::Error> {
# let grant = ClientCredentialsGrant::builder()
#     .client_id("client-id")
#     .client_auth(NoAuth)
#     .token_endpoint("https://as.example.com/token".parse()?)
#     .http_client(http_client)
#     .build();
// `grant` is any grant, built as in the grant guides.
let source = GrantTokenSource::builder()
    .grant(grant)
    .grant_parameters(ClientCredentialsGrantParameters::builder().build())
    .refresh_store(InMemoryRefreshTokenStore::default())
    .build();
let cache = InMemoryTokenCache::builder().source(source).build();

let app = App {
    authorizer: HttpAuthorizer::builder().cache(cache).build(),
};
# drop(app);
# Ok(())
# }
```

Make authenticated requests through `app.authorizer` — see [making
authenticated requests](crate::_docs::guide::authorizer) for the request loop,
and [handling errors](crate::_docs::guide::handling_errors) to map
[`TokenError`](crate::cache::TokenError) recovery actions onto your application.

To survive restarts, persist the refresh token with a
custom [`RefreshTokenStore`](crate::cache::RefreshTokenStore) (keychain- or
disk-backed) through the source's `refresh_store` setter. The first token
acquisition after startup attempts a refresh. To hand a newly obtained token
from the login path to a running source, use
[`GrantTokenSource::prime`](crate::cache::GrantTokenSource::prime).

The `grant_parameters` choice is required, and interactive flows are exactly
the case where it is [`NoSource`](crate::cache::NoSource): the source cannot
run the authorization-code exchange itself, so it lives off refresh tokens
and what you [`prime`](crate::cache::GrantTokenSource::prime) into it.
Remember that a `NoSource` source that is never primed (over an empty store)
cannot produce a token — after [running the authorization code
flow](crate::_docs::guide::authorization_code), hand its token response over
(the crate's `authorization_code` example shows the full wiring):

```rust
# use huskarl::core::http::HttpClient;
# use huskarl::grant::authorization_code::AuthorizationCodeGrant;
# use huskarl::grant::core::TokenResponse;
use huskarl::cache::{GrantTokenSource, InMemoryRefreshTokenStore, NoSource};

# async fn example(
#     grant: AuthorizationCodeGrant,
#     token_response: TokenResponse,
# ) -> Result<(), Box<dyn std::error::Error>> {
let source = GrantTokenSource::builder()
    .grant(grant)
    .grant_parameters(NoSource) // refresh/prime only — stated, not defaulted
    .refresh_store(InMemoryRefreshTokenStore::default())
    .build();
source.prime(token_response).await?;
# let _ = source;
# Ok(())
# }
```

## Implementing your own

Reach for a custom implementation when a built-in's *storage* or *production*
model doesn't fit:

- [`RefreshTokenStore`](crate::cache::RefreshTokenStore) — the common one:
  persist refresh tokens beyond process memory (keychain, disk, database) so
  they survive a restart.
- [`TokenCache`](crate::cache::TokenCache) over a
  [`TokenSource`](crate::cache::TokenSource) — to memoize in a store shared
  across processes (e.g. Redis) rather than per-process memory. Implementing the
  marker is your promise that the wrapper actually caches.
- [`TokenSource`](crate::cache::TokenSource) alone — for a producer that isn't a
  grant, e.g. a channel fed by a separate task.
- [`GrantParametersSource`](crate::cache::GrantParametersSource) — for
  parameters minted per exchange from your own source (e.g. assertions fetched
  from a sidecar), beyond the
  [`single_use`](crate::cache::single_use) /
  [`reusable`](crate::cache::reusable) / [`from_fn`](crate::cache::from_fn)
  helpers.

For why sharing a [`RefreshTokenStore`](crate::cache::RefreshTokenStore) across
sources or processes is or isn't safe, see [sharing a refresh token
store](crate::_docs::explanation::sharing_a_token_store); for how
`InMemoryTokenCache` decides when to refresh, see [refresh
timing](crate::_docs::explanation::refresh_timing).
