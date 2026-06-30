# Caching tokens and wiring an authorizer

Grants belong to the login path. For the request path, wrap a grant in a token
cache and an [`HttpAuthorizer`](crate::authorizer::HttpAuthorizer). The usual
wiring is a chain, built from the inside out: an `HttpAuthorizer` holds an
[`InMemoryTokenCache`](crate::cache::InMemoryTokenCache), which wraps a
[`GrantTokenSource`](crate::cache::GrantTokenSource), which runs a grant —
drawing exchange parameters from a
[`GrantParametersSource`](crate::cache::GrantParametersSource) and storing the
refresh token in a [`RefreshTokenStore`](crate::cache::RefreshTokenStore). Most
applications use the built-in at every link and implement none of these traits
themselves.

Workflow types carry no type parameters, so they store directly in your
application state.

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
and [error handling](crate::_docs::explanation::error_handling) for how every
operation's [`Error`](crate::core::Error) embeds in your own error type.

To survive restarts, persist only the refresh token by handing the cache a
custom [`RefreshTokenStore`](crate::cache::RefreshTokenStore) (keychain- or
disk-backed); on startup the cache refreshes into a fresh access token. For
handing a freshly-obtained token from the login path to a running source, use
[`GrantTokenSource::prime`](crate::cache::GrantTokenSource::prime).

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
store](crate::_docs::explanation::sharing_a_token_store); for how the cache
decides when to refresh, see [refresh
timing](crate::_docs::explanation::refresh_timing).
