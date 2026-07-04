# Sender-constraining tokens with DPoP

DPoP (RFC 9449) binds tokens to a key pair the client holds: every use of the
token carries a proof signed with that key, so a leaked token is useless to
anyone else. In huskarl it is one builder option on the grant — proof
generation, access-token binding, and nonce handling all follow from it.

## 1. Create the proof signer

[`DPoP`](crate::core::dpop::DPoP) wraps an asymmetric signing key. The key
*is* the binding: tokens obtained through this value can only be used with
it. A fresh key generated at startup is the normal deployment — the binding
only needs to outlive the tokens, and a per-process key never touches
storage:

```rust
use huskarl::core::dpop::DPoP;
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let dpop = DPoP::builder()
    .signer(PrivateKey::generate(GenerateAlgorithm::Es256, None)?)
    .build();
# let _ = dpop;
# Ok(())
# }
```

Reuse one `DPoP` value (it is cheap to clone) everywhere a binding to the
same key is intended.

## 2. Attach it to the grant

Every grant takes the same `dpop` builder option. Token requests then carry
a proof, and the tokens that come back are bound to the key:

```rust
# use huskarl::core::client_auth::NoAuth;
# use huskarl::core::dpop::DPoP;
# use huskarl::core::http::HttpClient;
# use huskarl::core::server_metadata::AuthorizationServerMetadata;
# use huskarl::grant::client_credentials::ClientCredentialsGrant;
# use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
# async fn example(
#     http_client: impl HttpClient + Clone + 'static,
# ) -> Result<(), Box<dyn std::error::Error>> {
# let metadata = AuthorizationServerMetadata::fetch()
#     .http_client(&http_client)
#     .issuer("https://issuer")
#     .call()
#     .await?;
let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
    .client_id("my-client")
    .http_client(http_client)
    .client_auth(NoAuth)
    .dpop(
        DPoP::builder()
            .signer(PrivateKey::generate(GenerateAlgorithm::Es256, None)?)
            .build(),
    )
    .build();
# let _ = grant;
# Ok(())
# }
```

If the authorization server demands a proof nonce at the token endpoint
(`use_dpop_nonce`, RFC 9449 §8), the grant records the nonce and retries the
request once automatically — no handling required.

Whether the issued token is actually DPoP-bound is the **server's**
decision: [`AccessToken`](crate::token::AccessToken) distinguishes plain
`Bearer` tokens from [`DPoP`](crate::token::AccessToken::DPoP) tokens, which
carry the confirmed key thumbprint (`jkt`). A server without DPoP support
typically ignores the proof and issues a Bearer token — the rest of the
pipeline handles either.

## 3. Calling resource servers

Wrap the grant in a cache and an
[`HttpAuthorizer`](crate::authorizer::HttpAuthorizer) exactly as in [caching
tokens](crate::_docs::guide::caching): no extra DPoP wiring. When the cached
token is DPoP-bound,
[`get_headers`](crate::authorizer::HttpAuthorizer::get_headers) returns an
`Authorization: DPoP …` header plus a fresh `DPoP` proof header bound to the
access token (`ath`) and the request's method and URI.

Resource servers can demand nonces too. [The request
loop](crate::_docs::guide::authorizer) already covers it:
[`process_response`](crate::authorizer::HttpAuthorizer::process_response)
records any `DPoP-Nonce` response header (per origin), and the single re-send
on a `401` carries the nonce the server just demanded.

To sign proofs without the authorizer — a one-off request, or your own
request path — derive the resource-server signer from the grant and create
proofs directly; see the [`basic_dpop`
example](https://github.com/huskarl-rs/huskarl/blob/main/huskarl/examples/basic_dpop.rs)
for the full flow:

```rust
# use http::Method;
# use huskarl::core::dpop::{AuthorizationServerDPoP as _, DPoP, ResourceServerDPoP as _};
# use huskarl::token::DpopAccessToken;
# async fn example(dpop: DPoP, token: DpopAccessToken) -> Result<(), Box<dyn std::error::Error>> {
let uri: http::Uri = "https://api.example.com/v1/widgets".parse()?;
let resource_dpop = dpop.to_resource_server_dpop();
let proof = resource_dpop
    .proof(&Method::GET, &uri, token.token(), token.jkt())
    .await?;
# let _ = proof;
# Ok(())
# }
```

## 4. Refresh keeps the binding

A refresh grant made with `to_refresh_grant` inherits the grant's DPoP
configuration alongside its client authentication (see [the refresh
guide](crate::_docs::guide::refresh)), so refreshed access tokens stay bound
to the same key — as does the
[`GrantTokenSource`](crate::cache::GrantTokenSource) refresh path, which
does this for you.

## Validating DPoP on the server side

The other half — a resource server validating DPoP-bound requests — lives in
[`huskarl-resource-server`](https://docs.rs/huskarl-resource-server); see its
*Validating DPoP-bound tokens* guide.
