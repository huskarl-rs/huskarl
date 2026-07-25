# Dynamic client registration

[OAuth 2.0 Dynamic Client Registration (RFC 7591)](crate::registration) lets a
client register itself with an authorization server by sending an HTTP `POST` of
the desired [`ClientMetadata`](crate::registration::ClientMetadata) to the
registration endpoint via
[`ClientRegistration`](crate::registration::ClientRegistration). On success the
server returns a
[`ClientInformationResponse`](crate::registration::ClientInformationResponse)
carrying the issued `client_id` and, for confidential clients, a
`client_secret` — the credentials the OAuth grants in [`crate::grant`] then use
to obtain tokens.

The registration endpoint (and its mTLS alias) is discovered from
[`AuthorizationServerMetadata`](crate::core::server_metadata::AuthorizationServerMetadata)
via `builder_from_metadata` — which errors if the server advertises no
registration endpoint — or supplied directly with
[`ClientRegistration::builder`](crate::registration::ClientRegistration::builder).

## Handling the issued client secret

A confidential client's `client_secret` is returned **once** and cannot be
re-fetched (re-registering issues a new `client_id`). Persist it to your secret
storage on receipt, then on later runs load it back through a
[`Secret`](crate::core::secrets::Secret) provider — an
[`EnvVarSecret`](crate::core::secrets::EnvVarSecret), a `FileSecret`, or your
own over a keychain or KMS — to build the grant's
[`ClientSecret`](crate::core::client_auth::ClientSecret) authentication. A
`Secret` provider is the only way to supply a client secret to a grant.

## Example

```rust,no_run
# use huskarl::core::http::HttpClient;
# use huskarl::core::server_metadata::AuthorizationServerMetadata;
use huskarl::registration::{ClientMetadata, ClientRegistration};

# async fn example(
#     http_client: impl HttpClient + 'static,
#     metadata: AuthorizationServerMetadata,
# ) -> Result<(), huskarl::core::Error> {
let registration = ClientRegistration::builder_from_metadata(&metadata)?
    .build();

let desired = ClientMetadata::builder()
    .client_name("My App")
    .redirect_uris(bon::vec!["https://app.example/callback"])
    .grant_types(bon::vec!["authorization_code"])
    .build();

let info = registration.register(&http_client, &desired).await.unwrap();
println!("registered client_id: {}", info.client_id);

// The client_secret is returned only once — persist it to your secret store.
if let Some(secret) = &info.client_secret {
    persist_to_secret_store(secret);
}
# Ok(())
# }
# fn persist_to_secret_store(_secret: &huskarl::core::secrets::SecretString) {}
```
