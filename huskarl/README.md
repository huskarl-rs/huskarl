<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Huskarl provides tools for implementing secure `OAuth2` clients in rust.

This library provides a number of grant implementations, each of which is configured
with a set of parameters that define how the grant/workflow should progress.

The library also provides a caching layer for token responses; and a HTTP authorizer
that can be used to make authenticated requests to resource servers.

## Examples

### Client Credentials Grant

```rust
let metadata = AuthorizationServerMetadata::builder()
    .http_client(&http_client)
    .issuer(issuer)
    .build()
    .await
    .unwrap();

let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
    .client_id(client_id)
    .client_auth(ClientSecret::new(client_secret))
    .dpop(NoDPoP)
    .build();

let token_response = grant
    .exchange(
        &http_client,
        ClientCredentialsGrantParameters::builder()
            .scopes(vec!["test"])
            .build(),
    )
    .await
    .unwrap();

println!(
    "Access token: {}",
    token_response.access_token.expose_token()
);
```

<!-- cargo-reedme: end -->
