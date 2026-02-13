# huskarl

<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Huskarl provides tools for implementing secure `OAuth2` clients in rust.

`OAuth2` grants are workflows that allow a user to get an authorization proof
from  an authorization server, and make that available for the client to use to
talk to other services (the resource server). There are a number of grants,
each of which are useful under different circumstances, and have different
characteristics.

## Comprehensive Grant Implementations

Huskarl provides each grant as a separate implementation, which is configured
up front in terms of how the grant/workflow should progress. Some of this
configuration may be provided by authorization server metadata, which allows
the client to discover the necessary information at runtime, and choose the
most appropriate set of steps to follow. For example, there are extensions to
the authorization code grant that make the grant more secure, but not all
servers support these extensions.

## Secure and Flexible Client Authentication

In an `OAuth2` context, a client may need to identify itself to the authorization
server. Huskarl allows the secret material to come from a variety of sources,
including environment variables, secure enclaves, secret managers, and cloud
HSMs.

## WASM / `WebCrypto`

Huskarl works with WASM and `WebCrypto`, which makes it suitable for use in
web browsers and edge computing contexts. `WebCrypto` can be more secure than
in-rust code in browsers, as it may be less vulnerable to side-channel
attacks.

## Device-bound Token Support

Protecting access and refresh tokens after receipt is an important part of the
client’s overall security posture. Huskarl fully supports `DPoP`, and
accepts `mTLS` clients; both are approaches which may make the tokens
unusable to an attacker if exfiltrated from the machine.

## Examples

### Client Credentials Grant

```rust
let metadata = AuthorizationServerMetadata::from_issuer(issuer)
    .call(&http_client)
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
