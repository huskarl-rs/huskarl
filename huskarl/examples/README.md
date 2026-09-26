# Client examples

Run these commands from the workspace root. Cargo supplies the examples'
HTTP transport, TLS backend, and Tokio runtime through dev-dependencies.
Both examples below use OpenID Connect discovery; for an OAuth-only server,
replace `oidc_fetch()` with `fetch()` and use its issuer URL.

## Obtain one access token

Register a confidential client that may use the client-credentials grant, then
set its issuer, client ID, and secret:

```sh
export ISSUER=http://127.0.0.1:8080/realms/huskarl-tutorial
export CLIENT_ID=tutorial-client
export CLIENT_SECRET=tutorial-secret
cargo run -p huskarl --example client_credentials
```

The [first-token tutorial](../docs/tutorial/first_token.md) sets up this local
server and client. The example prints `Access token: ...` and exits. It prints
the credential deliberately for inspection; the cached client example below
prints only HTTP status codes. Set `SCOPE` to a space-separated list if your
server requires scopes.

## Make requests with a cached token

Use an issuer and client authorized to access your resource server. Set
`RESOURCE_URL` to its final, absolute URL; the example does not follow redirects.

```sh
export ISSUER=https://auth.example.com
export CLIENT_ID=service-client
export CLIENT_SECRET=your-client-secret
export RESOURCE_URL=https://api.example.com/widgets
export SCOPE=read
cargo run -p huskarl --example cached_client
```

This sends two GET requests through one `HttpAuthorizer`, backed by a
`GrantTokenSource` and an `InMemoryTokenCache`. With a valid cached token, the
second request reuses it. Successful output is two lines such as
`Request 1: 200 OK` and `Request 2: 200 OK`.

Token acquisition retries once when `Recovery::Retry` advises it, honoring any
minimum delay. A recoverable HTTP authentication challenge also gets one retry.
Other acquisition failures and HTTP error statuses return an error. The example
checks authentication responses but leaves resource response bodies unread.

If you copy this into another project, add `huskarl`, `huskarl-reqwest` with
`rustls-tls`, `http`, `reqwest`, and `tokio` with `macros`, `rt-multi-thread`,
and `time`. See [the authorizer guide](../docs/guide/authorizer.md) for the
response-handling contract and [error handling](../docs/guide/handling_errors.md)
for other recovery policies.
