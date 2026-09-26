# Validate a bearer token

The `basic` example validates one token without starting an HTTP server. It
requires an issuer that publishes OpenID Connect discovery metadata and issues
RFC 9068 access tokens. JWTs with another profile need a
[custom validator](../docs/guide/custom.md); opaque tokens need
[introspection](../docs/guide/introspection.md).

Run from the workspace root:

```sh
export ISSUER=https://auth.example.com
export AUDIENCE=https://api.example.com
export RESOURCE_URL=https://api.example.com/widgets
export ACCESS_TOKEN=your-access-token
cargo run -p huskarl-resource-server --example basic
```

Use an unexpired bearer access token issued for `AUDIENCE`. The example fetches
discovery metadata and signing keys, then validates the token as if it arrived
on a GET request to `RESOURCE_URL`. Cargo supplies Tokio and the HTTP/TLS
backend through dev-dependencies. For OAuth-only discovery, replace
`oidc_fetch()` with `fetch()`.

Success prints `Authenticated; application authorization is still required.`
A rejected token prints the rejection status and response headers and exits
with an error. Your service must still check whether the authenticated claims
permit the requested operation.

This example presents a bearer token. DPoP-bound tokens also need a matching
proof; see the [DPoP guide](../docs/guide/dpop.md). For framework integration,
see the companion [huskarl-axum](https://github.com/huskarl-rs/huskarl-axum)
(unreleased) and [huskarl-pingora](https://github.com/huskarl-rs/huskarl-pingora)
repositories.
