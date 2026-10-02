# Making authenticated requests

[`HttpAuthorizer`](crate::authorizer::HttpAuthorizer) turns the token machinery
(grant, cache, `DPoP`) into request headers:
[`get_headers`](crate::authorizer::HttpAuthorizer::get_headers) builds the
authorization headers for a request — exchanging or refreshing tokens as
needed — and
[`process_response`](crate::authorizer::HttpAuthorizer::process_response)
records what each response reveals.

For a complete program with configuration, a token cache, real HTTP requests,
and bounded retries, see the repository's
[cached client example](https://github.com/huskarl-rs/huskarl/blob/main/huskarl/examples/README.md#make-requests-with-a-cached-token).

## The request loop

1. Build headers with
   [`get_headers`](crate::authorizer::HttpAuthorizer::get_headers) and send the
   request with your HTTP client.
2. Pass every response's headers — success or failure — to
   [`process_response`](crate::authorizer::HttpAuthorizer::process_response).
3. On a `401 Unauthorized`, rebuild the headers and re-send **once** if your API
   semantics allow: step 2 already recorded any demanded `DPoP` nonce and
   dropped a token the server rejected, so the rebuilt headers carry the fix if
   there is one. A second `401` is definitive.

```rust
# use huskarl::authorizer::{HttpAuthorizer, parse_challenges};
# use huskarl::core::OAuthErrorCode;
# use http::{HeaderMap, Method, StatusCode, Uri};
# struct Response { status: StatusCode, headers: HeaderMap }
# async fn send(_headers: HeaderMap) -> Response {
#     Response { status: StatusCode::OK, headers: HeaderMap::new() }
# }
# async fn example(authorizer: &HttpAuthorizer) -> Result<(), Box<dyn std::error::Error>> {
let uri: Uri = "https://api.example.com/v1/widgets".parse()?;

let headers = authorizer.get_headers(&Method::GET, &uri).await?;
let mut response = send(headers).await;
authorizer.process_response(&uri, &response.headers);

if response.status == StatusCode::UNAUTHORIZED {
    // Optional: the WWW-Authenticate challenges say what the server
    // objected to. `insufficient_scope` needs broader authorization —
    // re-sending cannot fix it.
    let scope_problem = parse_challenges(&response.headers)
        .iter()
        .any(|challenge| challenge.error() == Some(OAuthErrorCode::InsufficientScope));

    if !scope_problem {
        let headers = authorizer.get_headers(&Method::GET, &uri).await?;
        response = send(headers).await;
        authorizer.process_response(&uri, &response.headers);
    }
}
# drop(response);
# Ok(())
# }
```

Whether and when to re-send is the application's decision, not this library's —
[`parse_challenges`](crate::authorizer::parse_challenges) exposes the server's
stated objection for making it, as above. For `DPoP`,
[`dpop_resend_advised`](crate::authorizer::dpop_resend_advised) reports the one
recoverable nonce challenge: `use_dpop_nonce` carrying a fresh
nonce (RFC 9449 §7.2). Step 2 already recorded that nonce, so the rebuilt
headers carry it:

```rust
# use huskarl::authorizer::{HttpAuthorizer, dpop_resend_advised};
# use http::{HeaderMap, Method, StatusCode, Uri};
# struct Response { status: StatusCode, headers: HeaderMap }
# async fn send(_headers: HeaderMap) -> Response {
#     Response { status: StatusCode::OK, headers: HeaderMap::new() }
# }
# async fn example(authorizer: &HttpAuthorizer) -> Result<(), Box<dyn std::error::Error>> {
# let uri: Uri = "https://api.example.com/v1/widgets".parse()?;
# let headers = authorizer.get_headers(&Method::GET, &uri).await?;
# let mut response = send(headers).await;
authorizer.process_response(&uri, &response.headers);

if dpop_resend_advised(response.status, &response.headers) {
    let headers = authorizer.get_headers(&Method::GET, &uri).await?;
    response = send(headers).await;
    authorizer.process_response(&uri, &response.headers);
}
# drop(response);
# Ok(())
# }
```

For non-idempotent requests, retry only when the API guarantees that a rejected
request has no side effects, or provides an idempotency mechanism.

## When the server doesn't emit a spec-correct challenge

Step 2's automatic token invalidation works only when the server emits a
spec-correct `invalid_token` challenge (RFC 6750 §3.1), and not all do. The
application may recognize additional rejection signals from that server.

If the server's documented behavior identifies a bad token through a bare
`401`, a JSON error body, or a custom convention, call
[`invalidate`](crate::authorizer::HttpAuthorizer::invalidate) before re-sending.
Treating any `401` as a stale token is a common policy, at the cost of an
occasional unnecessary refresh.

## When a response relays an upstream challenge

[`process_response`](crate::authorizer::HttpAuthorizer::process_response) acts on
the headers alone and ignores the status code. A spec-correct `invalid_token`
challenge normally accompanies a `401` and describes the token sent by the
authorizer.

Consider a client calling an intermediary service, which calls an upstream API
with a separate token. If the intermediary copies the upstream API's
`WWW-Authenticate` header into its response to the client, that challenge
describes the intermediary's token. Passing it to the client's
`process_response` would wrongly invalidate the client's token.

When integrating the client's authorizer, pass only response headers that
describe the token it sent. When implementing the intermediary, handle upstream
authentication failures separately instead of presenting them as challenges to
the client.
