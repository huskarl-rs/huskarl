# Making authenticated requests

[`HttpAuthorizer`](crate::authorizer::HttpAuthorizer) turns the token machinery
(grant, cache, `DPoP`) into request headers:
[`get_headers`](crate::authorizer::HttpAuthorizer::get_headers) builds the
authorization headers for a request — exchanging or refreshing tokens as
needed — and
[`process_response`](crate::authorizer::HttpAuthorizer::process_response)
records what each response reveals.

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
        .any(|challenge| challenge.error() == Some("insufficient_scope"));

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
stated objection for making it, as above. A `401` is issued before the request
is processed, so a single re-send is normally safe even for non-idempotent
requests.

## When the server doesn't emit a spec-correct challenge

Step 2's automatic token invalidation works only when the server emits a
spec-correct `invalid_token` challenge (RFC 6750 §3.1), and not all do. You know
your server better than this library can: when a bare `401`, a JSON error body,
or a custom convention tells you the token is bad, call
[`invalidate`](crate::authorizer::HttpAuthorizer::invalidate) yourself before
re-sending. Treating any `401` as a stale token is a common policy, at the cost
of an occasional unnecessary refresh.

[`process_response`](crate::authorizer::HttpAuthorizer::process_response) acts on
the headers alone and ignores the status code. That is normally fine, since a
spec-correct `invalid_token` challenge always accompanies a `401`. The one trap
is relaying: if your service copies an upstream server's `WWW-Authenticate` onto
its own response, that header reflects *the upstream's* view of *its* token, not
yours — passing it here would wrongly invalidate your token. Give
[`process_response`](crate::authorizer::HttpAuthorizer::process_response) only
the headers that describe your own request.
