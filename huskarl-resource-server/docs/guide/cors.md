# Configure browser access with CORS

CORS belongs to the consuming server. Neither adapter installs a CORS policy.
For public metadata fetched without credentials, return
`Access-Control-Allow-Origin: *`; browser callers can use `credentials: "omit"`.
For protected API responses, configure allowed origins and expose
`WWW-Authenticate` (and `DPoP-Nonce` when used) through
`Access-Control-Expose-Headers`. Apply this to authentication failures too.
Handle permitted preflights before authentication, explicitly allowing
`Authorization` and, when needed, `DPoP`. Credentialed requests require an
explicit allowed origin and `Access-Control-Allow-Credentials: true`.
When responses select an origin dynamically, include `Vary: Origin`.
See the [Fetch CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol).

In Axum, put the chosen CORS middleware outside the assembled router so it
covers rejection responses and preflights. In Pingora, configure the consuming
server or front proxy to cover metadata, locally written failures and upstream
responses; an upstream-only filter misses local responses. A front proxy is
also a convenient place to handle preflights before either adapter's auth path.
Keep this policy separate from which `.well-known` paths are published.

Verify in a browser that public metadata is readable, a 401 exposes the challenge,
and allowed token-request preflights succeed without authenticating OPTIONS.
Metadata CORS permission does not grant access to the protected resource.
