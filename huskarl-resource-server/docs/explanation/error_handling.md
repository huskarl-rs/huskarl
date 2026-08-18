# The error model

A resource server answers a different question from an OAuth client. A client
error describes what happened while making an outbound request. A validation
error determines how this server rejects an inbound request without disclosing
unsafe details or blaming the token holder for a server failure.

## Response metadata and context

Every validator error implements
[`ToRfc6750Error`](crate::error::ToRfc6750Error). The trait separates two kinds
of information:

- [`Challenge`](crate::error::Challenge) contains response metadata: the error
  classification, client-safe description, required scope, and additional
  challenge parameters.
- `attempted_scheme`, `validation_outcome`, and `issuer` describe the context in
  which the failure occurred.

This distinction matters for composed validators. A wrapper preserves the inner
challenge because the underlying failure still determines the wire response.
It reports context itself because only the wrapper may know whether the token
was presented as `Bearer` or `DPoP`, which validation stage failed, or which
registered issuer was selected. The inner error remains available through
[`std::error::Error::source`] for diagnostics and downcasting.

## Client or ours

[`TokenValidationError`](crate::error::TokenValidationError) separates failures
that produced a verdict about the request from failures that prevented a
verdict.

The line is not "did something go wrong" but **was the token ever judged**. A
cold JWKS means the signature was never checked, so it is `Server` — reporting
`invalid_token` blames the client for this deployment's startup. Same for an
unreachable replay store or an introspection endpoint that will not answer.

Only `Server` carries a retry interval. Waiting can help when an upstream service
or required secret is temporarily unavailable; it cannot make an invalid token
valid.

Server failures carry a [`ServerStatus`](crate::error::ServerStatus), which can
represent only a 5xx. This prevents a failure from accidentally using a success
status or a 4xx while omitting the `WWW-Authenticate` challenge expected for a
client authentication error.

## Choosing a server status

The status identifies where recovery is needed:

- HTTP 500 indicates this resource server's credentials, configuration, or
  generated request must be fixed.
- HTTP 502 indicates that an upstream service returned no usable answer.
- HTTP 503 indicates that retrying may work. If the failure includes a measured
  delay, [`Rejection`](crate::rejection::Rejection) emits it as `Retry-After`.

These distinctions make access logs operationally useful without exposing the
underlying failure to the client. Applications that need different policy can
construct their own response from the error metadata.

## Two code enums, on purpose

[`TokenErrorCode`](crate::error::TokenErrorCode) is the **closed** set a resource
server emits; [`OAuthErrorCode`](crate::core::OAuthErrorCode) is the **open**
registry a client may receive. A resource server that could emit an arbitrary
string would be one whose challenges are not reviewable.

Keeping the emitted set closed makes resource-server responses reviewable,
while the open client-side representation remains able to preserve extension
codes received from other servers.

## Metrics agree with the wire

[`validation_outcome`](crate::error::ToRfc6750Error::validation_outcome) keeps
routine protocol outcomes separate from conditions that may need investigation:

- `Expired` is split from `InvalidToken` because late-refreshing clients make
  expiry the highest-volume benign rejection, and folding it in would mask a
  signature-failure spike — the broken-key-rotation signal.
- `NonceRequired` stays out of `BindingError` for the same reason: nonce churn
  is routine, while `BindingError` should stay a possible-stolen-token signal.
- Anything answering a 5xx is `CallError`. The token was never judged, so it
  must not appear as a token rejection.

[`issuer`](crate::error::ToRfc6750Error::issuer) is a metrics label, so it must
return only configured or registered values — never unverified token contents,
which an attacker could use to mint unbounded label cardinality.

## Nonce and missing-token responses

A `DPoP` nonce can accompany successful validation because a checker may rotate
nonces before they expire. It must be echoed in a `DPoP-Nonce` response header
on both success and rejection paths.

No credentials is not a token error. `Ok(None)` means nothing was presented. If
the endpoint requires authentication, respond with 401 and unauthenticated
challenges without an `error` attribute; RFC 6750 §3 reserves that attribute for
a request that presented a token.

## Reaching a concrete cause

Use [`Error::chain`](crate::core::Error::chain) to inspect a classified Huskarl
error and its sources. For other validation errors, follow
[`std::error::Error::source`]. Because wrappers expose their inner errors this
way, one walk can reach through a multi-issuer router, its selected validator,
and the underlying JWT error.

Chain output is operator-facing. The challenge `description` is client-facing
and must not be treated as a detailed diagnosis. In particular, RFC 7662 §2.2
defines `active: false` for expired, revoked, malformed, and unknown tokens; the
authorization server does not disclose which condition applied.
