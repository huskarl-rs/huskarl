# Authenticate a user with CIBA poll mode

Use [`CibaPollGrant`](crate::grant::ciba::CibaPollGrant) when you know the user's
identifier and your provider can authenticate them on a separate device. Your
application starts the request and polls for completion. It doesn't need a
notification endpoint.

For background, see [CIBA authentication](crate::_docs::explanation::ciba).

## Before you begin

Register your client with the provider for the
`urn:openid:params:grant-type:ciba` grant and `backchannel_token_delivery_mode`
set to `poll`. Configure client authentication and load the provider's
verification keys. See [client authentication](crate::_docs::guide::client_authentication)
for credential setup. The grant accepts any
[`JwsVerifier`](crate::core::crypto::verifier::JwsVerifier), including an existing
verifier that refreshes its keys.

For dynamic registration, set
[`ClientMetadata::backchannel_token_delivery_mode`](crate::registration::ClientMetadata::backchannel_token_delivery_mode)
to `"poll"` and include `"urn:openid:params:grant-type:ciba"` in `grant_types`.
Set `backchannel_authentication_request_signing_alg` if you sign authentication
requests, and `backchannel_user_code_parameter` if the client supports user codes.
The `backchannel_client_notification_endpoint` field is for ping and push
registration; poll mode does not need it.

Configure your HTTP transport to allow at least 30 seconds for token responses.
The provider can hold a poll open while it waits for authentication.

## 1. Configure the grant

Use discovery metadata to populate endpoints and provider capabilities:

```rust,no_run
use huskarl::{
    core::{
        client_auth::ClientAuthentication,
        crypto::verifier::JwsVerifier,
        http::HttpClient,
        server_metadata::AuthorizationServerMetadata,
    },
    grant::ciba::CibaPollGrant,
};

# fn configure(
#     metadata: &AuthorizationServerMetadata,
#     http_client: impl HttpClient + 'static,
#     client_auth: impl ClientAuthentication + 'static,
#     verifier: impl JwsVerifier + 'static,
# ) -> Result<CibaPollGrant, huskarl::core::Error> {
let grant = CibaPollGrant::builder_from_metadata(metadata)?
    .client_id("client_id")
    .client_auth(client_auth)
    .http_client(http_client)
    .jws_verifier(verifier)
    .build()?;
# Ok(grant)
# }
```

The builder requires an issuer and a verifier, and rejects unauthenticated
clients or metadata that doesn't advertise poll mode. Building the grant doesn't
fetch verification keys.

Without discovery, use `CibaPollGrant::builder()` and set `issuer`,
`token_endpoint`, and `backchannel_authentication_endpoint` explicitly. You can
also use `.client(&client_configuration)` to share client identity,
authentication, and DPoP configuration with other grants.

To limit how long ago a returned ID token may have been issued, set
`max_id_token_age` on the grant builder. The limit checks `iat` at token-response
receipt and includes clock leeway. It is a local acceptance policy, not a request
parameter or a deadline for user approval. No issuance-age limit applies by default.

## 2. Start authentication and poll for completion

Select one hint that your provider accepts. This example uses an email address:

```rust,no_run
use huskarl::grant::ciba::{CibaHint, CibaPollGrant, StartInput};

# async fn authenticate(grant: &CibaPollGrant) -> Result<(), Box<dyn std::error::Error>> {
let started = grant.start(
    StartInput::builder()
        .hint(CibaHint::login_hint("person@example.com"))
        .scope(bon::vec!["email"])
        .binding_message("A123")
        .build(),
).await?;

// Display the same binding message in your application.
let mut pending = started.pending_state;
let completed = grant.poll_to_completion(&mut pending, None).await?;

let subject = &completed.id_token.sub;
let access_token = completed.token_response.access_token();
// Associate the validated identity with the application session that started the request.
# Ok(())
# }
```

The grant includes `openid` automatically and validates the returned ID token.
Use `CibaHint::login_hint_token` for a provider-specific hint token, or
`CibaHint::id_token_hint` for a previously issued signed ID token.

If your provider and client registration support user codes, pass the current
user-supplied code with `.user_code(...)`. Ask for it for each flow. Don't store
it with pending state. Use `.requested_expiry(...)` with a `NonZeroU32` to request
a particular lifetime; the provider chooses the actual expiry.

## Sign authentication requests

If your client is registered to send signed requests, add
`.request_signer(signer)` to the grant builder. The signer must implement
[`AsymmetricJwsSignerSelector`](crate::core::crypto::signer::AsymmetricJwsSignerSelector).
Register its algorithm and verification keys with your provider.

The grant signs the authentication parameters and sends the resulting JWT in
`request`. Client authentication remains separate. Discovery restricts request
signing to the provider's advertised algorithms.

## Manage polling yourself

To integrate with your own scheduler, persist `started.pending_state` and call
`grant.poll(&mut pending, None)` for each attempt. The `poll` method doesn't
sleep or reject early calls. Wait at least `pending.interval_secs`
between requests, and avoid concurrent requests for the same authentication.
A `slow_down` response increases that interval.

Use `started.expires_at` to set an application deadline. The provider enforces
the actual expiry. Automatic polling persists this local estimate in pending
state, caps waits at it, and stops before sending another request once it passes.
Transport timeouts bound requests already in flight.

Handle [`PollResult`](crate::grant::ciba::PollResult) as follows:

- `Pending`: schedule another poll.
- `Complete`: use the validated ID token and token response.

For [`PollError`](crate::grant::ciba::PollError), inspect `retry_advice()`.
Automatic polling honors retry delays and the configured failure budget.
Denial, expiry, and ID-token completion failures stop polling. Completion
failures don't retry redemption, even if verification failed temporarily.
Recover the issued response with `error.into_token_response()` and call
`grant.complete(response, &pending).await` to retry validation
without another token request. Until validation succeeds, the response does not
establish the user's identity. Validation uses the original response receipt time.

For step-up authentication or other flows with a known subject, set
`.expected_sub(subject)` on `StartInput`. It is persisted with pending state and
checked against the validated ID token. Pass the original pending state when
retrying `complete`. Login hints are provider-specific and are not automatically
converted into subject identifiers.

With `experimental-oidc-key-binding` enabled, `start` rejects the unsupported
`bound_key` scope before contacting the provider.

The low-level `OAuth2ExchangeGrant::exchange` method returns raw token data.
Use `poll` or `poll_to_completion` when you need a validated identity.
