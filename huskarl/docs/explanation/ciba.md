# CIBA authentication

CIBA lets an application initiate authentication for a known user without
redirecting their browser. The application sends a hint identifying the user,
and the provider contacts their authentication device. In poll mode, the
application polls the token endpoint while the user authenticates and consents.
No notification endpoint is needed.

A binding message helps the user recognize the transaction across devices.
The optional user code is a secret supplied by the user to authorize starting
a request. See [CIBA authentication requests](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7).

## Authentication results

Successful completion includes access tokens and a validated ID token. The
ID token identifies the authenticated user. Validation checks its signature,
issuer, audience, and lifetime against the response receipt time.

The application associates this identity with the session that initiated the
request. Access tokens authorize API requests; they don't replace the ID token
as evidence of the user's identity.

## Signing and client authentication

A signed authentication request packages the authentication parameters in a
JWT signed with the client's asymmetric key. The client registers its signing
algorithm and verification keys with the provider.

Request signing protects the authentication parameters. Client authentication
authenticates HTTP requests to the provider. Both need their own configuration
when signed requests are used.

## Waiting for the user

The provider returns a request ID, an expiry, and a polling interval.
An `authorization_pending` response means authentication is still in progress;
`slow_down` increases the interval. Denial and expiry end the flow.

Automatic polling waits before the first request and after each response. It
honors `Retry-After` and limits consecutive transient failures. If the provider
holds a request open, the next automatic poll still waits for the interval after
that response. See [CIBA token requests](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1).

Use the [CIBA how-to guide](crate::_docs::guide::ciba) to configure the grant,
start authentication, and handle the result.
