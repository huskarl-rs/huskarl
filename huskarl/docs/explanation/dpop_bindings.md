# DPoP bindings and client authentication

A DPoP binding associates a token with a signing key. The client proves that
it holds the key by signing a proof for each request that uses the token.
Access tokens and refresh tokens have separate bindings because they are
used at different endpoints with different authentication requirements.
When both tokens are DPoP-bound in one response, they use the same request
proof key.

## Access tokens follow the server's response

The response's `token_type` identifies the access token as bearer or DPoP.
For a DPoP token, the grant stores the request proof's key thumbprint in the
returned `AccessToken` value. A thumbprint identifies the key; it does not
contain the signing key itself.

Sending a DPoP proof does not guarantee a DPoP access token. The server may
return a bearer token, which does not require a proof when used at a resource
server.

## Public clients retain the refresh key

A public client does not authenticate with client credentials or mTLS.
For public clients using DPoP, [RFC 9449 §5](https://www.rfc-editor.org/rfc/rfc9449.html#section-5)
requires the server to bind refresh tokens to the proof key. This applies
even when the access token is a bearer token.

Built-in grants therefore store the request proof's key thumbprint in each
returned `RefreshToken` value for these clients. The refresh grant selects
the key identified by the stored thumbprint, even after the signer's current
key changes. Keeping the refresh token usable requires retaining both the
complete token value and access to the signing key.

## Confidential clients authenticate refresh requests

Confidential clients authenticate at the token endpoint using client
credentials or mTLS. For ordinary DPoP, built-in grants leave the key thumbprint
absent from newly acquired `RefreshToken` values for these clients. OIDC Key
Binding retains it for both client types, as described below.

When no binding is stored, the refresh grant uses the signer's current key
if DPoP is configured, or sends no proof otherwise. A stored thumbprint is
always honored, regardless of client type, and preserved in replacement refresh
tokens. An unavailable bound key causes failure before the token request.

Older versions also stored thumbprints for ordinary confidential-client DPoP
responses. Those saved values remain pinned. If the server does not require
that binding, callers can explicitly reconstruct the refresh token without a
thumbprint using `RefreshToken::new(token, None)`. Do not clear a binding merely
because the client is confidential; another protocol may require it.

The grant determines whether a client is public from its client authentication
and HTTP transport. `NoAuth` alone only sends a client identifier. With an
HTTP client that reports mTLS authentication, the grant treats the client as
confidential. DPoP itself does not authenticate the client.

For the steps to configure a refresh request and retain the required keys,
see the [refresh guide](crate::_docs::guide::refresh).

## ID-token key binding

Support targets [OpenID Connect Key Binding draft 03](https://openid.net/specs/openid-connect-key-binding-1_0-03.html).

To request binding, configure a DPoP signer and request both `openid` and
`bound_key` in an authorization-code or device flow. Use a dedicated key with
an algorithm the provider supports. Huskarl exposes the optional discovery
advertisements (`scopes_supported` and `dpop_signing_alg_values_supported`)
but does not require them.

| Request | Binding behavior |
| --- | --- |
| Authorization, including PAR/JAR, or device authorization | Sends the key's thumbprint as `dpop_jkt` |
| Code exchange or device polling | Adds `c_s256`: base64url SHA-256 of `code` or `device_code`, without padding |
| Refresh | Uses the original key; omits `c_s256` |

Nonce retries use fresh proofs with the same code hash. Both client types
retain the original key binding through refresh-token rotation, even with
bearer access tokens or when the OP ignores `bound_key`. DPoP access tokens
remain bound to the request proof's key.

### ID-token validation

`openid_bound_key_requested` records the request, not whether the OP honored
it. Authorization-code completion performs its usual ID-token checks and
additionally accepts `dpop+id_token`; ordinary ID tokens, including those
without `typ`, remain accepted. Device and refresh grants return raw ID tokens
for explicit validation with `IdTokenValidator`.

These paths neither compare `cnf` with the requested key nor verify possession.
The compact token preserves `cnf.jwk`, which `ConfirmationClaim` does not expose
as a typed field. For presentations within the RP, use
`IdTokenPresentationValidator` with an application-specific proof verifier
(see `_docs::guide::id_token_presentations`).
ID tokens stay within the RP; use access tokens for protected resources.

### State and key lifetimes

- **During authorization:** retain the complete `PendingState` until completion
  and any ID-token validation. Serialize it in full if saving between requests
  or device polls. Discard it afterwards; refreshes do not use it.
- **After authorization:** retain the returned `RefreshToken`. To save and
  restore it, serialize and deserialize the complete object. `RefreshToken::new`
  does not restore `openid_bound_key_requested`, even if given the thumbprint.
- **Throughout both:** keep the original private key available to the signer.
  The saved objects identify the key by thumbprint; neither contains it.

Older saved state defaults to no OIDC binding request; older device state also
has no thumbprint. Existing flows are not upgraded automatically.

