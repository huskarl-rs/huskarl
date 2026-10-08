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
credentials or mTLS. Built-in grants leave the DPoP key thumbprint absent
from newly acquired `RefreshToken` values for these clients.

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
