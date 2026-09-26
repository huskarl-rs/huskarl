# Sharing a refresh token store

A [`GrantTokenSource`](crate::cache::GrantTokenSource) assumes it is the only
writer to its [`RefreshTokenStore`](crate::cache::RefreshTokenStore). Sharing
one source instance through `Arc` preserves its acquisition lock. Separate
sources or processes have separate locks, even if they share a store.

## Rotation determines the concurrency risk

With a non-rotating refresh token, concurrent refreshes can reuse the same
credential if the authorization server permits it. With rotation, two owners
can submit the same token, and one may invalidate the credential the other is
using. Reuse detection can revoke the token family.

Client type and sender constraints do not establish whether rotation is enabled.
A confidential client or a DPoP-bound token can still be subject to rotation.
A provider's grace period may reduce rejected concurrent requests, but it does
not coordinate writes to the store or prevent responses arriving out of order.

## Re-reading reduces races but does not eliminate them

After `invalid_grant`, the source re-reads the store. If it observes a different
token, it retries with that token, up to three refresh attempts in total. If it
still sees the rejected token, it clears the store.

The read and clear are separate operations. A peer can write a new token between
them, so this check cannot guarantee that a peer's token is preserved. Successful
refreshes can also overwrite each other's rotated tokens.

The store API provides no atomic compare-and-clear or cross-process refresh
lock. For rotating tokens, keep one owner for each refresh-token lineage, or
coordinate the entire read, exchange, and write sequence outside these sources.
Separate replicas can instead use independently issued credentials.
