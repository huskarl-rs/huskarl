# Sharing a refresh token store

A refresh token lives in a [`RefreshTokenStore`](crate::cache::RefreshTokenStore),
and a [`GrantTokenSource`](crate::cache::GrantTokenSource) treats its store as
singly owned: it assumes it is the only writer. Sharing one source *instance*
across tasks (via `Arc`) is always fine. Whether several sources — or several
processes/replicas — may share one store comes down to whether the authorization
server rotates refresh tokens, which RFC 9700 §4.14.2 ties to the client type:

- **Confidential clients** are not subject to the replay-detection requirement,
  and commonly issue long-lived, non-rotating refresh tokens. Concurrent
  refreshes reuse the same token, so sharing is safe.
- **Public clients** must let the server detect refresh-token replay by one of
  two means: *sender-constraining* the token (mTLS [RFC 8705] or `DPoP`
  [RFC 9449]) **or** *rotation* (a new refresh token on each refresh, the
  previous one invalidated). Sender-constraining satisfies the requirement
  without rotation, so a `DPoP`-bound client (which huskarl supports) can also
  share safely.
- **Public clients relying on rotation** are the one share-hostile case: two
  owners refreshing concurrently can each present a token the other rotated out,
  and reuse detection then revokes the whole family. Because that is harsh, the
  major providers that mandate rotation (Okta, Auth0, …) soften it with a short
  **grace period** in which the rotated-out token stays valid — which, with the
  source re-reading the store before every refresh, absorbs the brief race and
  lost-response retries. A provider with no grace period stays unsafe to share;
  use single ownership, or sender-constrain the token.

To stay correct under sharing, a
[`GrantTokenSource`](crate::cache::GrantTokenSource) does **not** blindly clear
the store on `invalid_grant`: it re-reads first and discards only if the store
still holds the token that was rejected, so it never erases a peer's
freshly-rotated token. huskarl adds no cross-process rotation lock —
[`RefreshTokenStore::get`](crate::cache::RefreshTokenStore::get) /
[`set`](crate::cache::RefreshTokenStore::set) expose no atomic rotate — so for a
strict, rotation-only public client, give each replica its own store and
credential.

[RFC 8705]: https://www.rfc-editor.org/rfc/rfc8705
[RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449
