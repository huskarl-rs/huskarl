# Composing crypto strategies

The [`crypto`](crate::crypto) module is built from small, single-purpose traits
and a set of wrappers that decorate them. Each base operation — signing,
verification, encryption, decryption — is one trait describing a single key. The
wrappers implement the *same* trait, so they nest: a retrying verifier can wrap
a scheduled-refresh verifier that swaps a multi-key snapshot, and the JWT layer
above sees only a `JwsVerifier`. You assemble the behaviour you need by
stacking layers rather than configuring one large type.

## The base traits

- **Signing** — [`JwsSigner`](crate::crypto::signer::JwsSigner) produces a JWS
  signature for one key.
- **Verification** — [`JwsVerifier`](crate::crypto::verifier::JwsVerifier)
  verifies a signature for one key.
- **Encryption / decryption** —
  [`AeadEncryptor`](crate::crypto::cipher::AeadEncryptor) and
  [`AeadDecryptor`](crate::crypto::cipher::AeadDecryptor) for content encryption
  with one key.

Concrete key implementations of these traits live in the platform crypto crates
(for example the native and WebCrypto backends), not in `huskarl-core`, which
defines only the traits and the wrappers that compose them.

Verification carries one piece of machinery the other directions don't. Its key
material *arrives as data* — a JWKS fetched at runtime — so each key has to be
turned into a working verifier by whatever backend is present. That construction
step is the [`JwsVerifierPlatform`](crate::crypto::verifier::JwsVerifierPlatform):
a pluggable "materialise a verifier from a [`PublicJwk`](crate::jwk::PublicJwk)"
seam, which is what lets the same JWKS logic run over RustCrypto natively and
WebCrypto on wasm. There is deliberately no matching signer or cipher "platform":
you *hold* those keys, building a concrete
[`JwsSigner`](crate::crypto::signer::JwsSigner) or
[`AeadCipher`](crate::crypto::cipher::AeadCipher) directly from a source you chose
(a KMS handle, a file, a secret manager). Nothing has to be materialised from
arriving data, so a factory there would resolve nothing — the concrete key already
carries its backend. It is the inbound/outbound split below in another guise:
inbound keys are *built for you* from what the wire delivered; outbound keys are
*handed in* fully formed.

## Two directions of key selection

Picking *which* key to use splits along the direction of the operation, and the
two directions work in opposite ways.

**Inbound — matching a key to an arriving token.** Verification and decryption
are handed a token (or bundle) and must find the held key whose `alg`/`kid`
fits. The verifier reports the fit through
[`key_match`](crate::crypto::verifier::JwsVerifier::key_match) and the decryptor
through [`cipher_match`](crate::crypto::cipher::AeadDecryptor::cipher_match),
both ranked by [`KeyMatchStrength`](crate::crypto::KeyMatchStrength): an exact
`kid` match (`ByKeyId`) beats an algorithm-only match (`ByAlgorithm`). That
ordering is what lets a multi-key wrapper pick the best candidate, and what lets
the retrying wrappers recognise a *miss* — no held key matched — and react.

**Outbound — selecting a key to emit with.** Signing and encryption are not
handed a token to match; the caller chooses the current key. That choice goes
through a *selector*:
[`select_signer`](crate::crypto::signer::JwsSignerSelector::select_signer) hands
out the signer to use right now, and
[`select_cipher`](crate::crypto::cipher::AeadCipherSelector::select_cipher) the
encryptor. [`KeyMatchStrength`](crate::crypto::KeyMatchStrength) plays no part
here. The multi-key signer ([`MultiKeySigner`](crate::crypto::signer::MultiKeySigner))
returns its default key, or — via
[`select_signer_by_thumbprint`](crate::crypto::signer::AsymmetricJwsSignerSelector::select_signer_by_thumbprint)
— the key with a given JWK thumbprint, which is how a `DPoP` proof is signed
with the exact key the access token is bound to (its `dpop_jkt`).

## Why selectors exist: staying consistent across a reload

The selector is not ceremony; it is what keeps outbound operations correct when
keys rotate at runtime. The difference shows in *which trait* each refreshable
wrapper implements.

On the inbound side,
[`RefreshableVerifier`](crate::crypto::verifier::RefreshableVerifier) implements
[`JwsVerifier`](crate::crypto::verifier::JwsVerifier) directly. Each call loads
the current key snapshot and runs to completion, and a verify only ever accepts
or rejects — so a rotation landing mid-flight can do no worse than turn a match
into a miss, which the retrying layer recovers by refreshing and trying once
more. The consumer holds the wrapper for the life of the program and never sees
the swap.

On the outbound side a swap *mid-operation* would be corrupting, not merely a
miss. Signing is compound: read the signer's algorithm and `kid` to build the
JWS protected header, then sign. The header must describe the key that actually
produced the signature. If the key rotated between reading the `kid` and
signing, the result would be a JWS whose header names one key but whose
signature came from another — silently invalid, with no error to catch it. So
the refreshable wrapper implements the *selector*, not the operation:
[`RefreshableSigner`](crate::crypto::signer::RefreshableSigner) is a
[`JwsSignerSelector`](crate::crypto::signer::JwsSignerSelector), **not** a
`JwsSigner` — there is deliberately no hot-swappable signer.
[`select_signer`](crate::crypto::signer::JwsSignerSelector::select_signer) hands
back a frozen snapshot, and the caller runs the whole read-header-then-sign
sequence against that one snapshot. Rotation happens *between* selections, never
within one — which is why a selected signer should be used immediately and
dropped, not cached across a rotation. Encryption and
[`AeadCipherSelector`](crate::crypto::cipher::AeadCipherSelector) work the same
way.

## The wrapper families

The same concerns recur across the operations, each a wrapper implementing the
relevant trait — the operation trait inbound, the selector trait outbound:

- **Multi-key** — [`MultiKeyVerifier`](crate::crypto::verifier::MultiKeyVerifier)
  and [`MultiKeyDecryptor`](crate::crypto::cipher::MultiKeyDecryptor) dispatch an
  arriving token to the best-matching key by
  [`KeyMatchStrength`](crate::crypto::KeyMatchStrength); this is how a JWKS with
  many keys is presented as a single verifier.
  [`MultiKeySigner`](crate::crypto::signer::MultiKeySigner) and
  [`MultiKeyCipher`](crate::crypto::cipher::MultiKeyCipher) are the outbound
  counterparts — the signer selects by default or thumbprint (above), and the
  cipher encrypts with one key while decrypting against many (e.g. rotated
  cookie keys).

- **Refreshable (hot-swap)** —
  [`RefreshableVerifier`](crate::crypto::verifier::RefreshableVerifier),
  [`RefreshableSigner`](crate::crypto::signer::RefreshableSigner),
  [`RefreshableCipher`](crate::crypto::cipher::RefreshableCipher). Hold the
  current key material behind an atomic swap so it can be replaced at runtime
  (a rotated key, a re-fetched JWKS) without rebuilding the stack above.
  Concurrent refreshes are serialised; waiters adopt the in-flight result. The
  signer and cipher variants are *selectors*, for the reason above.

- **Scheduled refresh** —
  [`ScheduledRefreshVerifier`](crate::crypto::verifier::ScheduledRefreshVerifier),
  [`ScheduledRefreshSigner`](crate::crypto::signer::ScheduledRefreshSigner),
  [`ScheduledRefreshCipher`](crate::crypto::cipher::ScheduledRefreshCipher). Wrap
  a refreshable with a TTL and drive it *on the read path*: on each inbound
  operation ([`verify`](crate::crypto::verifier::JwsVerifier::verify) /
  [`decrypt`](crate::crypto::cipher::AeadDecryptor::decrypt)), if the keyset has
  outlived its TTL the first caller to notice reloads it single-flight —
  non-blocking for concurrent callers, who keep serving the current keyset —
  before proceeding. This bounds the keyset's age to the TTL, which is what
  drops a *removed* key: a key dropped upstream still verifies (or decrypts) its
  own tokens, so no failure ever signals its removal — only the time bound catches
  it. A minimum interval and
  failure backoff rate-limit the reloads. The outbound selectors work the same
  way: selection
  ([`select_signer`](crate::crypto::signer::JwsSignerSelector::select_signer) /
  [`select_cipher`](crate::crypto::cipher::AeadCipherSelector::select_cipher)) is
  async, so it reloads a stale key *during selection* — the outbound read path —
  and hands back a fresh frozen snapshot. There the TTL bounds how quickly a
  rotated-in key is discovered rather than how quickly a removed one is dropped,
  but the mechanism is identical and the caller never has to poll.

- **Retrying** —
  [`RetryingVerifier`](crate::crypto::verifier::RetryingVerifier),
  [`RetryingDecryptor`](crate::crypto::cipher::RetryingDecryptor). React to a
  *miss* — no held key matches the token's `alg`/`kid` — by refreshing and trying
  once more. This is the fast path for key *additions*: a token signed by a
  freshly-rotated `kid` is accepted as soon as a miss drives a reload, instead of
  waiting for the next scheduled reload — though that reload is itself gated by the
  scheduled layer's `min_refresh_interval`, so the first unknown-`kid` miss fetches
  while any others arriving within that window still surface the miss until the
  ceiling clears. It reacts *only* to a miss; a signature mismatch is almost
  always a forged token (a refresh would be wasted), and its one legitimate case —
  a same-algorithm, kid-less rotation — is caught within the TTL by the scheduled
  layer's read-path reload instead. So the two layers split the work: **misses
  here handle additions; the TTL there handles removals and the kid-less edge.**
  Retrying is inbound-only — there is no outbound miss, since the caller selects
  the key.

## How a stack fits together

A typical verifier for an authorization server's JWKS reads, from the outside
in: an optional metrics wrapper, around a retrying verifier (reload-and-retry on
an unknown `kid`), around a scheduled-refresh verifier (the TTL-bounded snapshot
of the whole keyset, reloaded on the read path), around a multi-key verifier
(pick the matching key from the current snapshot), around the per-key verifiers.
The scheduled-refresh layer sits *outside* the multi-key verifier, so a reload
swaps the entire keyset as a unit — which is how a *removed* key is dropped, not
merely how a new one is added. Every layer is a
[`JwsVerifier`](crate::crypto::verifier::JwsVerifier), so the
[`jwt`](crate::jwt) validator — and any other consumer — depends only on the
base trait and never sees the composition.

For the task-oriented recipe — wiring this default stack into a validator and
swapping it for another — see [configuring JWT
verification](crate::_docs::guide::configuring_jwt_verification).

A signing stack composes the same way but in selector terms: a
scheduled/refreshable
[`JwsSignerSelector`](crate::crypto::signer::JwsSignerSelector) over the key
source, with the layer above calling
[`select_signer`](crate::crypto::signer::JwsSignerSelector::select_signer) once
per token and signing against the returned snapshot.

One nuance distinguishes the outbound direction. Because you own the signing key
and choose when it rotates, outbound rotation is *self-driven*: the TTL bounds how
quickly a newly-rotated key is discovered rather than how quickly a removed one is
dropped, and
[`refresh`](crate::crypto::signer::RefreshableSigner::refresh) forces an immediate
reload on an explicit rotation event.

## Sealing: self-contained bundles

Encryption has one more layer for values that must travel on their own —
encrypted cookies, stateless tokens — where the nonce and tag have to ride along
with the ciphertext. [`AeadSealer`](crate::crypto::cipher::AeadSealer) and
[`AeadUnsealer`](crate::crypto::cipher::AeadUnsealer) frame an AEAD operation as
a versioned, self-describing bundle
(`[0x01 || nonce_len || tag_len || nonce || ciphertext || tag]`), implemented by
[`AeadV1Cipher`](crate::crypto::cipher::AeadV1Cipher) over any inner cipher. The
impls are capability-conditional: wrapping a cipher that does both directions
yields a [`SealedAeadCipher`](crate::crypto::cipher::SealedAeadCipher); an
encrypt-only key yields just a sealer; a decrypt-only key — a retired rotation
key that can still open old bundles — yields just an unsealer.

Sealing is an **outbound** operation, so — like signing — it reaches its key
through a *selector*.
[`select_sealer`](crate::crypto::cipher::AeadSealerSelector::select_sealer) hands
back a *frozen* [`AeadSealer`](crate::crypto::cipher::AeadSealer), and
[`unseal`](crate::crypto::cipher::AeadUnsealer::unseal) takes the same match
criteria as decryption, so a caller can record *which* key sealed a bundle — a
cookie attribute, a database column — for a later unseal to select on. The frozen
snapshot is what makes that recorded `kid` trustworthy: it collapses the separate
"read the [`key_id`](crate::crypto::cipher::AeadEncryptor::key_id)" and
"[`seal`](crate::crypto::cipher::AeadSealer::seal)" steps onto one key, so a
rotation between them cannot leave the bundle carrying one key's `kid` over
another's ciphertext — the same corruption a
[`JwsSignerSelector`](crate::crypto::signer::JwsSignerSelector) prevents for
read-header-then-sign. Note the hazard lives in the *caller's* out-of-band `kid`,
not in the bundle, which carries none.

For a key that never rotates, wrap it in
[`StaticAeadCipher`](crate::crypto::cipher::StaticAeadCipher) — the fixed-key base
case, the cipher analogue of a signing key that is its own selector. For one that
does, a [`RefreshableCipher`](crate::crypto::cipher::RefreshableCipher) or
[`ScheduledRefreshCipher`](crate::crypto::cipher::ScheduledRefreshCipher) reloads a
stale key during `select_sealer` exactly as it does for
[`select_cipher`](crate::crypto::cipher::AeadCipherSelector::select_cipher),
bounding how quickly a rotated-in key is discovered; both erase to
`Arc<dyn SealedAeadCipherSelector>` when the key source is chosen at runtime. A
resource server uses this to issue and check stateless `DPoP` nonces: select a
sealer, seal the issue time into a bundle, hand it out, and unseal it later to
verify its age without server-side storage.
