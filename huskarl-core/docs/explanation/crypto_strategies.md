# Composing crypto strategies

The [`crypto`](crate::crypto) module is built from small, single-purpose traits
and a set of wrappers that decorate them. Each base operation — signing,
verification, encryption, decryption — is one trait describing a single key. The
wrappers implement the *same* trait, so they nest: a multi-key verifier can hold
retrying verifiers, each of which holds a refreshable verifier, and the JWT
layer above sees only a `JwsVerifier`. You assemble the behaviour you need by
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
  [`ScheduledRefreshCipher`](crate::crypto::cipher::ScheduledRefreshCipher). The
  *policy* layer over a refreshable: it never starts a reload on its own, but
  rate-limits the reload attempts something else makes — gating them by a TTL, a
  minimum interval between attempts, and a failure backoff. Inbound, the retrying
  wrapper makes those attempts on a miss; outbound, the application makes them (a
  background task, or a key-rotation event), since there is no miss to react to.

- **Retrying** —
  [`RetryingVerifier`](crate::crypto::verifier::RetryingVerifier),
  [`RetryingDecryptor`](crate::crypto::cipher::RetryingDecryptor). React to a
  *miss*: when no held key matches an incoming token, force a refresh (through
  the scheduled-refresh policy, when one is present) and try once more. This
  closes the gap when a token arrives signed by a key minted since the last JWKS
  fetch. Retrying is inbound-only — there is no outbound miss to react to, since
  the caller selects the key.

When the `metrics` feature is enabled,
[`MetricsJwsVerifier`](crate::crypto::verifier::MetricsJwsVerifier) and
[`MetricsAeadDecryptor`](crate::crypto::cipher::MetricsAeadDecryptor) wrap any
layer to emit counters and timings without changing its behaviour.

## How a stack fits together

A typical verifier for an authorization server's JWKS reads, from the outside
in: a metrics wrapper, around a retrying verifier (refresh-and-retry on an
unknown `kid`), around a multi-key verifier (pick the matching key), around a
refreshable verifier (the swappable JWKS snapshot), with a scheduled-refresh
policy bounding how often that snapshot may actually reload. Every layer is a
[`JwsVerifier`](crate::crypto::verifier::JwsVerifier), so the
[`jwt`](crate::jwt) validator — and any other consumer — depends only on the
base trait and never sees the composition.

A signing stack composes the same way but in selector terms: a
scheduled/refreshable
[`JwsSignerSelector`](crate::crypto::signer::JwsSignerSelector) over the key
source, with the layer above calling
[`select_signer`](crate::crypto::signer::JwsSignerSelector::select_signer) once
per token and signing against the returned snapshot.

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
[`unseal`](crate::crypto::cipher::AeadUnsealer::unseal) takes the same optional
match criteria as decryption, so a multi-key unsealer can pick the right key
from an out-of-band hint. A resource server uses this to issue and check
stateless `DPoP` nonces: seal the issue time into a bundle, hand it out, and
unseal it later to verify its age without server-side storage.
