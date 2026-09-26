# Composing crypto strategies

For an introduction with alternative key configurations feeding the same JWT
validation policy, start with
[how verification fits together](crate::_docs::explanation::verification).

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

Concrete key implementations of these traits live in the backend crates — the
native and WebCrypto platforms, and remote backends such as `huskarl-google-cloud`
for Cloud KMS — not in `huskarl-core`, which defines only the traits and the
wrappers that compose them.

JWKS verification also needs a
[`JwsVerifierPlatform`](crate::crypto::verifier::JwsVerifierPlatform) to turn
public JWK data into working verifiers. This lets the same key-fetching logic
use native cryptography or WebCrypto. Signing and encryption instead receive
keys that already carry their backend, such as a local key or KMS handle.

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
[`select_encryptor`](crate::crypto::cipher::AeadEncryptorSelector::select_encryptor)
the encryptor. [`KeyMatchStrength`](crate::crypto::KeyMatchStrength) plays no part
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
[`JwsVerifier`](crate::crypto::verifier::JwsVerifier) directly. Each verification
uses one key snapshot. A later call can use a new snapshot without rebuilding
the consumer.

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
[`AeadEncryptorSelector`](crate::crypto::cipher::AeadEncryptorSelector) work the
same way.

The relation is deliberately one-way: you hold a *selector* and get an
encryptor, never the reverse. Even a fixed key is a selector — it hands out its
shared inner [`AeadEncryptor`](crate::crypto::cipher::AeadEncryptor) — so
there is no wrapper for lifting a bare encryptor into selection, which would
silently freeze anything rotating beneath it.

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
  [`ScheduledRefreshSigner`](crate::crypto::signer::ScheduledRefreshSigner), and
  [`ScheduledRefreshCipher`](crate::crypto::cipher::ScheduledRefreshCipher)
  attempt a reload on use after a TTL. One caller waits for the reload while
  concurrent callers use the existing snapshot. Minimum refresh intervals and
  failure backoff limit attempts. A successful reload replaces the whole keyset,
  including removing retired keys.

  **The TTL is a refresh trigger, not a maximum key age.** A failed reload keeps
  the previous keys available. Rate limiting and in-flight reloads can also
  extend their use beyond the TTL. Consequently, an upstream key removal takes
  effect only after a successful refresh is observed by the caller. Applications
  requiring a strict retirement deadline need an additional policy.

- **Warm start from a persisted cache.** A scheduled-refresh layer serves its
  factory's `Ok` value immediately, so a factory that falls back to a *trusted
  local cache* comes up **warm** — able to verify at once — even when the
  authorization server is unreachable at boot, then picks up live keys on the
  next TTL refresh. This is distinct from
  [`JwksStartup::SeedEmpty`](crate::jwk::JwksStartup::SeedEmpty), which comes up
  *cold* and returns
  [`KeysUnavailable`](crate::crypto::verifier::VerifyError::KeysUnavailable)
  until a live fetch lands. Persist each successful fetch so the cache tracks key
  rotations rather than a stale bake-in; with no live fetch *and* no cache (a
  first-ever offline boot) the build still fails — you genuinely have no keys.

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
  a same-algorithm, kid-less rotation — is handled after a successful scheduled
  reload instead. So the two layers split the work: **misses
  here handle additions; the TTL there handles removals and the kid-less edge.**
  Retrying is inbound-only — there is no outbound miss, since the caller selects
  the key.

## How a stack fits together

A typical verifier for an authorization server's JWKS reads, from the outside
in: an optional metrics wrapper, around a retrying verifier (reload-and-retry on
an unknown `kid`), around a scheduled-refresh verifier (a cached snapshot
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

For an explicit signing-key rotation, call
[`refresh`](crate::crypto::signer::RefreshableSigner::refresh) to request an
immediate reload instead of waiting for a scheduled attempt.

## Sealing: self-contained bundles

The [`cipher`](crate::crypto::cipher) traits are the flexible base: they expose
the AEAD operation in its `(nonce, ciphertext, tag)` parts, which is exactly what
a scheme like JWE needs — it places each part in its own header/segment. Most
callers, though, don't want to manage those parts; they just need to encrypt a
value, store or send it, and decrypt it later. [`seal`](crate::crypto::seal) is
that convenience layer, built *on* `cipher`: it packs the parts into one opaque,
self-contained bundle. The trade is deliberate — the bundle framing is
huskarl's own, so sealing is the wrong tool for JWE (whose framing is fixed by
spec); reach past it to the `cipher` traits there.

Sealing suits values that must travel on their own — encrypted cookies, stateless
tokens — where the nonce and tag must be carried alongside the ciphertext.
[`AeadSealer`](crate::crypto::seal::AeadSealer) and
[`AeadUnsealer`](crate::crypto::seal::AeadUnsealer) describe that operation:
sealing packs one opaque byte string, unsealing re-opens it.
[`AeadV1Sealer`](crate::crypto::seal::AeadV1Sealer) is the local
implementation, framing an AEAD operation as a versioned, self-describing bundle
(`[0x01 || nonce_len || tag_len || nonce || ciphertext || tag]`) over any inner
key stack. Its impls are capability-conditional: an
[`AeadEncryptorSelector`](crate::crypto::cipher::AeadEncryptorSelector) inside
yields a sealer; an [`AeadDecryptor`](crate::crypto::cipher::AeadDecryptor) — a
retired rotation key that can still open old bundles, say — yields an unsealer;
and an inner with both, an [`AeadCipher`](crate::crypto::cipher::AeadCipher),
yields an [`AeadSealerUnsealer`](crate::crypto::seal::AeadSealerUnsealer), the
combined trait that erases to one `Arc<dyn AeadSealerUnsealer>` carrying both
directions.

Sealing is an **outbound** operation, but unlike signing it needs no separate
selector trait: each [`seal`](crate::crypto::seal::AeadSealer::seal) selects
one frozen encryptor snapshot internally and runs the whole encrypt-then-frame
sequence against it, so a rotation cannot land between choosing the key and
using it — the read-header-then-sign hazard, closed off inside the one call.
Key identity crosses the seam as a value: `seal` returns the bundle together
with the `kid` of the key that sealed it, read off that same frozen snapshot,
and [`unseal`](crate::crypto::seal::AeadUnsealer::unseal) takes it back for
direct key dispatch. Stored beside the bundle, the kid makes "which key
protects this record" a metadata query; discarded, a multi-key unsealer tries
its candidates, and the AEAD tag makes a wrong key a clean authentication
failure, never a wrong plaintext. A kid only selects a key — an untrusted
value can at worst cause a miss — and the bundle itself stays kid-free.

Because a raw key is already a selector, `AeadV1Sealer::new(key)` is the whole
fixed-key story. For a rotating key, put a
[`ScheduledRefreshCipher`](crate::crypto::cipher::ScheduledRefreshCipher) (or
[`RefreshableCipher`](crate::crypto::cipher::RefreshableCipher)) inside instead,
and the stale key is reloaded during each seal's internal selection, bounding
how quickly a rotated-in key is discovered. A resource server uses this to issue
and check stateless `DPoP` nonces: seal the issue time into a bundle, hand it
out, and unseal it later to verify its age without server-side storage.

For such a long-lived seal key — a nonce or session-cookie key with no natural
rotation trigger — prefer XChaCha20-Poly1305 (the native `XChaChaKey`, `XC20P`):
its 192-bit nonce is wide enough that random selection stays collision-free at
any practical volume, so rotation is a key-lifetime choice, not a nonce-budget
obligation as it is under AES-GCM's 96-bit nonce. Fall back to AES-GCM only
when the sealer must also run on WebCrypto, which has no ChaCha primitive.

The sealer traits are also a *boundary*, not just a framing: they are where
encryption can be delegated wholesale to an external service. A KMS- or
Vault-style encrypt endpoint returns one opaque, self-describing token — there
is no nonce/ciphertext/tag decomposition to expose, so such a service cannot
implement [`AeadEncryptor`](crate::crypto::cipher::AeadEncryptor) at all — but
it implements [`AeadSealer`](crate::crypto::seal::AeadSealer) /
[`AeadUnsealer`](crate::crypto::seal::AeadUnsealer) naturally, handling
rotation on its own side. It reports whatever key identity its service does —
a KMS response often names the exact key version — or `None`; its tokens name
their key internally either way, so unsealing may ignore the hint. Consumers
bound on the sealer traits accept either world unchanged.

## The three operations, compared

|                        | Signing                                     | Verification                                 | Encryption / decryption                                        |
|------------------------|---------------------------------------------|----------------------------------------------|----------------------------------------------------------------|
| Direction              | outbound                                    | inbound                                      | both, on one key family                                        |
| Base trait             | `JwsSigner`                                 | `JwsVerifier`                                | `AeadEncryptor` / `AeadDecryptor`; `AeadCipher` for both       |
| Key chosen by          | caller, via `JwsSignerSelector`             | the token, via `key_match`                   | caller via `AeadEncryptorSelector`; bundle via `cipher_match`  |
| Hot-swap wrapper is    | the *selector*, never a `JwsSigner`         | the operation itself                         | the selector outbound; the operation inbound                   |
| Miss reaction          | none — no outbound miss exists              | `RetryingVerifier`: refresh, retry once      | `RetryingDecryptor`: same, inbound only                        |
| Ambiguous key match    | n/a — default key, or by thumbprint         | fails closed: wrong-key acceptance is a risk | try-all is safe: the AEAD tag self-authenticates               |
| Materialisation seam   | none — keys are handed in                   | `JwsVerifierPlatform`, keys arrive as a JWKS | none — keys are handed in                                      |
| Extra layer            | by-thumbprint selection (`DPoP`'s `dpop_jkt`) | —                                          | sealing: self-contained bundles, external sealers              |
