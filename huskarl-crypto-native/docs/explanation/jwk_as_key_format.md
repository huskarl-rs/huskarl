# Why JWK is the native key format

A key can arrive in several encodings — a JWK, a PKCS#8 PEM file, raw PKCS#8
DER bytes, bare symmetric key bytes. huskarl treats the **JWK as the canonical
form** and funnels every other encoding through it. This page explains why,
and what follows from it.

## A JWK is self-describing

A JSON Web Key ([`PrivateJwk`](huskarl_core::jwk::PrivateJwk)) carries not just
the key material but its metadata: the algorithm (`alg`) and the key id
(`kid`). PKCS#8 does not — it encodes the key material and an algorithm *family*
OID, but not which JWS algorithm to use (an RSA key could sign with `RS256` or
`PS512`) and never a `kid`. Bare symmetric bytes carry nothing at all — 32
bytes could be an `HS256` signing key or an `A256GCM` cipher key.

That difference sets the shape of the API. Loading a JWK needs no extra
arguments; loading PKCS#8 or raw bytes makes you supply the algorithm, and a
`kid` if you want one.

## The `kid` lives in the key

Because the JWK carries the `kid`, a
[`PrivateKey`](crate::asymmetric::signer::PrivateKey) has exactly one source of
truth for it. The value that goes in a signature's `kid` header
([`JwsSigner::key_id`](huskarl_core::crypto::signer::JwsSigner::key_id)) and the
JWK you publish in a JWKS
([`as_private_jwk`](crate::asymmetric::signer::PrivateKey::as_private_jwk)) both
read it from the same place, so they cannot disagree — a verifier looking up
your key by `kid` will always find it. There is no separate `kid` argument to
pass to the accessor, and so none to accidentally mismatch.

## One funnel

Every load path ends at a [`PrivateJwk`](huskarl_core::jwk::PrivateJwk) — a sum
of [`Asymmetric`](huskarl_core::jwk::PrivateJwk::Asymmetric) and
[`Symmetric`](huskarl_core::jwk::PrivateJwk::Symmetric) key material — which a
`from_secret` loader finalizes:

```text
JWK JSON   ─ JwkJson   ┐              ┌─►  PrivateKey::from_secret
PKCS#8 PEM ─ Pkcs8Pem  ├─► PrivateJwk ┼─►  SymmetricKey::from_secret
PKCS#8 DER ─ Pkcs8Der  │              └─►  aead::from_secret
raw bytes  ─ OctBytes  ┘
```

For AEAD, [`aead::from_secret`](crate::aead::from_secret) dispatches on the
JWK's `alg` to an [`AesGcmKey`](crate::aead::AesGcmKey) or
[`XChaChaKey`](crate::aead::XChaChaKey); their own `from_secret` constructors
remain for binding to one cipher.

Decoders are chosen by **input format**, key types by what you need — each
funnel accepts the variant it can finalize and rejects the other with a
configuration error. The decoders are
[`SecretMap`](huskarl_core::secrets::SecretMap)s, so they compose onto any
secret source with [`mapped`](huskarl_core::secrets::Secret::mapped) and pass
its `identity` through — which is what lets a secret manager's version name
become the `kid` when the encoding carries none. The precedence is: an
explicit `kid` in the JWK wins, then the secret's identity, then none.

## Only PKCS#8 needs a backend

Turning PKCS#8 into a JWK derives the public half of the key from the private
material — curve arithmetic — so it lives in the crypto backend
([`pkcs8_der`](crate::asymmetric::signer::pkcs8_der) /
[`pkcs8_pem`](crate::asymmetric::signer::pkcs8_pem), which is why they can emit a
complete JWK even for an Ed25519 seed that stores no public key). Parsing a JWK
is pure JSON, and wrapping raw symmetric bytes is pure bookkeeping, so
[`JwkJson`](huskarl_core::jwk::JwkJson) and
[`OctBytes`](huskarl_core::jwk::OctBytes) live in `huskarl-core` and are shared
by every backend — the WebCrypto AES-GCM key loads through the identical
funnel. Store your keys as JWKs and the runtime load path never touches
backend-specific decoding at all — which is the case for
[loading a signing key](crate::_docs::guide::loading_a_signing_key).
