# Key IDs (`kid`)

When a verifier or decryptor spans several key versions, it needs a way to pick
the right one for an incoming JWS or ciphertext. That selector is the JWS/JWE
`kid` header. This crate derives the `kid` from a resource's **version
identifier** — the trailing segment of a Cloud KMS crypto key version resource
name or a Secret Manager secret version resource name (for example, `"3"`).
[`VersionKid`](crate::kid::VersionKid) defines this derivation consistently
across the crate.

## Three choices

- [`VersionKid::none()`](crate::kid::VersionKid::none) — derive no `kid`. Keys
  carry no key ID unless one is supplied another way (for example, a `kid`
  already present on a JWK).
- [`VersionKid::verbatim()`](crate::kid::VersionKid::verbatim) — use the version
  identifier as-is, so version `"3"` becomes `kid` `"3"`.
- [`VersionKid::map`](crate::kid::VersionKid::map) — transform the version into
  a `kid`, for example with `format!("my-key-v{version}")`.

```rust
use huskarl_google_cloud::kid::VersionKid;

let no_kid = VersionKid::none();
let version_as_kid = VersionKid::verbatim();
let prefixed = VersionKid::map(|version| format!("my-key-v{version}"));
# let _ = (no_kid, version_as_kid, prefixed);
```

## Why the two backends default differently

The available policies are the same everywhere; only the *default* differs to
match each backend's convention:

- **Cloud KMS keys default to [`none()`](crate::kid::VersionKid::none).** A bare
  KMS version number (`"1"`, `"2"`, …) is rarely unique or meaningful enough to
  be a useful `kid`. Callers can supply an explicit mapping when they need one.
- **Secret Manager sources default to
  [`verbatim()`](crate::kid::VersionKid::verbatim).** A secret version is a
  natural, stable `kid` during rotation, so passing it through unchanged is
  usually what you want.

## How the `kid` is used for selection

The version-derived `kid` is a *fallback* identity, not an override. When the
secret material is itself a JWK document that carries its own `kid` (and `alg`),
the explicit values take precedence; the version identity fills in only when
the material has none. This lets you store fully formed JWKs and keep their
intended key IDs, while opaque key bytes still get a sensible `kid` from their
version.

During rotation, a multi-key
[`MultiKeyVerifier`](huskarl_core::crypto::verifier::MultiKeyVerifier) or
[`MultiKeyDecryptor`](huskarl_core::crypto::cipher::MultiKeyDecryptor) matches
the incoming `kid` against each version's derived `kid` to route to the correct
key. This is why a stable, per-version `kid` matters. See
[key versions and rotation](crate::_docs::explanation::versions_and_rotation).
