# Loading a signing key

A [`PrivateKey`](crate::asymmetric::signer::PrivateKey) signs JWTs. This guide
covers the ways to get one, from the recommended path outward. For *why* the API
is shaped around JWKs, see [why JWK is the native
format](crate::_docs::explanation::jwk_as_key_format).

## Recommended: store a JWK

A JWK is self-describing — it carries its own algorithm and key id — so loading
one needs no extra arguments. Serialize your key to a JWK once, keep the JSON in
your secret manager, and load it by composing the
[`JwkJson`](huskarl_core::jwk::JwkJson) decoder onto the secret:

```rust
use huskarl_core::prelude::*; // brings `Secret::mapped` into scope
use huskarl_core::{jwk::JwkJson, secrets::{ProvidedSecret, SecretString}};
use huskarl_crypto_native::asymmetric::signer::PrivateKey;

# async fn example(jwk_json: SecretString) -> Result<(), huskarl_core::error::Error> {
// `jwk_json` is a JWK with its own `alg` and `kid` — here from a value already
// in hand; in practice it is your secret manager's provider.
let secret = ProvidedSecret::new(jwk_json);
let key = PrivateKey::from_secret(secret.mapped(JwkJson)).await?;
# let _ = key;
# Ok(())
# }
```

The `kid` comes from the JWK, so the key you sign with and the public JWK you
publish always agree.

## Generate a fresh key

For a key created in-process, pass the algorithm and an optional `kid`:

```rust
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

# fn example() -> Result<(), huskarl_core::error::Error> {
let key = PrivateKey::generate(GenerateAlgorithm::Es256, Some("key-1".to_string()))?;
# let _ = key;
# Ok(())
# }
```

## From a JWK you already parsed

If you already hold key material — for example from deserialized
configuration — skip the secret machinery. `from_jwk` takes the
[`AsymmetricPrivateJwk`](huskarl_core::jwk::AsymmetricPrivateJwk) variant
directly; a [`PrivateJwk`](huskarl_core::jwk::PrivateJwk) (which may hold
either an asymmetric or a symmetric key) converts with `try_into()`:

```rust
use huskarl_core::jwk::PrivateJwk;
use huskarl_crypto_native::asymmetric::signer::PrivateKey;

# fn example(jwk: PrivateJwk) -> Result<(), huskarl_core::error::Error> {
let key = PrivateKey::from_jwk(jwk.try_into()?)?;
# let _ = key;
# Ok(())
# }
```

## If you only have PKCS#8

`openssl` and most tooling produce PKCS#8 PEM or DER, which carry no `kid` and do
not pin the JWS algorithm (an RSA key could be `RS256` or `PS256`). You have two
options.

### Convert once, at setup (preferred)

Convert to a JWK with
[`pkcs8_pem`](crate::asymmetric::signer::pkcs8_pem) or
[`pkcs8_der`](crate::asymmetric::signer::pkcs8_der), supplying the algorithm and
a `kid`, then store the resulting JWK and load it as above. This keeps the
runtime path on the blessed, backend-independent `JwkJson` decoder:

```rust
use huskarl_crypto_native::asymmetric::signer::{pkcs8_pem, AsymmetricAlgorithm};

# fn example(pem: &str) -> Result<(), huskarl_core::error::Error> {
let jwk = pkcs8_pem(pem, AsymmetricAlgorithm::Es256, Some("key-1"))?;
// Serialize `jwk` (it is `Into<huskarl_core::jwk::Jwk>`, which is `Serialize`)
// and store the JSON in your secret manager.
# let _ = jwk;
# Ok(())
# }
```

### Load PKCS#8 from a secret at runtime

If you must keep PKCS#8 in your secret store, compose the matching decoder
([`Pkcs8Pem`](crate::asymmetric::signer::Pkcs8Pem) /
[`Pkcs8Der`](crate::asymmetric::signer::Pkcs8Der)) onto the secret instead:

```rust
use huskarl_core::prelude::*; // brings `Secret::mapped` into scope
use huskarl_core::secrets::{ProvidedSecret, SecretString};
use huskarl_crypto_native::asymmetric::signer::{
    AsymmetricAlgorithm, Pkcs8Pem, PrivateKey,
};

# async fn example(pem: ProvidedSecret<SecretString>) -> Result<(), huskarl_core::error::Error> {
let key = PrivateKey::from_secret(
    pem.mapped(Pkcs8Pem::new(AsymmetricAlgorithm::Es256)),
)
.await?;
# let _ = key;
# Ok(())
# }
```

PKCS#8 has no `kid`, so stamp one with
[`with_kid`](crate::asymmetric::signer::Pkcs8Pem::with_kid); otherwise the
secret's identity fills it, and failing that the key has none.

## Symmetric (HMAC) keys go through the same funnel

An HS256/384/512 key is loaded exactly like the asymmetric ones — same
`from_secret`, same decoders, same `kid` precedence. A JWK-JSON secret goes
through [`JwkJson`](huskarl_core::jwk::JwkJson) unchanged; raw key bytes take
[`OctBytes`](huskarl_core::jwk::OctBytes), which — like the PKCS#8 decoders —
stamps the algorithm the bare bytes cannot carry:

```rust
use huskarl_core::prelude::*; // brings `Secret::mapped` into scope
use huskarl_core::{jwk::OctBytes, secrets::{ProvidedSecret, SecretBytes}};
use huskarl_crypto_native::symmetric::SymmetricKey;

# async fn example(raw: ProvidedSecret<SecretBytes>) -> Result<(), huskarl_core::error::Error> {
let key = SymmetricKey::from_secret(raw.mapped(OctBytes::new("HS256"))).await?;
# let _ = key;
# Ok(())
# }
```

The AEAD ciphers load the same way: [`AesGcmKey`](crate::aead::AesGcmKey) with
an `A128GCM`/`A192GCM`/`A256GCM` algorithm label matching its key length,
[`XChaChaKey`](crate::aead::XChaChaKey) with `XC20P` and a 32-byte key.
