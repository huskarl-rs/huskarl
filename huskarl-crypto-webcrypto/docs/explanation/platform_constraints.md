# Platform constraints (parity with `huskarl-crypto-native`)

This crate implements the same `huskarl-core` traits as
[`huskarl-crypto-native`](https://docs.rs/huskarl-crypto-native), but code
written against the native backend does not always port directly. The
differences are `WebCrypto` (`SubtleCrypto`) platform constraints, not
omissions:

| Capability | native | webcrypto |
|---|---|---|
| Generate a signing key | ✔ (sync) | ✔ (`async`) |
| **Import** a signing key (PKCS#8 / private JWK) | ✔ | ✘ — keys are generated non-extractable; there is no `from_secret`/`from_jwk` on the signer |
| Import a *public* verify key (JWK / JWKS) | ✔ | ✔ (`async`) |
| Symmetric JWS (HMAC, e.g. `HS256` / `client_secret_jwt`) | ✔ (`SymmetricKey`) | ✘ — no symmetric signing module |
| AES-GCM AEAD from key material | ✔ | ✔ (plus [`from_crypto_key`](crate::aead::AesGcmKey::from_crypto_key) for an existing `CryptoKey`) |
| Sign / verify / import calls | sync | `async` (`SubtleCrypto`) |

## Consequences

Because signing keys are generated non-extractable and never leave
`SubtleCrypto`, a wasm client authenticates with `private_key_jwt` only via a key
**generated in-browser** and registered by its public JWK. This also suits
`DPoP`, where an ephemeral per-session key is the normal deployment. Two things
follow:

- A pre-provisioned private key cannot be loaded — there is no signer-side
  `from_secret`/`from_jwk`.
- `client_secret_jwt` is unavailable, because there is no symmetric (HMAC)
  signing module.

All crypto operations are `async` because `SubtleCrypto` is async: signing,
verification, and key import all return futures.
