# How signing fits together

JWT construction can stay the same whether the signing key is local, loaded
from a secret store, or held in Google Cloud KMS. A
[`JwsSignerSelector`](crate::crypto::signer::JwsSignerSelector) chooses a key
for one operation; the resulting [`JwsSigner`](crate::crypto::signer::JwsSigner)
provides its algorithm and key ID and produces the signature.

## One signing operation, different key sources

This function works with a fixed key or a selector that reloads keys:

```rust
use huskarl_core::{
    Error,
    crypto::signer::JwsSignerSelector,
    jwt::Jwt,
    secrets::SecretString,
};
use std::time::Duration;

async fn issue_token(selector: &impl JwsSignerSelector) -> Result<SecretString, Error> {
    let signer = selector.select_signer().await;
    let jwt = Jwt::builder()
        .iss("https://issuer.example")
        .sub("user-123")
        .audience("https://api.example")
        .issued_now_expires_after(Duration::from_secs(300))
        .claims(serde_json::json!({ "scope": "read" }))
        .build();

    jwt.to_jws_compact(signer.as_ref()).await
}
```

The configuration determines what selection and signing do:

| Configuration | What selection returns | Where signing happens |
| --- | --- | --- |
| Fixed native `PrivateKey` | The same key each time | Locally |
| Reloadable key from a file or secret store | A snapshot of the currently loaded key | Locally, using the retrieved private material |
| Reloadable KMS `SigningKey` | A handle pinned to the resolved KMS key version | In KMS; private material stays there |

The native and KMS key types implement the selector interface as well as
providing signers. A fixed key therefore needs no refresh wrapper. The
[native loading guide](https://github.com/huskarl-rs/huskarl/blob/main/huskarl-crypto-native/docs/guide/loading_a_signing_key.md)
shows fixed and reloadable local keys; the
[KMS refresh guide](https://github.com/huskarl-rs/huskarl/blob/main/huskarl-google-cloud/docs/guide/refreshing_keys.md)
shows the corresponding remote configuration.

## Reloading replaces future selections

A refresh wrapper takes an asynchronous factory that constructs a selector.
For a local key, that factory reads a file or secret, decodes its key material,
and constructs a native signer. For KMS, it rebuilds a key handle, resolving
the version according to the configured version strategy. It does not download
the private key or create a new KMS key version.

The factory runs at construction and again on refresh. A successful refresh
swaps in the new selector for future selections. Reading a secret once does
not subscribe to later changes: the factory must read it again, and the
secret source's own caching or version pinning can affect what it returns.

[`RefreshableSigner`](crate::crypto::signer::RefreshableSigner) lets the
application request reloads explicitly.
[`ScheduledRefreshSigner`](crate::crypto::signer::ScheduledRefreshSigner)
attempts a reload during selection after a TTL, subject to rate limits and
failure backoff. It starts no background task. One caller waits for a reload
while concurrent callers can select from the existing snapshot. Failed
reloads retain the previous selector; the TTL is not a maximum key age.

## Why selection returns a stable signer

Signing has two connected steps: construct the protected header from the
signer's `alg` and optional `kid`, then sign that header and the payload.
Both must use the same key. If reloading changed the key between those steps,
the header could identify one key while another produced the signature.

The selected signer keeps its identity throughout the operation, even if its
selector is refreshed concurrently. Select once per signing operation and use
that signer for the whole operation. Keeping it across unrelated operations
would keep using the old selection after rotation. For KMS, stable identity
means a pinned version; disabling that version can still cause signing to fail.

## Default selection, key IDs, and thumbprints

These identifiers and selection methods serve different purposes:

| Mechanism | Purpose |
| --- | --- |
| `select_signer()` | Choose the current default for a new signing operation. |
| The signer's `kid` | Put an assigned identifier in the JWT header so a verifier can match a key. |
| `select_signer_by_thumbprint(...)` | Choose the exact asymmetric key required by an existing key binding. |

The signing traits have no select-by-`kid` method. On verification, `alg` and
optional `kid` guide key matching. A `kid` is an assigned name; a JWK thumbprint
is derived from public key material and is independent of that name.

DPoP makes the distinction concrete. After rotation, new bindings can use the
new default key, but proofs for tokens already bound to the old key must still
use that key. [`MultiKeySigner`](crate::crypto::signer::MultiKeySigner) can keep
the new default alongside older signers:

```rust
use std::sync::Arc;
use huskarl_core::crypto::signer::{
    AsymmetricJwsSigner, AsymmetricJwsSignerSelector, JwsSignerSelector, MultiKeySigner,
};

# async fn example(new_key: Arc<dyn AsymmetricJwsSigner>, old_key: Arc<dyn AsymmetricJwsSigner>, bound_thumbprint: &str) {
let keys = MultiKeySigner::new(new_key, vec![old_key]);
let current = keys.select_signer().await;
let bound = keys.select_signer_by_thumbprint(bound_thumbprint).await;
# }
```

`bound` is `None` if that key is unavailable. Substituting the default would
break the binding. Reloading a multi-key selector must retain any old keys
still needed for existing bindings; the refresh wrapper does not preserve
them automatically. Huskarl's DPoP implementation performs thumbprint
selection when a binding is supplied.

## Publishing verification keys is separate

Changing the default signer does not ensure verifiers have its public key.
Coordinate publication and activation so verifiers can obtain the new key,
and retain the old public key for as long as previously issued tokens should
remain verifiable. Retaining an old private key for DPoP proofs is a separate
need from retaining its public key for verification.

For the lower-level wrapper design, see
[composing crypto strategies](crate::_docs::explanation::crypto_strategies).
For the other side of the operation, see
[how verification fits together](crate::_docs::explanation::verification).
