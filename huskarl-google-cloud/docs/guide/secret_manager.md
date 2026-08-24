# Reading secrets from Secret Manager

The `secretmanager` module exposes a Google Cloud Secret Manager secret as a
[`huskarl` secret source](huskarl_core::secrets::Secret) — a lazily-fetched
value for any construct that consumes secret material. The module provides a
single-version source for ordinary secrets and a multi-version source for
rotated keys.

## A single secret version

[`SecretVersionBytes`](crate::secretmanager::SecretVersionBytes) fetches one
version as raw bytes. [`SecretVersion::string`](crate::secretmanager::SecretVersion::string)
wraps it to decode the value as UTF-8 text, trimming surrounding whitespace.
Both fetch on every access, so add caching if needed. The `resource_name` is a
fully qualified secret version name, and the `latest` alias
is accepted:

```rust,no_run
use google_cloud_secretmanager_v1::client::SecretManagerService;
use huskarl_core::secrets::Secret;
use huskarl_google_cloud::secretmanager::{SecretVersion, SecretVersionBytes};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = SecretManagerService::builder().build().await?;

// Raw bytes — no decoding applied.
let raw = SecretVersionBytes::builder()
    .client(client.clone())
    .resource_name("projects/p/secrets/my-secret/versions/latest")
    .build();
let bytes = raw.get_secret_value().await?;

// UTF-8 text.
let text = SecretVersion::string(
    SecretVersionBytes::builder()
        .client(client)
        .resource_name("projects/p/secrets/my-secret/versions/latest")
        .build(),
);
let value = text.get_secret_value().await?;
# let _ = (bytes, value);
# Ok(())
# }
```

Each fetched value carries an `identity` derived from its secret version via
[`VersionKid`](crate::kid::VersionKid), which becomes the `kid` when the value
feeds a signer or cipher. Secret Manager sources default to
[`verbatim()`](crate::kid::VersionKid::verbatim) — the version segment is used
as-is. See [key IDs](crate::_docs::explanation::key_ids).

## Rotating a key across versions

[`SecretVersions`](crate::secretmanager::SecretVersions) is the multi-version
source. It exposes a **primary** version through a caller-controlled alias and
**all** enabled versions. Repoint the alias to promote a new key.
[`all`](crate::secretmanager::SecretVersions::all) returns a validated
[`ActiveSecretVersions`](crate::secretmanager::ActiveSecretVersions) view in
which the primary is guaranteed to appear in the enabled set. This prevents the
caller from constructing an encryptor whose key is absent from its decryptors.

Feed the primary to an encryptor and every enabled version to a
[`MultiKeyDecryptor`](huskarl_core::crypto::cipher::MultiKeyDecryptor). Here the
opaque key bytes become in-process AES-GCM keys through `AesGcmKey` from
`huskarl-crypto-native`, each identified by its version:

```rust,no_run
use std::sync::Arc;

use google_cloud_secretmanager_v1::client::SecretManagerService;
use huskarl_core::crypto::cipher::{AeadDecryptor, MultiKeyDecryptor};
use huskarl_core::jwk::OctBytes;
use huskarl_core::secrets::Secret;
use huskarl_crypto_native::aead::AesGcmKey;
use huskarl_google_cloud::secretmanager::SecretVersions;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = SecretManagerService::builder().build().await?;

let secret = SecretVersions::builder()
    .client(client)
    .secret_name("projects/p/secrets/my-aes-key")
    .primary_alias("active")
    .build();

// One validated view: `primary` is confirmed present in `all`.
let active = secret.all().await?;

// Encrypt with the primary version — its `kid` is the secret version.
let encryptor =
    AesGcmKey::from_secret(active.primary.clone().mapped(OctBytes::new("A256GCM"))).await?;

// Decrypt across every enabled version, routed by `kid` during rotation.
let mut decryptors: Vec<Arc<dyn AeadDecryptor>> = Vec::new();
for version in &active.all {
    decryptors.push(Arc::new(
        AesGcmKey::from_secret(version.clone().mapped(OctBytes::new("A256GCM"))).await?,
    ));
}
let decryptor = MultiKeyDecryptor::new(decryptors);
# let _ = (encryptor, decryptor);
# Ok(())
# }
```

Rotate by adding a new version, waiting for every consumer to load it (they
reload their `all` set on refresh), then repointing the `active` alias — the same
add → wait → promote order as [KMS
rotation](crate::_docs::explanation::versions_and_rotation). Rebuild the snapshot
on a schedule with a
[`ScheduledRefreshCipher`](huskarl_core::crypto::cipher::ScheduledRefreshCipher);
[`all`](crate::secretmanager::SecretVersions::all) is the typical factory body.
See the [self-refreshing keys guide](crate::_docs::guide::refreshing_keys).

> If the stored value is itself a JWK document, its own `kid` and `alg` take
> precedence over the version-derived identity, so you can store fully formed
> JWKs and keep their intended key IDs.
