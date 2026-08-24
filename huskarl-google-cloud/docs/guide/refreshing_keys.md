# Keeping keys fresh under rotation

Keys in this crate resolve their versions [once, at build
time](crate::_docs::explanation::versions_and_rotation), and remain pinned to
them. To pick up a rotated version, rebuild the key. The `huskarl-core` refresh
wrappers do this on a schedule: you supply a **factory** closure, and the wrapper
runs it on refresh before swapping in the new key atomically.

## A self-refreshing AEAD cipher

Wrap a [`CipherKey`](crate::kms::symmetric::cipher::CipherKey) in a
[`ScheduledRefreshCipher`](huskarl_core::crypto::cipher::ScheduledRefreshCipher).
The factory re-resolves the version on each reload; map the build error into a
[`huskarl_core::Error`](huskarl_core::Error) (see
[error handling](crate::_docs::explanation::error_handling)):

```rust,no_run
use std::pin::Pin;

use google_cloud_kms_v1::client::KeyManagementService;
use huskarl_core::crypto::cipher::ScheduledRefreshCipher;
use huskarl_core::platform::MaybeSendFuture;
use huskarl_core::Error;
use huskarl_google_cloud::kms::{VersionStrategy, symmetric::cipher::CipherKey};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let kms_client = KeyManagementService::builder().build().await?;
let key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k";

// The factory rebuilds the key on every refresh, re-resolving the version.
let factory = move || -> Pin<Box<dyn MaybeSendFuture<Output = Result<CipherKey, Error>>>> {
    let kms_client = kms_client.clone();
    let key_name = key_name.to_owned();
    Box::pin(async move {
        CipherKey::builder()
            .key_name(key_name)
            .kms_client(kms_client)
            // Encrypt only with the label-pinned version, which you promote
            // *after* the new version has propagated to all decryptors.
            .strategy(VersionStrategy::ByLabel("active".into()))
            .build()
            .await
            .map_err(Error::from)
    })
};

// Refreshes are gated by a TTL (1 hour by default); decryption spans all
// enabled versions, so retired keys keep decrypting until disabled.
let cipher = ScheduledRefreshCipher::builder().factory(factory).build().await?;
# let _ = cipher;
# Ok(())
# }
```

## A self-refreshing signer

The same shape works for signing: build a
[`SigningKey`](crate::kms::asymmetric::signer::SigningKey) in the factory and
wrap it in a
[`ScheduledRefreshSigner`](huskarl_core::crypto::signer::ScheduledRefreshSigner).
Selecting a signer reloads the key if it has outlived the TTL, then hands back a
frozen snapshot to sign with — there is no "refresh before you sign" step to
forget:

```rust,no_run
use std::pin::Pin;

use google_cloud_kms_v1::client::KeyManagementService;
use huskarl_core::crypto::signer::{JwsSignerSelector, ScheduledRefreshSigner};
use huskarl_core::platform::MaybeSendFuture;
use huskarl_core::Error;
use huskarl_google_cloud::kms::asymmetric::signer::SigningKey;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let kms_client = KeyManagementService::builder().build().await?;
let key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k";

let factory = move || -> Pin<Box<dyn MaybeSendFuture<Output = Result<SigningKey, Error>>>> {
    let kms_client = kms_client.clone();
    let key_name = key_name.to_owned();
    Box::pin(async move {
        SigningKey::builder()
            .key_name(key_name)
            .kms_client(kms_client)
            .build()
            .await
            .map_err(Error::from)
    })
};

let signer = ScheduledRefreshSigner::builder().factory(factory).build().await?;
let current = signer.select_signer().await;
# let _ = current;
# Ok(())
# }
```

## Refreshing on an unknown key as well as on a timer

A scheduled refresh reloads according to a TTL. This is enough when new versions
appear predictably, but a newly rotated key is not loaded until the next refresh.
Layer a
[`RetryingDecryptor`](huskarl_core::crypto::cipher::RetryingDecryptor) or
[`RetryingVerifier`](huskarl_core::crypto::verifier::RetryingVerifier) on top and
a refresh is *also* triggered on demand: when the layer sees a ciphertext or JWS
whose key it does not yet hold, it forces a reload and retries, so a token signed
by a brand-new version verifies without waiting for the timer.

The lower-level
[`RefreshableCipher`](huskarl_core::crypto::cipher::RefreshableCipher) /
[`RefreshableSigner`](huskarl_core::crypto::signer::RefreshableSigner) expose the
same rebuild-and-swap mechanism without TTL scheduling if you want to drive
refreshes yourself.

See [key versions and rotation](crate::_docs::explanation::versions_and_rotation)
for why decryption and verification tolerate rotation the moment they refresh,
and why the encryption strategy is critical.
