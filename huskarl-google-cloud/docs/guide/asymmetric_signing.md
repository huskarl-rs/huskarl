# Signing JWS and serving JWKS with an asymmetric KMS key

An asymmetric Cloud KMS `CryptoKey` (an EC, RSA, or Ed25519 signing key) gives
you two halves of a JWS setup: a private signer that stays inside KMS, and the
public keys you publish so others can verify. This crate provides
[`SigningKey`](crate::kms::asymmetric::signer::SigningKey) for the first and
[`Jwks`](crate::kms::asymmetric::jwks::Jwks) for the second.

## Sign with the current version

[`SigningKey`](crate::kms::asymmetric::signer::SigningKey) resolves a primary
version via its [`VersionStrategy`](crate::kms::VersionStrategy) (defaulting to
[`Latest`](crate::kms::VersionStrategy::Latest)) and signs with it. It also
loads all enabled versions so it can select a signer by JWK thumbprint.
It implements [`JwsSignerSelector`](huskarl_core::crypto::signer::JwsSignerSelector),
so you can pass it to any `huskarl` construct that signs or use it directly:

```rust,no_run
use google_cloud_kms_v1::client::KeyManagementService;
use huskarl_core::crypto::signer::JwsSignerSelector;
use huskarl_google_cloud::kms::asymmetric::signer::SigningKey;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let kms_client = KeyManagementService::builder().build().await?;

let key = SigningKey::builder()
    .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
    .kms_client(kms_client)
    .build()
    .await?;

// Select the signer for the primary version and sign the JWS signing input.
let signer = key.select_signer().await;
let signature = signer.sign(b"protected.payload").await?;
# let _ = signature;
# Ok(())
# }
```

The algorithm is discovered from the key: EC P-256 and P-384 become `ES256` and
`ES384` (and KMS's DER signatures are converted to the fixed-width `r‖s` JWS
form), supported RSA algorithms become `RS256`, `RS512`, `PS256`, or `PS512`,
and Ed25519 becomes `Ed25519`. Set `use_fully_specified_jws_algorithm` to
`false` to use the deprecated `EdDSA` identifier instead.

## Serve the public keys as a JWKS

[`Jwks`](crate::kms::asymmetric::jwks::Jwks) fetches the public key for every
enabled version as a [`PublicJwks`](huskarl_core::jwk::PublicJwks), which a
resource server or verifier can consume. It does not cache the result. Add
caching around [`fetch`](crate::kms::asymmetric::jwks::Jwks::fetch) as needed,
and configure a
[`kid`](crate::kid::VersionKid) so verifiers can select a key by ID:

```rust,no_run
use google_cloud_kms_v1::client::KeyManagementService;
use huskarl_google_cloud::kid::VersionKid;
use huskarl_google_cloud::kms::asymmetric::jwks::Jwks;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let kms_client = KeyManagementService::builder().build().await?;

let jwks = Jwks::builder()
    .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
    .kms_client(kms_client)
    // Give each published key a stable `kid`; verifiers match it against the
    // JWS header. See the key-IDs explanation for the choices.
    .kid(VersionKid::map(|version| format!("kms-v{version}")))
    .build();

let public_jwks = jwks.fetch().await?;
# let _ = public_jwks;
# Ok(())
# }
```

The default `Latest` strategy starts signing with a new version as soon as the
signer reloads. Verifiers can accept that version after they refresh their
JWKS; stage promotion if signatures must remain verifiable throughout the
propagation window. See
[key versions and rotation](crate::_docs::explanation::versions_and_rotation),
[key IDs](crate::_docs::explanation::key_ids), and — to refresh the signer and
JWKS automatically — the
[self-refreshing keys guide](crate::_docs::guide::refreshing_keys).

> **Bounding the fetch.** Both builders accept `max_versions`. When set, at
> most that many enabled versions are loaded in newest-first order, and listing
> requires only one request when the versions fit within the limit. Retrieving
> each public key still requires a separate request. When unset, listing pages
> through all enabled versions.
