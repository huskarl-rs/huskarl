use bon::Builder;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use huskarl_core::{
    RetryAdvice,
    secrets::{Secret, SecretBytes, SecretOutput},
};
use snafu::prelude::*;

use super::SecretVersionBytes;
use crate::kid::VersionKid;

/// An error returned while resolving or listing secret versions.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SecretVersionsError {
    /// Failed to retrieve the secret version metadata.
    GetSecretVersion {
        /// The underlying error from the Secret Manager API.
        source: google_cloud_secretmanager_v1::Error,
    },
    /// Failed to list secret versions.
    ListSecretVersions {
        /// The underlying error from the Secret Manager API.
        source: google_cloud_secretmanager_v1::Error,
    },
    /// No enabled secret versions were found.
    NoEnabledSecretVersions,
    /// The primary version is not among the enabled versions.
    ///
    /// This can occur if the version referenced by the primary alias is
    /// disabled or does not exist.
    PrimaryVersionNotFound,
}

impl SecretVersionsError {
    /// Returns advice about retrying the failed operation.
    ///
    /// If the service supplied a minimum delay in the RPC's `RetryInfo` detail,
    /// the returned [`RetryAdvice`] preserves it.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            Self::GetSecretVersion { source } | Self::ListSecretVersions { source } => {
                crate::retry::advice(source)
            }
            Self::NoEnabledSecretVersions | Self::PrimaryVersionNotFound => RetryAdvice::No,
        }
    }

    /// Returns `true` if retrying the failed operation may help.
    ///
    /// This is a coarse view of [`retry_advice`](Self::retry_advice) that
    /// discards any minimum retry delay supplied by the service.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        !matches!(self.retry_advice(), RetryAdvice::No)
    }
}

/// The resolved secret versions returned by [`SecretVersions::all`].
///
/// Versions are exposed as raw [`SecretVersionBytes`] sources — the common
/// rotation use case is opaque key material. Decode per-version with
/// [`SecretVersion::string`](super::SecretVersion::string) or
/// [`Secret::mapped`] if you need typed
/// output.
///
/// `primary` is guaranteed to be present in `all`.
pub struct ActiveSecretVersions {
    /// The version identified by the configured primary alias.
    /// Use this for encryption.
    pub primary: SecretVersionBytes,
    /// All enabled versions, including `primary`. Use this alongside
    /// a caller-supplied cipher factory to build a
    /// [`MultiKeyDecryptor`](huskarl_core::crypto::cipher::MultiKeyDecryptor)
    /// so that data encrypted with any enabled version can be decrypted
    /// during key rotation.
    pub all: Vec<SecretVersionBytes>,
}

impl ActiveSecretVersions {
    /// Fetches the secret values for the primary version and all enabled
    /// versions concurrently.
    ///
    /// Returns `(primary_value, all_values)`, where `all_values` is aligned
    /// positionally with [`all`](Self::all); `primary_value` is one of its entries.
    ///
    /// # Errors
    ///
    /// Returns an error if any secret value fetch fails.
    pub async fn get_all_values(
        &self,
    ) -> Result<(SecretOutput<SecretBytes>, Vec<SecretOutput<SecretBytes>>), huskarl_core::Error>
    {
        futures_util::future::try_join(
            self.primary.get_secret_value(),
            futures_util::future::try_join_all(
                self.all
                    .iter()
                    .map(huskarl_core::secrets::Secret::get_secret_value),
            ),
        )
        .await
    }
}

/// A multi-version source for a Google Cloud Secret Manager secret.
///
/// Provides access to both a designated primary version (via a configured
/// alias) and all enabled versions of the secret. Intended for use with
/// key rotation: the primary alias is updated externally to promote a new
/// key after it has propagated to all consumers.
///
/// This type does not cache results; callers choose when to refresh it.
///
/// Rotate by adding a version, waiting for consumers to load it via
/// [`all`](Self::all) into a
/// [`MultiKeyDecryptor`](huskarl_core::crypto::cipher::MultiKeyDecryptor), then
/// repointing the primary alias. See the [Secret Manager
/// guide](crate::_docs::guide::secret_manager) and [key versions and
/// rotation](crate::_docs::explanation::versions_and_rotation).
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_secretmanager_v1::client::SecretManagerService;
/// use huskarl_google_cloud::secretmanager::SecretVersions;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = SecretManagerService::builder().build().await?;
/// let sv = SecretVersions::builder()
///     .client(client)
///     .secret_name("projects/p/secrets/my-aes-key")
///     .primary_alias("active")
///     .build();
///
/// // Validated view: primary confirmed present in all enabled versions.
/// let active = sv.all().await?;
/// let (primary_val, all_vals) = active.get_all_values().await?;
/// // `primary_val.value.expose_secret()` is the raw key material; feed
/// // primary_val and all_vals to a caller-supplied cipher factory.
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Builder)]
pub struct SecretVersions {
    /// The Secret Manager client used for operations.
    client: SecretManagerService,
    /// The secret resource name (for example, `projects/p/secrets/my-key`).
    #[builder(into)]
    secret_name: String,
    /// The version alias used to identify the primary version (for example,
    /// `"active"` or `"current"`).
    #[builder(into)]
    primary_alias: String,
    /// The policy for deriving each version's `identity` (and therefore its
    /// `kid`) from the secret version. Defaults to [`VersionKid::verbatim()`]
    /// and applies uniformly to the primary and every enabled version.
    #[builder(default = VersionKid::verbatim())]
    kid: VersionKid,
    /// Maximum number of enabled versions to return from [`all`](SecretVersions::all)
    /// and [`get_secrets`](SecretVersions::get_secrets).
    ///
    /// When set, at most this many versions are fetched, in newest-first order.
    /// The API `page_size` is set to this value, so listing requires only one
    /// request when the number of enabled versions is within the limit.
    ///
    /// When unset, all enabled versions are fetched (may require multiple
    /// paged requests).
    max_versions: Option<usize>,
}

impl SecretVersions {
    /// Returns a handle to the primary secret version.
    ///
    /// This is a synchronous operation — it constructs a [`SecretVersionBytes`]
    /// pointing at `{secret_name}/versions/{primary_alias}` without making
    /// any API calls. The secret value is fetched lazily when
    /// [`get_secret_value`](huskarl_core::secrets::Secret::get_secret_value)
    /// is called on the returned handle.
    #[must_use]
    pub fn get_primary_secret(&self) -> SecretVersionBytes {
        SecretVersionBytes::builder()
            .client(self.client.clone())
            .resource_name(format!(
                "{}/versions/{}",
                self.secret_name, self.primary_alias
            ))
            .kid(self.kid.clone())
            .build()
    }

    /// Returns handles to all enabled versions of the secret.
    ///
    /// Lists all versions with state `ENABLED` and returns a
    /// [`SecretVersionBytes`] handle for each. Handles are returned newest-first
    /// (Secret Manager's default ordering). Values are fetched lazily — no
    /// secret data is retrieved until
    /// [`get_secret_value`](huskarl_core::secrets::Secret::get_secret_value)
    /// is called on a handle.
    ///
    /// # Errors
    ///
    /// Returns an error if listing fails or no enabled versions are found.
    pub async fn get_secrets(&self) -> Result<Vec<SecretVersionBytes>, SecretVersionsError> {
        let versions = self.list_enabled_versions().await?;

        ensure!(!versions.is_empty(), NoEnabledSecretVersionsSnafu);

        Ok(versions
            .into_iter()
            .map(|v| {
                SecretVersionBytes::builder()
                    .client(self.client.clone())
                    .resource_name(v.name)
                    .kid(self.kid.clone())
                    .build()
            })
            .collect())
    }

    /// Resolves the primary alias and lists all enabled versions, returning a
    /// validated [`ActiveSecretVersions`] view.
    ///
    /// Resolves the primary alias to a concrete version, lists all enabled
    /// versions, and confirms the primary is present. The returned
    /// [`ActiveSecretVersions::primary`] is guaranteed to be present in
    /// [`ActiveSecretVersions::all`], allowing callers to build an encryptor
    /// whose key is also present in the corresponding decryptor set.
    ///
    /// This is a typical factory operation for a scheduled refresh wrapper.
    ///
    /// # Errors
    ///
    /// Returns an error if resolving the primary alias fails, listing fails,
    /// no enabled versions are found, or the primary version is not among
    /// the enabled versions.
    pub async fn all(&self) -> Result<ActiveSecretVersions, SecretVersionsError> {
        let primary_alias_resource =
            format!("{}/versions/{}", self.secret_name, self.primary_alias);

        // Resolve the alias and list all enabled versions concurrently.
        let (primary_meta, raw) = futures_util::try_join!(
            async {
                self.client
                    .get_secret_version()
                    .set_name(&primary_alias_resource)
                    .send()
                    .await
                    .context(GetSecretVersionSnafu)
            },
            self.list_enabled_versions(),
        )?;

        let primary_name = primary_meta.name;
        ensure!(!raw.is_empty(), NoEnabledSecretVersionsSnafu);

        // Build handles, tracking the primary by matching its resolved name.
        let mut primary_opt: Option<SecretVersionBytes> = None;
        let all: Vec<SecretVersionBytes> = raw
            .into_iter()
            .map(|v| {
                let handle = SecretVersionBytes::builder()
                    .client(self.client.clone())
                    .resource_name(v.name.clone())
                    .kid(self.kid.clone())
                    .build();
                if v.name == primary_name {
                    primary_opt = Some(handle.clone());
                }
                handle
            })
            .collect();

        let primary = primary_opt.ok_or_else(|| PrimaryVersionNotFoundSnafu.build())?;

        Ok(ActiveSecretVersions { primary, all })
    }

    async fn list_enabled_versions(
        &self,
    ) -> Result<Vec<google_cloud_secretmanager_v1::model::SecretVersion>, SecretVersionsError> {
        let mut all_versions = Vec::new();
        let mut page_token = String::new();

        loop {
            let remaining = self
                .max_versions
                .map(|m| m.saturating_sub(all_versions.len()));
            if remaining == Some(0) {
                break;
            }

            let mut request = self
                .client
                .list_secret_versions()
                .set_parent(&self.secret_name)
                .set_filter("state=ENABLED");

            if let Some(n) = remaining {
                request = request.set_page_size(i32::try_from(n).unwrap_or(i32::MAX));
            }

            if !page_token.is_empty() {
                request = request.set_page_token(&page_token);
            }

            let response = request.send().await.context(ListSecretVersionsSnafu)?;

            all_versions.extend(response.versions);

            if response.next_page_token.is_empty()
                || self.max_versions.is_some_and(|m| all_versions.len() >= m)
            {
                break;
            }
            page_token = response.next_page_token;
        }

        Ok(all_versions)
    }
}

/// End-to-end composition tests: the multi-version byte sources must plug into
/// the standard local-key funnel (`AesGcmKey`/`SymmetricKey` via `OctBytes`),
/// deriving each key's `kid` from its secret version, and route correctly
/// through the multi-key aggregators during rotation.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod crypto_composition {
    use std::{collections::BTreeMap, future::Future, sync::Arc};

    use google_cloud_gax::{Result as GaxResult, options::RequestOptions, response::Response};
    use google_cloud_secretmanager_v1::{
        model::{
            AccessSecretVersionRequest, AccessSecretVersionResponse, GetSecretVersionRequest,
            ListSecretVersionsRequest, ListSecretVersionsResponse, SecretPayload,
            SecretVersion as SecretVersionModel,
        },
        stub::SecretManagerService as SmStub,
    };
    use huskarl_core::{
        crypto::{
            cipher::{
                AeadDecryptor, AeadEncryptor, AeadEncryptorSelector, CipherMatch, MultiKeyDecryptor,
            },
            signer::{JwsSigner, JwsSignerSelector},
            verifier::{JwsVerifier, KeyMatch, MultiKeyVerifier},
        },
        jwk::{JwkJson, OctBytes},
        secrets::{Secret, encodings::StringEncoding},
    };
    use huskarl_crypto_native::{aead::AesGcmKey, symmetric::SymmetricKey};

    use super::*;

    const SECRET: &str = "projects/p/secrets/s";

    fn version_name(v: &str) -> String {
        format!("{SECRET}/versions/{v}")
    }

    /// A Secret Manager stub backing a `SecretVersions`: resolves the primary
    /// alias, lists enabled versions newest-first, and serves per-version key
    /// bytes keyed by resource name.
    #[derive(Debug, Clone)]
    struct MockVersions {
        /// The full version name the primary alias resolves to.
        primary_name: String,
        /// Enabled version names, newest-first.
        order: Vec<String>,
        /// Version name -> key material.
        keys: BTreeMap<String, Vec<u8>>,
    }

    impl SmStub for MockVersions {
        fn list_secret_versions(
            &self,
            _req: ListSecretVersionsRequest,
            _options: RequestOptions,
        ) -> impl Future<Output = GaxResult<Response<ListSecretVersionsResponse>>> + Send {
            let versions: Vec<SecretVersionModel> = self
                .order
                .iter()
                .map(|n| SecretVersionModel::default().set_name(n.clone()))
                .collect();
            let resp = ListSecretVersionsResponse::default().set_versions(versions);
            async move { Ok(Response::from(resp)) }
        }

        fn get_secret_version(
            &self,
            _req: GetSecretVersionRequest,
            _options: RequestOptions,
        ) -> impl Future<Output = GaxResult<Response<SecretVersionModel>>> + Send {
            let resp = SecretVersionModel::default().set_name(self.primary_name.clone());
            async move { Ok(Response::from(resp)) }
        }

        fn access_secret_version(
            &self,
            req: AccessSecretVersionRequest,
            _options: RequestOptions,
        ) -> impl Future<Output = GaxResult<Response<AccessSecretVersionResponse>>> + Send {
            let name = req.name;
            let data = self.keys.get(&name).cloned().unwrap_or_default();
            let resp = AccessSecretVersionResponse::default()
                .set_name(name)
                .set_payload(SecretPayload::default().set_data(data));
            async move { Ok(Response::from(resp)) }
        }
    }

    fn secret_versions(mock: MockVersions) -> SecretVersions {
        SecretVersions::builder()
            .client(SecretManagerService::from_stub(mock))
            .secret_name(SECRET)
            .primary_alias("active")
            .build()
    }

    /// A cipher built from the primary version derives its `kid` from that
    /// version, and a `MultiKeyDecryptor` spanning all enabled versions
    /// decrypts the primary's output when selected by that `kid`.
    #[tokio::test]
    async fn ciphers_derive_kid_from_version_and_roundtrip_across_rotation() {
        let mock = MockVersions {
            primary_name: version_name("3"),
            order: vec![version_name("3"), version_name("2")],
            keys: BTreeMap::from([
                (version_name("3"), vec![3u8; 32]),
                (version_name("2"), vec![2u8; 32]),
            ]),
        };
        let active = secret_versions(mock).all().await.unwrap();

        // The encryptor's `kid` is derived from the primary version.
        let enc = AesGcmKey::from_secret(active.primary.clone().mapped(OctBytes::new("A256GCM")))
            .await
            .unwrap()
            .select_encryptor()
            .await;
        assert_eq!(enc.key_id().as_deref(), Some("3"));

        // The decryptor spans every enabled version, each identified by its
        // version.
        let mut decryptors: Vec<Arc<dyn AeadDecryptor>> = Vec::new();
        for v in &active.all {
            let key: Arc<dyn AeadDecryptor> = Arc::new(
                AesGcmKey::from_secret(v.clone().mapped(OctBytes::new("A256GCM")))
                    .await
                    .unwrap(),
            );
            decryptors.push(key);
        }
        let multi = MultiKeyDecryptor::new(decryptors);

        // Encrypt with the primary, then route decryption through the multi-key
        // set using the `kid`.
        let plaintext = b"rotate me";
        let aad = b"session-context";
        let out = enc.encrypt(plaintext, aad).await.unwrap();
        let recovered = multi
            .decrypt(
                Some(&CipherMatch::builder().kid("3").build()),
                &out.nonce,
                &out.ciphertext,
                &out.tag,
                aad,
            )
            .await
            .unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// A verifier built from each version derives its `kid` from that version,
    /// and a `MultiKeyVerifier` selects the correct key by `kid` to verify a
    /// signature made with a non-primary version.
    #[tokio::test]
    async fn verifiers_derive_kid_from_version_and_select_by_kid() {
        let mock = MockVersions {
            primary_name: version_name("3"),
            order: vec![version_name("3"), version_name("2")],
            keys: BTreeMap::from([
                (version_name("3"), vec![9u8; 32]),
                (version_name("2"), vec![8u8; 32]),
            ]),
        };
        let active = secret_versions(mock).all().await.unwrap();

        // Sign with *non-primary* version 2 to exercise `kid`-based routing.
        let v2 = active
            .all
            .iter()
            .find(|v| v.resource_name().ends_with("/versions/2"))
            .unwrap();
        let signer = SymmetricKey::from_secret(v2.clone().mapped(OctBytes::new("HS256")))
            .await
            .unwrap()
            .select_signer()
            .await;
        assert_eq!(signer.key_id().as_deref(), Some("2"));

        // The verifier spans every enabled version.
        let mut verifiers: Vec<Arc<dyn JwsVerifier>> = Vec::new();
        for v in &active.all {
            let key: Arc<dyn JwsVerifier> = Arc::new(
                SymmetricKey::from_secret(v.clone().mapped(OctBytes::new("HS256")))
                    .await
                    .unwrap(),
            );
            verifiers.push(key);
        }
        let multi = MultiKeyVerifier::new(verifiers);

        let input = b"protected.payload";
        let signature = signer.sign(input).await.unwrap();
        multi
            .verify(
                input,
                &signature,
                &KeyMatch::builder().alg("HS256").kid("2").build(),
            )
            .await
            .unwrap();
    }

    /// When the secret *is* a JWK JSON document, its own `kid` and `alg` win —
    /// the version-derived identity is only a fallback (`with_kid_fallback`), so
    /// a JWK carrying its own `kid` is not overwritten by the secret version.
    #[tokio::test]
    async fn jwk_json_secret_uses_the_jwks_own_kid_and_alg() {
        // Store a complete JWK document at version 5. Its `kid` is
        // "jwk-sym-1", not "5".
        let jwk_json = br#"{"kty":"oct","alg":"HS256","kid":"jwk-sym-1",
            "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
        let mock = MockVersions {
            primary_name: version_name("5"),
            order: vec![version_name("5")],
            keys: BTreeMap::from([(version_name("5"), jwk_json.to_vec())]),
        };
        let active = secret_versions(mock).all().await.unwrap();

        // Decode the bytes as UTF-8 JSON and parse the JWK while preserving the
        // version-derived identity ("5").
        let key = SymmetricKey::from_secret(
            active
                .primary
                .clone()
                .mapped(StringEncoding)
                .mapped(JwkJson),
        )
        .await
        .unwrap()
        .select_signer()
        .await;

        // The JWK's own `kid` and `alg` take precedence; version "5" does not
        // overwrite them.
        assert_eq!(key.key_id().as_deref(), Some("jwk-sym-1"));
        assert_eq!(key.jws_algorithm().as_ref(), "HS256");
    }
}
