//! JWKS fetching for asymmetric Cloud KMS keys.

use bon::bon;
use google_cloud_kms_v1::client::KeyManagementService;
use huskarl_core::{RetryAdvice, jwk, jwk::PublicJwks};
use snafu::prelude::*;

use super::signer::{
    PublicKeyParseError, get_jwe_algorithm, get_jws_algorithm, parse_public_key_pem,
};
use crate::{kid::VersionKid, retry::RpcDiagnostics as _};

/// Fetches the public keys for all enabled versions of a Cloud KMS
/// `CryptoKey` as a [`PublicJwks`].
///
/// This type does not cache the result; callers can add caching as needed.
///
/// # Examples
///
/// ```rust,no_run
/// use google_cloud_kms_v1::client::KeyManagementService;
/// use huskarl_google_cloud::kms::asymmetric::jwks::Jwks;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + 'static>> {
/// let kms_client = KeyManagementService::builder().build().await?;
/// let jwks = Jwks::builder()
///     .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
///     .kms_client(kms_client)
///     .build();
///
/// let public_jwks = jwks.fetch().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Jwks {
    kms_client: KeyManagementService,
    key_name: String,
    kid: VersionKid,
    max_versions: Option<usize>,
}

impl std::fmt::Debug for Jwks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jwks")
            .field("key_name", &self.key_name)
            .finish_non_exhaustive()
    }
}

#[bon]
impl Jwks {
    /// Creates a `Jwks` from a Cloud KMS crypto key resource name.
    ///
    /// Captures configuration only — no I/O happens here (unlike the signer
    /// builders); call [`fetch`](Self::fetch) to retrieve the public keys.
    #[builder(finish_fn = build)]
    pub fn builder(
        /// The full resource name of the crypto key.
        #[builder(into)]
        key_name: String,
        /// The KMS client used for operations.
        kms_client: KeyManagementService,
        /// The policy for deriving a `kid` from the key version ID. Defaults to
        /// [`VersionKid::none()`] (no `kid`).
        #[builder(default = VersionKid::none())]
        kid: VersionKid,
        /// Maximum number of enabled versions to include in the JWKS.
        ///
        /// When set, at most this many versions are fetched, in newest-first
        /// order. The API `page_size` is set to this value, so listing requires
        /// only one request when the number of enabled versions is within the
        /// limit. Retrieving each public key still requires a separate request.
        ///
        /// When unset, all enabled versions are fetched (may require multiple
        /// paged requests).
        max_versions: Option<usize>,
    ) -> Self {
        Self {
            kms_client,
            key_name,
            kid,
            max_versions,
        }
    }

    /// Fetches the public keys of all enabled versions as a [`PublicJwks`].
    ///
    /// Lists all enabled `CryptoKeyVersion`s for the configured key,
    /// retrieves each version's public key, and parses it into a
    /// [`PublicJwk`](huskarl_core::jwk::PublicJwk).
    ///
    /// Versions with unsupported algorithms are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if listing versions fails, retrieving a public key
    /// fails, or no enabled versions are found.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "huskarl.gcp.kms.jwks", level = "debug", skip_all)
    )]
    pub async fn fetch(&self) -> Result<PublicJwks, JwksError> {
        let versions = self.list_enabled_versions().await?;

        ensure!(!versions.is_empty(), NoEnabledCryptoKeyVersionsSnafu);

        let futures: Vec<_> = versions
            .iter()
            .filter_map(|version| {
                let (algorithm, key_use) = if let Some(alg) = get_jws_algorithm(&version.algorithm)
                {
                    (alg, jwk::KeyUse::Sign)
                } else {
                    let Some(alg) = get_jwe_algorithm(&version.algorithm) else {
                        #[cfg(feature = "tracing")]
                        tracing::trace!(
                            version = crate::diagnostics::version_id(&version.name),
                            decision = "skip_version",
                            reason = "unsupported_algorithm",
                            "Skipping KMS version for JWKS"
                        );
                        return None;
                    };
                    (alg, jwk::KeyUse::Encrypt)
                };
                let version_id =
                    super::super::version::version_id_from_resource_name(&version.name);
                let kid = self.kid.derive(version_id);
                let name = &version.name;
                let kms_client = &self.kms_client;

                Some(async move {
                    let public_key_response = kms_client
                        .get_public_key()
                        .set_name(name)
                        .send()
                        .await
                        .observe_rpc("get_public_key")
                        .inspect(crate::diagnostics::public_key)
                        .context(GetPublicKeySnafu)?;

                    parse_public_key_pem(
                        &public_key_response.pem,
                        algorithm,
                        kid.as_deref(),
                        key_use,
                    )
                    .context(PublicKeyParseSnafu)
                })
            })
            .collect();

        let keys = futures_util::future::try_join_all(futures).await?;

        #[cfg(feature = "tracing")]
        tracing::trace!(
            api_versions = versions.len(),
            keys = keys.len(),
            "Converted KMS versions to JWKS"
        );
        Ok(PublicJwks::new(keys))
    }

    async fn list_enabled_versions(
        &self,
    ) -> Result<Vec<google_cloud_kms_v1::model::CryptoKeyVersion>, JwksError> {
        super::super::version::list_enabled_kms_versions(
            &self.kms_client,
            &self.key_name,
            self.max_versions,
            None,
        )
        .await
        .context(ListCryptoKeyVersionsSnafu)
    }
}

/// An error returned while fetching a JWKS from Cloud KMS.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum JwksError {
    /// Failed to list crypto key versions.
    ListCryptoKeyVersions {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// Failed to retrieve a public key from KMS.
    GetPublicKey {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// A public key PEM could not be parsed into a JWK.
    PublicKeyParse {
        /// The underlying parse error.
        source: PublicKeyParseError,
    },
    /// No enabled crypto key versions were found.
    NoEnabledCryptoKeyVersions,
}

impl JwksError {
    /// Returns advice about retrying the failed operation.
    ///
    /// If the service supplied a minimum delay in the RPC's `RetryInfo` detail,
    /// the returned [`RetryAdvice`] preserves it.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            JwksError::ListCryptoKeyVersions { source } | JwksError::GetPublicKey { source } => {
                crate::retry::advice(source)
            }
            JwksError::PublicKeyParse { .. } | JwksError::NoEnabledCryptoKeyVersions => {
                RetryAdvice::No
            }
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

#[cfg(all(test, feature = "tracing"))]
#[allow(clippy::unwrap_used)]
mod tracing_tests {
    use google_cloud_gax::{options::RequestOptions, response::Response};
    use google_cloud_kms_v1::{
        model::{
            CryptoKeyVersion, ListCryptoKeyVersionsRequest, ListCryptoKeyVersionsResponse,
            crypto_key_version::{CryptoKeyVersionAlgorithm, CryptoKeyVersionState},
        },
        stub::KeyManagementService as KmsStub,
    };

    use super::*;

    const KEY: &str = "projects/p/locations/l/keyRings/r/cryptoKeys/k";

    #[derive(Debug, Clone)]
    struct PagedKms;

    impl KmsStub for PagedKms {
        fn list_crypto_key_versions(
            &self,
            req: ListCryptoKeyVersionsRequest,
            _: RequestOptions,
        ) -> impl Future<Output = google_cloud_gax::Result<Response<ListCryptoKeyVersionsResponse>>> + Send
        {
            assert_eq!(req.parent, KEY);
            assert_eq!(req.filter, "state=ENABLED");
            let first = req.page_token.is_empty();
            if !first {
                assert_eq!(req.page_token, "private-page-token");
            }
            let version = CryptoKeyVersion::default()
                .set_name(format!(
                    "{KEY}/cryptoKeyVersions/{}",
                    if first { 2 } else { 1 }
                ))
                .set_state(CryptoKeyVersionState::Enabled)
                .set_algorithm(CryptoKeyVersionAlgorithm::HmacSha256);
            let response = ListCryptoKeyVersionsResponse::default()
                .set_crypto_key_versions([version])
                .set_next_page_token(if first { "private-page-token" } else { "" });
            async move { Ok(Response::from(response)) }
        }
    }

    #[tokio::test]
    async fn api_versions_are_visible_before_unsupported_keys_are_filtered() {
        let source = Jwks::builder()
            .key_name(KEY)
            .kms_client(KeyManagementService::from_stub(PagedKms))
            .build();
        let (result, text) =
            crate::test_tracing::capture_with_api(source.fetch(), tracing::Level::TRACE, true)
                .await;
        result.unwrap();
        assert_eq!(text.matches("KMS API version page").count(), 2, "{text}");
        for version in [1, 2] {
            assert!(text.contains(&format!("version=\"{version}\"")), "{text}");
        }
        assert!(text.contains("HMAC_SHA256"), "{text}");
        assert!(text.contains("ENABLED"), "{text}");
        assert_eq!(
            text.matches("decision=\"skip_version\"").count(),
            2,
            "{text}"
        );
        assert_eq!(
            text.matches("reason=\"unsupported_algorithm\"").count(),
            2,
            "{text}"
        );
        assert!(
            text.find("KMS API version").unwrap() < text.find("unsupported_algorithm").unwrap()
        );
        assert!(text.contains("api_versions=2 keys=0"), "{text}");
        assert!(!text.contains("private-page-token"), "{text}");
        assert!(!text.contains(KEY), "{text}");
        let (result, ordinary) =
            crate::test_tracing::capture(source.fetch(), tracing::Level::TRACE).await;
        result.unwrap();
        assert!(ordinary.contains("KMS API version page"), "{ordinary}");
        assert!(
            ordinary.contains("Converted KMS versions to JWKS"),
            "{ordinary}"
        );
        assert!(
            !ordinary.contains("huskarl_google_cloud::api"),
            "{ordinary}"
        );
        assert!(!ordinary.contains("HMAC_SHA256"), "{ordinary}");
    }
}
