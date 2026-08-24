//! JWKS fetching for asymmetric Cloud KMS keys.

use bon::bon;
use google_cloud_kms_v1::client::KeyManagementService;
use huskarl_core::RetryAdvice;
use huskarl_core::jwk::PublicJwks;
use snafu::prelude::*;

use huskarl_core::jwk;

use crate::kid::VersionKid;

use super::signer::{
    PublicKeyParseError, get_jwe_algorithm, get_jws_algorithm, parse_public_key_pem,
};

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
///   .key_name("projects/p/locations/l/keyRings/r/cryptoKeys/k")
///   .kms_client(kms_client)
///   .build();
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
                    let alg = get_jwe_algorithm(&version.algorithm)?;
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
