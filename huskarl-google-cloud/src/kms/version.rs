//! Shared version resolution logic for Cloud KMS keys.

use std::time::{Duration, SystemTime};

use google_cloud_kms_v1::{client::KeyManagementService, model::CryptoKeyVersion};
use huskarl_core::RetryAdvice;
use snafu::prelude::*;

/// Extract the trailing version ID segment from a resource name.
///
/// For `"…/cryptoKeyVersions/42"` this returns `"42"`.
#[must_use]
pub fn version_id_from_resource_name(resource_name: &str) -> &str {
    // `rsplit('/').next()` always returns `Some`; if there is no '/' the
    // whole string is returned, which is fine — KMS will reject it if invalid.
    resource_name.rsplit('/').next().unwrap_or(resource_name)
}

/// An error returned while resolving a Cloud KMS key version.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum VersionResolutionError {
    /// Failed to retrieve the crypto key metadata.
    GetCryptoKey {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// Failed to list crypto key versions.
    ListCryptoKeyVersions {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// No enabled crypto key versions were found.
    NoEnabledCryptoKeyVersions,
    /// The name reported by KMS did not follow the required format.
    InvalidKeyVersionName,
    /// The version label was not found on the crypto key.
    VersionLabelNotFound {
        /// The label that was not found.
        label: String,
    },
}

impl VersionResolutionError {
    /// Returns advice about retrying the failed operation.
    ///
    /// If the service supplied a minimum delay in the RPC's `RetryInfo` detail,
    /// the returned [`RetryAdvice`] preserves it.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            Self::GetCryptoKey { source } | Self::ListCryptoKeyVersions { source } => {
                crate::retry::advice(source)
            }
            Self::NoEnabledCryptoKeyVersions
            | Self::InvalidKeyVersionName
            | Self::VersionLabelNotFound { .. } => RetryAdvice::No,
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

/// Strategy for selecting which key version to use.
///
/// The choice matters for encryption and signing, which pin a single version —
/// see [key versions and
/// rotation](crate::_docs::explanation::versions_and_rotation) for picking one
/// safely under rotation.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum VersionStrategy {
    /// Use a specific version ID.
    Specific(String),
    /// Use the latest enabled version.
    ///
    /// For encryption this is the riskiest choice: a newly created version is
    /// used as soon as the encryptor reloads, which can outrun decryptors on
    /// other servers (see [key versions and
    /// rotation](crate::_docs::explanation::versions_and_rotation)). Signing
    /// has a similar propagation window when verifiers cache their keys.
    #[default]
    Latest,
    /// Use the version indicated by a label on the `CryptoKey`.
    ///
    /// The label's value is interpreted as the version ID. Promoting the label
    /// only after every consumer has loaded the new version makes this a
    /// rotation-safe choice for encryption (see [key versions and
    /// rotation](crate::_docs::explanation::versions_and_rotation)).
    ByLabel(String),
    /// Use the newest enabled version whose `create_time` is at least
    /// `min_age` in the past.
    ///
    /// This is useful during key rotation: a newly created version is skipped
    /// until it has had time to propagate or be validated. If no
    /// version meets the age threshold (for example, when the only version is
    /// new), the newest enabled version is used as a fallback.
    MinAge(Duration),
}

/// Resolves a version ID from a key name using the given strategy.
///
/// # Errors
///
/// Returns an error if the version could not be resolved from KMS.
pub async fn resolve_version(
    key_name: &str,
    strategy: &VersionStrategy,
    kms_client: &KeyManagementService,
) -> Result<String, VersionResolutionError> {
    match strategy {
        VersionStrategy::Specific(version) => Ok(version.clone()),
        VersionStrategy::Latest => resolve_latest_version(key_name, kms_client).await,
        VersionStrategy::ByLabel(label) => {
            resolve_version_by_label(key_name, kms_client, label).await
        }
        VersionStrategy::MinAge(min_age) => {
            resolve_min_age_version(key_name, kms_client, min_age).await
        }
    }
}

async fn resolve_latest_version(
    key_name: &str,
    kms_client: &KeyManagementService,
) -> Result<String, VersionResolutionError> {
    kms_client
        .list_crypto_key_versions()
        .set_parent(key_name)
        .set_page_size(1)
        .set_filter("state=ENABLED")
        .set_order_by("name desc")
        .send()
        .await
        .context(ListCryptoKeyVersionsSnafu)?
        .crypto_key_versions
        .into_iter()
        .next()
        .ok_or(NoEnabledCryptoKeyVersionsSnafu.build())?
        .name
        .rsplit('/')
        .next()
        .ok_or(InvalidKeyVersionNameSnafu.build())
        .map(String::from)
}

async fn resolve_min_age_version(
    key_name: &str,
    kms_client: &KeyManagementService,
    min_age: &Duration,
) -> Result<String, VersionResolutionError> {
    let versions = list_enabled_kms_versions(kms_client, key_name, None, Some("name desc"))
        .await
        .context(ListCryptoKeyVersionsSnafu)?;

    ensure!(!versions.is_empty(), NoEnabledCryptoKeyVersionsSnafu);

    Ok(select_min_age_id(&versions, min_age).to_string())
}

/// Fetches all enabled `CryptoKeyVersion`s for `key_name`, handling pagination.
///
/// Returns the raw API error on failure; callers should `.context(…)` it into
/// their own error type.
pub(crate) async fn list_enabled_kms_versions(
    kms_client: &KeyManagementService,
    key_name: &str,
    max_versions: Option<usize>,
    order_by: Option<&str>,
) -> Result<Vec<CryptoKeyVersion>, google_cloud_kms_v1::Error> {
    let mut all = Vec::new();
    let mut page_token = String::new();

    loop {
        let remaining = max_versions.map(|m| m.saturating_sub(all.len()));
        if remaining == Some(0) {
            break;
        }

        let mut request = kms_client
            .list_crypto_key_versions()
            .set_parent(key_name)
            .set_filter("state=ENABLED");

        if let Some(order) = order_by {
            request = request.set_order_by(order);
        }

        if let Some(n) = remaining {
            request = request.set_page_size(i32::try_from(n).unwrap_or(i32::MAX));
        }

        if !page_token.is_empty() {
            request = request.set_page_token(&page_token);
        }

        let response = request.send().await?;
        all.extend(response.crypto_key_versions);

        if response.next_page_token.is_empty() || max_versions.is_some_and(|m| all.len() >= m) {
            break;
        }
        page_token = response.next_page_token;
    }

    Ok(all)
}

/// Selects a version ID from a list in newest-first order using the
/// [`VersionStrategy::MinAge`] strategy.
///
/// Returns the newest version whose `create_time` is at least `min_age` in
/// the past, falling back to the newest version if none meet the threshold.
pub(crate) fn select_min_age_id<'a>(
    versions: &'a [CryptoKeyVersion],
    min_age: &Duration,
) -> &'a str {
    let cutoff = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default() // only fails if the system clock is before the Unix epoch
        .as_secs()
        .cast_signed()
        - min_age.as_secs().cast_signed();

    let chosen = versions
        .iter()
        .find(|v| {
            v.create_time
                .as_ref()
                .is_some_and(|ct| ct.seconds() <= cutoff)
        })
        // Fall back to the newest version if none meet the threshold.
        .unwrap_or(&versions[0]);

    version_id_from_resource_name(&chosen.name)
}

async fn resolve_version_by_label(
    key_name: &str,
    kms_client: &KeyManagementService,
    label: &str,
) -> Result<String, VersionResolutionError> {
    let crypto_key = kms_client
        .get_crypto_key()
        .set_name(key_name)
        .send()
        .await
        .context(GetCryptoKeySnafu)?;

    crypto_key
        .labels
        .get(label)
        .cloned()
        .context(VersionLabelNotFoundSnafu { label })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::time::UNIX_EPOCH;

    use google_cloud_wkt::Timestamp;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/42",
        "42"
    )]
    #[case("projects/p/.../cryptoKeyVersions/primary", "primary")]
    #[case("1", "1")]
    #[case("", "")]
    fn version_id_from_resource_name_extracts_trailing_segment(
        #[case] resource_name: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(version_id_from_resource_name(resource_name), expected);
    }

    fn now_secs() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    /// Builds a newest-first list of versions, each with a `create_time` at the
    /// given age (in seconds) before now.
    fn versions(ages_secs: &[(&str, i64)]) -> Vec<CryptoKeyVersion> {
        let now = now_secs();
        ages_secs
            .iter()
            .map(|(name, age)| {
                CryptoKeyVersion::default()
                    .set_name(*name)
                    .set_create_time(Timestamp::clamp(now - age, 0))
            })
            .collect()
    }

    #[test]
    fn select_min_age_picks_newest_version_past_the_threshold() {
        // Newest first: v3 is 10 seconds old (too new), v2 is 100 seconds old,
        // and v1 is 1,000 seconds old.
        let vs = versions(&[
            (".../cryptoKeyVersions/3", 10),
            (".../cryptoKeyVersions/2", 100),
            (".../cryptoKeyVersions/1", 1000),
        ]);
        // With a 60-second minimum age, v3 is skipped and v2 is the newest
        // version old enough to qualify.
        assert_eq!(select_min_age_id(&vs, &Duration::from_secs(60)), "2");
    }

    #[test]
    fn select_min_age_falls_back_to_newest_when_none_old_enough() {
        let vs = versions(&[
            (".../cryptoKeyVersions/3", 5),
            (".../cryptoKeyVersions/2", 10),
        ]);
        // No version is 3,600 seconds old, so fall back to the newest version,
        // which appears first.
        assert_eq!(select_min_age_id(&vs, &Duration::from_secs(3600)), "3");
    }

    #[test]
    fn select_min_age_ignores_versions_without_create_time() {
        let now = now_secs();
        let vs = vec![
            // Newest, but no create_time — not eligible for the age check.
            CryptoKeyVersion::default().set_name(".../cryptoKeyVersions/3"),
            CryptoKeyVersion::default()
                .set_name(".../cryptoKeyVersions/2")
                .set_create_time(Timestamp::clamp(now - 1000, 0)),
        ];
        assert_eq!(select_min_age_id(&vs, &Duration::from_secs(60)), "2");
    }
}
