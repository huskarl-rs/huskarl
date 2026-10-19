//! Page summaries and separately filtered, allowlisted API metadata.

// Unknown textual values have no numeric value; unknown numeric values have no name.
#[cfg(feature = "tracing")]
fn api_enum_name(value: Option<i32>, name: Option<&str>) -> &str {
    value.and(name).unwrap_or("unknown")
}

#[cfg(feature = "tracing")]
pub(crate) fn version_id(resource: &str) -> &str {
    resource.rsplit('/').next().unwrap_or_default()
}

#[cfg(feature = "secretmanager")]
#[inline]
pub(crate) fn secret_access(
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    response: &google_cloud_secretmanager_v1::model::AccessSecretVersionResponse,
) {
    #[cfg(feature = "tracing")]
    {
        tracing::trace!(
            target: "huskarl_google_cloud::api",
            version = version_id(&response.name),
            payload_present = response.payload.is_some(),
            "Secret Manager API access response"
        );
    }
}

#[cfg(feature = "kms")]
#[inline]
pub(crate) fn kms_versions(
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    response: &google_cloud_kms_v1::model::ListCryptoKeyVersionsResponse,
) {
    #[cfg(feature = "tracing")]
    {
        tracing::trace!(
            count = response.crypto_key_versions.len(),
            has_more = !response.next_page_token.is_empty(),
            "KMS API version page"
        );
        if tracing::enabled!(target: "huskarl_google_cloud::api", tracing::Level::TRACE) {
            for version in &response.crypto_key_versions {
                // The timestamp type is from a transitive SDK dependency.
                #[allow(clippy::redundant_closure_for_method_calls)]
                let created_at_seconds = version.create_time.as_ref().map(|time| time.seconds());
                tracing::trace!(
                    target: "huskarl_google_cloud::api",
                    version = version_id(&version.name),
                    state = api_enum_name(version.state.value(), version.state.name()),
                    algorithm = api_enum_name(version.algorithm.value(), version.algorithm.name()),
                    created_at_seconds,
                    "KMS API version"
                );
            }
        }
    }
}

#[cfg(feature = "kms")]
#[inline]
pub(crate) fn crypto_key(
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    response: &google_cloud_kms_v1::model::CryptoKey,
) {
    #[cfg(feature = "tracing")]
    {
        tracing::trace!(
            target: "huskarl_google_cloud::api",
            purpose = api_enum_name(response.purpose.value(), response.purpose.name()),
            "KMS API key metadata"
        );
    }
}

#[cfg(feature = "secretmanager")]
#[inline]
pub(crate) fn secret_version(
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    response: &google_cloud_secretmanager_v1::model::SecretVersion,
) {
    #[cfg(feature = "tracing")]
    {
        tracing::trace!(
            target: "huskarl_google_cloud::api",
            version = version_id(&response.name),
            state = api_enum_name(response.state.value(), response.state.name()),
            "Secret Manager API resolved version"
        );
    }
}

#[cfg(feature = "secretmanager")]
#[inline]
pub(crate) fn secret_versions(
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    response: &google_cloud_secretmanager_v1::model::ListSecretVersionsResponse,
) {
    #[cfg(feature = "tracing")]
    {
        tracing::trace!(
            count = response.versions.len(),
            has_more = !response.next_page_token.is_empty(),
            "Secret Manager API version page"
        );
        if tracing::enabled!(target: "huskarl_google_cloud::api", tracing::Level::TRACE) {
            for version in &response.versions {
                tracing::trace!(
                    target: "huskarl_google_cloud::api",
                    version = version_id(&version.name),
                    state = api_enum_name(version.state.value(), version.state.name()),
                    "Secret Manager API version"
                );
            }
        }
    }
}

#[cfg(feature = "kms")]
#[inline]
pub(crate) fn kms_version(
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    response: &google_cloud_kms_v1::model::CryptoKeyVersion,
) {
    #[cfg(feature = "tracing")]
    {
        tracing::trace!(
            target: "huskarl_google_cloud::api",
            version = version_id(&response.name),
            algorithm = api_enum_name(response.algorithm.value(), response.algorithm.name()),
            state = api_enum_name(response.state.value(), response.state.name()),
            "KMS API key metadata"
        );
    }
}

#[cfg(feature = "kms")]
#[inline]
pub(crate) fn public_key(
    #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
    response: &google_cloud_kms_v1::model::PublicKey,
) {
    #[cfg(feature = "tracing")]
    {
        tracing::trace!(
            target: "huskarl_google_cloud::api",
            version = version_id(&response.name),
            algorithm = api_enum_name(response.algorithm.value(), response.algorithm.name()),
            "KMS API key metadata"
        );
    }
}

#[cfg(all(test, feature = "tracing", feature = "kms"))]
mod tests {
    use google_cloud_kms_v1::model::{
        CryptoKeyVersion, ListCryptoKeyVersionsResponse,
        crypto_key_version::CryptoKeyVersionAlgorithm,
    };

    #[tokio::test]
    async fn unknown_api_enum_names_are_not_copied_into_traces() {
        let response = ListCryptoKeyVersionsResponse::default().set_crypto_key_versions([
            CryptoKeyVersion::default()
                .set_name("projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/7")
                .set_algorithm(CryptoKeyVersionAlgorithm::from("private-unknown-algorithm")),
        ]);
        let ((), text) = crate::test_tracing::capture_with_api(
            async {
                super::kms_versions(&response);
            },
            tracing::Level::TRACE,
            true,
        )
        .await;
        assert!(text.contains("algorithm=\"unknown\""), "{text}");
        assert!(text.contains("version=\"7\""), "{text}");
        assert!(!text.contains("private-unknown-algorithm"), "{text}");
        assert!(!text.contains("projects/"), "{text}");
    }
}
