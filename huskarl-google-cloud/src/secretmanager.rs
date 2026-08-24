//! Secret sources backed by Google Cloud Secret Manager.
//!
//! [`SecretVersionBytes`] and [`SecretVersion`] read a single version;
//! [`SecretVersions`] exposes a primary version plus all enabled versions for
//! key rotation. See the [Secret Manager
//! guide](crate::_docs::guide::secret_manager).

use bon::Builder;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use huskarl_core::RetryAdvice;
use huskarl_core::platform::MaybeSendBoxFuture;
use huskarl_core::secrets::encodings::StringEncoding;
use huskarl_core::secrets::{MappedSecret, Secret, SecretBytes, SecretMap, SecretOutput};
use snafu::prelude::*;

use crate::kid::VersionKid;

pub use versions::ActiveSecretVersions;
pub use versions::SecretVersions;
pub use versions::SecretVersionsError;

mod versions;

/// An error returned while fetching a secret from Secret Manager.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SecretError {
    /// Secret Manager failed to return the secret value.
    AccessSecret {
        /// The underlying error from the Secret Manager API.
        source: google_cloud_secretmanager_v1::Error,
    },
    /// The response did not contain the required secret payload.
    ///
    /// This indicates an unexpected successful response from Secret Manager.
    MissingPayload,
}

impl SecretError {
    /// Returns advice about retrying the failed operation.
    ///
    /// If the service supplied a minimum delay in the RPC's `RetryInfo` detail,
    /// the returned [`RetryAdvice`] preserves it.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            Self::AccessSecret { source } => crate::retry::advice(source),
            Self::MissingPayload => RetryAdvice::No,
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

impl From<SecretError> for huskarl_core::Error {
    #[track_caller]
    fn from(err: SecretError) -> Self {
        huskarl_core::Error::new(err.retry_advice(), err)
    }
}

/// A raw byte source for a specific Secret Manager version.
///
/// This type implements `Secret<Output = SecretBytes>`. Fetch a value with
/// [`get_secret_value`](Secret::get_secret_value) and inspect it with
/// [`expose_secret`](SecretBytes::expose_secret). No decoding is applied. To
/// decode UTF-8 text, Base64, or hexadecimal data, wrap it in [`SecretVersion`]
/// or compose a [`SecretMap`] with
/// [`Secret::mapped`].
///
/// The `resource_name` should be the fully qualified secret version resource
/// name, such as `projects/p/secrets/s/versions/3`. The built-in `latest` alias
/// (`projects/p/secrets/s/versions/latest`) and any custom aliases are also
/// accepted.
///
/// # Usage
///
/// ```rust
/// # use huskarl_google_cloud::secretmanager::SecretVersionBytes;
/// # use google_cloud_secretmanager_v1::client::SecretManagerService;
/// # async fn setup(secret_manager: SecretManagerService) {
///     let bytes = SecretVersionBytes::builder()
///         .client(secret_manager)
///         .resource_name("projects/boogawooga/secrets/my-private-secret/versions/1")
///         .build();
/// # }
/// ```
#[derive(Debug, Clone, Builder)]
pub struct SecretVersionBytes {
    /// The Secret Manager client used for operations.
    client: SecretManagerService,
    /// The secret version resource name (for example,
    /// `projects/x/secrets/y/versions/z`).
    #[builder(into)]
    resource_name: String,
    /// The policy for deriving the fetched value's `identity` (and therefore
    /// its `kid`) from the secret version. Defaults to
    /// [`VersionKid::verbatim()`], which uses the version segment unchanged.
    #[builder(default = VersionKid::verbatim())]
    kid: VersionKid,
}

impl SecretVersionBytes {
    /// Returns the fully qualified secret version resource name fetched by this
    /// source.
    #[must_use]
    pub fn resource_name(&self) -> &str {
        &self.resource_name
    }
}

impl Secret for SecretVersionBytes {
    type Output = SecretBytes;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, huskarl_core::Error>> {
        Box::pin(async move {
            let response = self
                .client
                .access_secret_version()
                .set_name(&self.resource_name)
                .send()
                .await
                .context(AccessSecretSnafu)?;

            let payload = response.payload.context(MissingPayloadSnafu)?;

            Ok(SecretOutput {
                value: SecretBytes::new(payload.data.to_vec()),
                identity: response
                    .name
                    .rsplit('/')
                    .next()
                    .and_then(|version| self.kid.derive(version)),
            })
        })
    }
}

/// A [`SecretVersionBytes`] decoded through a [`SecretMap`], using UTF-8 text
/// by default.
///
/// This type combines [`SecretVersionBytes`] with [`MappedSecret`]. It fetches
/// the version on every access and maps the bytes with `M`, defaulting to
/// [`StringEncoding`] so the output is a
/// [`SecretString`](huskarl_core::secrets::SecretString). The source's identity
/// (the trailing version segment) is passed through unchanged. For raw bytes,
/// use [`SecretVersionBytes`] directly; for an ad-hoc map at a call site, prefer
/// [`Secret::mapped`] on a [`SecretVersionBytes`].
///
/// # Usage
///
/// ```rust
/// # use huskarl_google_cloud::secretmanager::{SecretVersion, SecretVersionBytes};
/// # use google_cloud_secretmanager_v1::client::SecretManagerService;
/// # async fn setup(secret_manager: SecretManagerService) {
///     let text = SecretVersion::string(
///         SecretVersionBytes::builder()
///             .client(secret_manager)
///             .resource_name("projects/boogawooga/secrets/my-private-secret/versions/1")
///             .build(),
///     );
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SecretVersion<M: SecretMap<In = SecretBytes> = StringEncoding> {
    inner: MappedSecret<SecretVersionBytes, M>,
}

impl<M: SecretMap<In = SecretBytes>> SecretVersion<M> {
    /// Wraps a byte source, decoding each fetch through `map`.
    #[must_use]
    pub fn new(source: SecretVersionBytes, map: M) -> Self {
        let context = format!("decoding secret version {}", source.resource_name());
        Self {
            inner: MappedSecret::new(source, map).with_context(context),
        }
    }
}

impl SecretVersion {
    /// Decodes each fetch as UTF-8 text via [`StringEncoding`].
    #[must_use]
    pub fn string(source: SecretVersionBytes) -> Self {
        Self::new(source, StringEncoding)
    }
}

impl<M: SecretMap<In = SecretBytes>> Secret for SecretVersion<M> {
    type Output = M::Out;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, huskarl_core::Error>> {
        self.inner.get_secret_value()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::future::Future;

    use google_cloud_gax::Result as GaxResult;
    use google_cloud_gax::options::RequestOptions;
    use google_cloud_gax::response::Response;
    use google_cloud_secretmanager_v1::model::{
        AccessSecretVersionRequest, AccessSecretVersionResponse, SecretPayload,
    };
    use google_cloud_secretmanager_v1::stub::SecretManagerService as SmStub;
    use rstest::rstest;

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct MockSm {
        response_name: String,
        /// `None` simulates a disabled/destroyed version with no payload.
        data: Option<Vec<u8>>,
    }

    impl SmStub for MockSm {
        fn access_secret_version(
            &self,
            _req: AccessSecretVersionRequest,
            _options: RequestOptions,
        ) -> impl Future<Output = GaxResult<Response<AccessSecretVersionResponse>>> + Send {
            let mut resp =
                AccessSecretVersionResponse::default().set_name(self.response_name.clone());
            if let Some(data) = self.data.clone() {
                resp = resp.set_payload(SecretPayload::default().set_data(data));
            }
            async move { Ok(Response::from(resp)) }
        }
    }

    fn secret_version_bytes(mock: MockSm) -> SecretVersionBytes {
        SecretVersionBytes::builder()
            .client(SecretManagerService::from_stub(mock))
            .resource_name("projects/p/secrets/s/versions/3")
            .build()
    }

    #[rstest]
    #[case(SecretError::MissingPayload)]
    fn secret_error_advises_against_retry(#[case] err: SecretError) {
        assert!(!err.is_retryable());
        assert_eq!(
            huskarl_core::Error::from(err).retry_advice(),
            RetryAdvice::No
        );
    }

    #[tokio::test]
    async fn bytes_source_returns_raw_data_and_identity() {
        let sv = secret_version_bytes(MockSm {
            response_name: "projects/p/secrets/s/versions/7".to_owned(),
            data: Some(b"  hunter2  ".to_vec()),
        });

        let out = sv.get_secret_value().await.unwrap();
        // The byte source is verbatim — no trimming, no decoding.
        assert_eq!(out.value.expose_secret(), b"  hunter2  ");
        // Identity is the trailing version segment of the resolved name.
        assert_eq!(out.identity.as_deref(), Some("7"));
    }

    #[tokio::test]
    async fn kid_policy_transforms_or_suppresses_the_identity() {
        let mock = MockSm {
            response_name: "projects/p/secrets/s/versions/7".to_owned(),
            data: Some(b"x".to_vec()),
        };

        // The shared `VersionKid` policy lets `map` transform the version into
        // the identity and `kid`.
        let mapped = SecretVersionBytes::builder()
            .client(SecretManagerService::from_stub(mock.clone()))
            .resource_name("projects/p/secrets/s/versions/3")
            .kid(VersionKid::map(|v| format!("sm-key-{v}")))
            .build();
        assert_eq!(
            mapped.get_secret_value().await.unwrap().identity.as_deref(),
            Some("sm-key-7"),
        );

        // `none` suppresses the identity entirely.
        let none = SecretVersionBytes::builder()
            .client(SecretManagerService::from_stub(mock))
            .resource_name("projects/p/secrets/s/versions/3")
            .kid(VersionKid::none())
            .build();
        assert_eq!(none.get_secret_value().await.unwrap().identity, None);
    }

    #[tokio::test]
    async fn string_wrapper_decodes_and_extracts_identity() {
        let sv = SecretVersion::string(secret_version_bytes(MockSm {
            response_name: "projects/p/secrets/s/versions/7".to_owned(),
            data: Some(b"  hunter2  ".to_vec()), // surrounding whitespace is trimmed
        }));

        let out = sv.get_secret_value().await.unwrap();
        assert_eq!(out.value.expose_secret(), "hunter2");
        // Identity passes through the map unchanged.
        assert_eq!(out.identity.as_deref(), Some("7"));
    }

    #[test]
    fn a_quota_delay_reaches_the_huskarl_error() {
        let err = SecretError::AccessSecret {
            source: crate::retry::quota_error_retrying_after(45),
        };

        assert!(err.is_retryable());
        assert_eq!(
            huskarl_core::Error::from(err).retry_advice(),
            RetryAdvice::retry_after(std::time::Duration::from_secs(45)),
        );
    }

    #[tokio::test]
    async fn get_secret_value_reports_missing_payload_as_permanent() {
        let sv = secret_version_bytes(MockSm {
            response_name: "projects/p/secrets/s/versions/7".to_owned(),
            data: None,
        });

        let err = sv.get_secret_value().await.err().unwrap();
        assert_eq!(err.retry_advice(), RetryAdvice::No);
    }
}
