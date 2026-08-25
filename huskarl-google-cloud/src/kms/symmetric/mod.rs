//! Symmetric Cloud KMS key integrations.
//!
//! - [`cipher`] — raw AEAD encryption and decryption
//!   (`RAW_ENCRYPT_DECRYPT` key purpose)
//! - [`signer`] — HMAC signing and verification (`MAC` key purpose)
//!
//! Encryption and signing pin a single key version; decryption and verification
//! span all enabled versions. See [key versions and
//! rotation](crate::_docs::explanation::versions_and_rotation) for the version
//! and rotation model, and the [symmetric crypto
//! guide](crate::_docs::guide::symmetric_crypto).

pub mod cipher;
pub mod signer;

use google_cloud_kms_v1::model::crypto_key_version::CryptoKeyVersionAlgorithm;
use huskarl_core::RetryAdvice;
use snafu::prelude::*;

use super::version::VersionResolutionError;

/// An error returned while building a [`cipher::KeyVersion`] or
/// [`signer::KeyVersion`] directly.
#[derive(Debug, Snafu)]
#[snafu(module(setup))]
#[non_exhaustive]
pub enum SetupError {
    /// Failed to retrieve the crypto key version metadata.
    GetCryptoKeyVersion {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// The specified key uses an unsupported algorithm.
    #[snafu(display("unsupported algorithm {algorithm:?}"))]
    UnsupportedAlgorithm {
        /// The algorithm reported by the KMS API.
        algorithm: CryptoKeyVersionAlgorithm,
    },
}

impl SetupError {
    /// Returns advice about retrying the failed operation.
    ///
    /// If the service supplied a minimum delay in the RPC's `RetryInfo` detail,
    /// the returned [`RetryAdvice`] preserves it.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            SetupError::GetCryptoKeyVersion { source } => crate::retry::advice(source),
            SetupError::UnsupportedAlgorithm { .. } => RetryAdvice::No,
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

impl From<SetupError> for huskarl_core::Error {
    #[track_caller]
    fn from(err: SetupError) -> Self {
        huskarl_core::Error::new(err.retry_advice(), err)
    }
}

/// An error returned by a higher-level symmetric-key builder such as
/// [`cipher::CipherKey`] or [`signer::SigningKey`].
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum KeyError {
    /// Failed to resolve the primary version via the configured strategy.
    ResolveVersion {
        /// The underlying version resolution error.
        source: VersionResolutionError,
    },
    /// Failed to retrieve key version metadata from KMS.
    GetCryptoKeyVersion {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// The key version uses an unsupported algorithm.
    #[snafu(display("unsupported algorithm {algorithm:?}"))]
    UnsupportedAlgorithm {
        /// The algorithm reported by the KMS API.
        algorithm: CryptoKeyVersionAlgorithm,
    },
    /// Failed to list enabled key versions.
    ListCryptoKeyVersions {
        /// The underlying error from the KMS API.
        source: google_cloud_kms_v1::Error,
    },
    /// No enabled key versions were found.
    NoEnabledCryptoKeyVersions,
}

impl KeyError {
    /// Returns advice about retrying the failed operation.
    ///
    /// If the service supplied a minimum delay in the RPC's `RetryInfo` detail,
    /// the returned [`RetryAdvice`] preserves it.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            KeyError::ResolveVersion { source } => source.retry_advice(),
            KeyError::GetCryptoKeyVersion { source }
            | KeyError::ListCryptoKeyVersions { source } => crate::retry::advice(source),
            KeyError::UnsupportedAlgorithm { .. } | KeyError::NoEnabledCryptoKeyVersions => {
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

impl From<KeyError> for huskarl_core::Error {
    #[track_caller]
    fn from(err: KeyError) -> Self {
        huskarl_core::Error::new(err.retry_advice(), err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build errors convert to `huskarl_core::Error`, allowing these builders to
    // serve as factories for `ScheduledRefreshCipher` and
    // `ScheduledRefreshSigner`.

    #[test]
    fn key_error_classifies_by_retryability() {
        // A permanent failure (no enabled versions) advises against a retry.
        assert!(!KeyError::NoEnabledCryptoKeyVersions.is_retryable());
        assert_eq!(
            huskarl_core::Error::from(KeyError::NoEnabledCryptoKeyVersions).retry_advice(),
            RetryAdvice::No
        );
    }

    #[test]
    fn a_quota_delay_survives_a_nested_crate_error() {
        let err = KeyError::ResolveVersion {
            source: crate::kms::version::VersionResolutionError::GetCryptoKey {
                source: crate::retry::quota_error_retrying_after(20),
            },
        };

        assert_eq!(
            huskarl_core::Error::from(err).retry_advice(),
            RetryAdvice::retry_after(std::time::Duration::from_secs(20)),
        );
    }

    #[test]
    fn setup_error_classifies_by_retryability() {
        let permanent = SetupError::UnsupportedAlgorithm {
            algorithm: CryptoKeyVersionAlgorithm::default(),
        };
        assert!(!permanent.is_retryable());
        assert_eq!(
            huskarl_core::Error::from(permanent).retry_advice(),
            RetryAdvice::No
        );
    }
}
