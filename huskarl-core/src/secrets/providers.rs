use std::ffi::OsString;

use snafu::ResultExt as _;

use crate::{
    error::Error,
    platform::{MaybeSendBoxFuture, MaybeSendSync},
    secrets::{
        Secret, SecretBytes, SecretMap, SecretOutput, SecretString, encodings::StringEncoding,
    },
};

/// The cause of a secret-provider failure.
#[derive(Debug, snafu::Snafu, huskarl_macros::Classify)]
#[cfg_attr(test, derive(strum::EnumCount))]
#[non_exhaustive]
pub(crate) enum ProviderError {
    /// The environment variable is unset or not readable.
    #[snafu(display("reading environment variable {name}"))]
    #[classify(no)]
    ReadingEnvVar {
        /// The variable, lossily rendered.
        name: String,
        /// The underlying error.
        source: std::env::VarError,
    },
    /// The environment variable's value could not be mapped.
    #[snafu(display("decoding environment variable {name}"))]
    DecodingEnvVar {
        /// The variable, lossily rendered.
        name: String,
        /// The underlying error.
        source: Error,
    },
    /// The secret file could not be read.
    #[cfg(feature = "fs")]
    #[snafu(display("reading secret file {path}"))]
    #[classify(with = ProviderError::reading_a_file)]
    ReadingSecretFile {
        /// The file that could not be read.
        path: String,
        /// The underlying error.
        source: std::io::Error,
    },
}

impl ProviderError {
    // Classify only transient I/O conditions as retryable.
    #[cfg(feature = "fs")]
    fn reading_a_file(
        _path: &String,
        io: &std::io::Error,
    ) -> crate::error::propagation::Origin<'static> {
        use crate::error::propagation::Origin;

        let advice = match io.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                crate::error::RetryAdvice::RETRY
            }
            _ => crate::error::RetryAdvice::No,
        };
        Origin::Establishes(advice.into())
    }
}

/// Retrieves secrets from environment variables with a configurable mapping.
///
/// **Reads the variable once, at construction** — the decoded value is
/// snapshotted, and later changes to the environment are never observed. That
/// is the honest model for process environments (they are fixed at spawn for
/// practical purposes), and it means construction fails loudly on a missing
/// or malformed value instead of every token request failing later. Contrast
/// `FileSecret` (behind the `fs` feature), which re-reads its file on
/// **every fetch** and so picks up rotations.
#[derive(Debug, Clone)]
pub struct EnvVarSecret<Output = SecretString> {
    /// The name of the value read from the environment.
    value: Output,
}

impl<O> EnvVarSecret<O> {
    /// Creates a new environment variable secret provider with the specified
    /// mapping (a byte-input [`SecretMap`], e.g. a decoder or the UTF-8
    /// conversion).
    ///
    /// # Errors
    ///
    /// Returns a non-retryable error if the variable does not exist or its value
    /// cannot be mapped.
    pub fn new<M: SecretMap<In = SecretBytes, Out = O>>(
        var_name: impl Into<OsString>,
        encoding: &M,
    ) -> Result<Self, Error> {
        let var_name = var_name.into();

        let encoded_value = std::env::var(&var_name).with_context(|_| ReadingEnvVarSnafu {
            name: var_name.to_string_lossy().into_owned(),
        })?;
        let value = encoding
            .apply(SecretBytes::new(encoded_value.into_bytes()))
            .with_context(|_| DecodingEnvVarSnafu {
                name: var_name.to_string_lossy().into_owned(),
            })?;

        Ok(Self { value })
    }
}

impl EnvVarSecret<SecretString> {
    /// Creates a new environment variable secret provider returning a `SecretString`.
    ///
    /// # Errors
    ///
    /// Returns a non-retryable error if the variable does not exist or its value
    /// is not valid UTF-8.
    pub fn string(var_name: impl Into<OsString>) -> Result<Self, Error> {
        Self::new(var_name, &StringEncoding)
    }
}

impl<O: Clone + MaybeSendSync> Secret for EnvVarSecret<O> {
    type Output = O;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
        Box::pin(async move {
            Ok(SecretOutput {
                value: self.value.clone(),
                identity: None,
            })
        })
    }
}

#[cfg(test)]
mod env_tests {
    use super::*;

    #[tokio::test]
    async fn test_env_var_secret_missing() {
        let result = EnvVarSecret::string("NON_EXISTENT_SECRET");
        assert!(result.is_err());
    }
}

/// A secret value the process already holds.
///
/// For a value obtained at runtime from a source this crate doesn't cover — a
/// custom vault client, a configuration struct (note that [`SecretString`]
/// implements `Deserialize`), a test fixture. Construction takes the redacted
/// wrapper ([`SecretString`]/[`SecretBytes`]) rather than a plain string,
/// deliberately: wrapping a value here is a statement that it was *obtained*,
/// not written down.
///
/// **Do not use this to embed a credential in source code.** A hardcoded
/// secret lands in version control, binaries, and backups, and cannot be
/// rotated without a release. If the value is known before the process
/// starts, read it at runtime with [`EnvVarSecret`] or `FileSecret` (behind
/// the `fs` feature) instead.
///
/// The value is a snapshot: rotation in the upstream source is never
/// observed. If the source can rotate, implement [`Secret`] for it directly
/// (see [providing secrets](crate::_docs::guide::providing_secrets)) so each
/// fetch sees the current value.
#[derive(Debug, Clone)]
pub struct ProvidedSecret<Output = SecretString> {
    value: Output,
}

impl<O> ProvidedSecret<O> {
    /// Wraps an already-obtained value as a [`Secret`] provider.
    pub fn new(value: O) -> Self {
        Self { value }
    }
}

impl<O: Clone + MaybeSendSync> Secret for ProvidedSecret<O> {
    type Output = O;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
        Box::pin(async move {
            Ok(SecretOutput {
                value: self.value.clone(),
                identity: None,
            })
        })
    }
}

#[cfg(test)]
mod provided_tests {
    use super::*;

    #[tokio::test]
    async fn provided_string_round_trips() {
        let secret = ProvidedSecret::new(SecretString::new("already-fetched"));
        let output = secret.get_secret_value().await.unwrap();
        assert_eq!(output.value.expose_secret(), "already-fetched");
        assert!(output.identity.is_none());
    }

    #[tokio::test]
    async fn provided_bytes_round_trips() {
        let secret = ProvidedSecret::new(SecretBytes::new(vec![0x2a; 4]));
        let output = secret.get_secret_value().await.unwrap();
        assert_eq!(output.value.expose_secret(), &[0x2a; 4]);
    }
}

#[cfg(feature = "fs")]
mod file_secret {
    use std::path::PathBuf;

    use crate::{
        error::Error,
        platform::MaybeSendBoxFuture,
        secrets::{
            MappedSecret, Secret, SecretBytes, SecretMap, SecretOutput, encodings::StringEncoding,
        },
    };

    /// The raw bytes of a file, read on each access.
    ///
    /// Yields the file contents verbatim as [`SecretBytes`], with no decoding.
    /// Layer a [`SecretMap`] over it with [`Secret::mapped`] (or
    /// [`MappedSecret`]) to parse an encoded form — [`FileSecret`] is the
    /// pre-composed convenience for exactly that.
    ///
    /// The file is read asynchronously on each call to
    /// [`get_secret_value`](Secret::get_secret_value). For rotation schemes that
    /// replace files atomically (write to a temporary file then rename), no file
    /// locking is needed. Wrap in [`CachedSecret`](crate::secrets::CachedSecret)
    /// to add TTL-based caching or to read the file only once.
    #[derive(Debug, Clone)]
    pub struct FileBytes {
        path: PathBuf,
    }

    impl FileBytes {
        /// Creates a new file byte source for `path`.
        pub fn new(path: impl Into<PathBuf>) -> Self {
            Self { path: path.into() }
        }
    }

    impl Secret for FileBytes {
        type Output = SecretBytes;

        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
            Box::pin(async move {
                let bytes = tokio::fs::read(&self.path).await.map_err(|source| {
                    // `ProviderError` classifies this from the I/O error kind.
                    Error::from(super::ProviderError::ReadingSecretFile {
                        path: self.path.display().to_string(),
                        source,
                    })
                })?;
                Ok(SecretOutput {
                    value: SecretBytes::new(bytes),
                    identity: None,
                })
            })
        }
    }

    /// A secret read from a file on each access, mapped through `M`.
    ///
    /// A pre-composed [`FileBytes`] + [`MappedSecret`]: it reads the file on
    /// **every fetch** and maps the bytes with the configured [`SecretMap`]
    /// (defaulting to UTF-8 text via [`StringEncoding`]) — so a rotated file
    /// (e.g. a Kubernetes projected secret) is picked up on the next use, and
    /// construction is infallible because nothing is read yet. Contrast
    /// [`EnvVarSecret`](super::EnvVarSecret), which snapshots eagerly at
    /// construction.
    ///
    /// Wrap in [`CachedSecret`](crate::secrets::CachedSecret) to add TTL-based
    /// caching or to read the file only once.
    #[derive(Debug, Clone)]
    pub struct FileSecret<M: SecretMap<In = SecretBytes> = StringEncoding> {
        inner: MappedSecret<FileBytes, M>,
    }

    impl<M: SecretMap<In = SecretBytes>> FileSecret<M> {
        /// Creates a new file secret provider with the specified mapping.
        pub fn new(path: impl Into<PathBuf>, map: M) -> Self {
            let path = path.into();
            let decode_context = format!("decoding secret file {}", path.display());
            Self {
                inner: MappedSecret::new(FileBytes::new(path), map).with_context(decode_context),
            }
        }
    }

    impl FileSecret {
        /// Creates a new file secret provider returning a [`SecretString`](crate::secrets::SecretString).
        pub fn string(path: impl Into<PathBuf>) -> Self {
            Self::new(path, StringEncoding)
        }
    }

    impl<M: SecretMap<In = SecretBytes>> Secret for FileSecret<M> {
        type Output = M::Out;

        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
            self.inner.get_secret_value()
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io::Write;

        use super::*;
        use crate::secrets::encodings::Base64Encoding;

        #[tokio::test]
        async fn file_secret_trims_trailing_newline() {
            let mut tmp = tempfile::NamedTempFile::new().unwrap();
            writeln!(tmp, "my-secret").unwrap();

            let secret = FileSecret::string(tmp.path());
            let output = secret.get_secret_value().await.unwrap();
            assert_eq!(output.value.expose_secret(), "my-secret");
        }

        #[tokio::test]
        async fn missing_file_is_config_error() {
            let secret = FileSecret::string("/nonexistent/secret/path");
            let err = secret.get_secret_value().await.unwrap_err();
            assert_eq!(err.retry_advice(), crate::error::RetryAdvice::No);
        }

        /// A decode failure names the offending file in its context, not just a
        /// generic "decoding secret value".
        #[tokio::test]
        async fn decode_error_names_the_file() {
            let mut tmp = tempfile::NamedTempFile::new().unwrap();
            write!(tmp, "not valid base64 !!").unwrap();

            let secret = FileSecret::new(tmp.path(), Base64Encoding);
            let err = secret.get_secret_value().await.unwrap_err();
            assert!(
                format!("{err:#}").contains(&tmp.path().display().to_string()),
                "decode error should name the file: {err}"
            );
        }

        /// `FileBytes` yields raw bytes, and `.mapped()` layers an encoding —
        /// the composition `FileSecret` is built from.
        #[tokio::test]
        async fn file_bytes_mapped_composes() {
            let mut tmp = tempfile::NamedTempFile::new().unwrap();
            // base64("hello") wrapped across lines — stripped before decoding.
            write!(tmp, "aGVs\nbG8=").unwrap();

            let secret = FileBytes::new(tmp.path()).mapped(Base64Encoding);
            let output = secret.get_secret_value().await.unwrap();
            assert_eq!(output.value.expose_secret(), b"hello");
        }
    }
}

#[cfg(feature = "fs")]
pub use file_secret::{FileBytes, FileSecret};

#[cfg(test)]
mod classification {
    use strum::EnumCount as _;

    use super::*;
    use crate::error::RetryAdvice;

    // Pin the classification of every variant enabled by the current features.
    #[test]
    fn provider_classifications() {
        #[cfg_attr(not(feature = "fs"), allow(unused_mut))]
        let mut cases: Vec<(&str, ProviderError, RetryAdvice)> = vec![
            (
                "ReadingEnvVar",
                ProviderError::ReadingEnvVar {
                    name: String::from("SECRET"),
                    source: std::env::VarError::NotPresent,
                },
                RetryAdvice::No,
            ),
            (
                "DecodingEnvVar",
                ProviderError::DecodingEnvVar {
                    name: String::from("SECRET"),
                    source: Error::new(RetryAdvice::No, "config failure"),
                },
                RetryAdvice::No,
            ),
        ];
        #[cfg(feature = "fs")]
        cases.push((
            "ReadingSecretFile",
            ProviderError::ReadingSecretFile {
                path: String::from("/nope"),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            },
            RetryAdvice::No,
        ));

        assert_eq!(
            cases.len(),
            ProviderError::COUNT,
            "every variant of ProviderError must be pinned here"
        );
        for (label, sample, advice) in cases {
            let err = Error::from(sample);
            assert_eq!(err.retry_advice(), advice, "{label}: retry advice");
        }
    }

    // File-provider retryability depends on the specific I/O error kind.
    #[cfg(feature = "fs")]
    #[test]
    fn a_secret_file_is_retryable_only_when_the_io_was_transient() {
        let advice_for = |kind| {
            Error::from(ProviderError::ReadingSecretFile {
                path: String::from("/secret"),
                source: std::io::Error::from(kind),
            })
            .retry_advice()
        };

        for kind in [std::io::ErrorKind::WouldBlock, std::io::ErrorKind::TimedOut] {
            assert_eq!(advice_for(kind), RetryAdvice::RETRY, "{kind:?}");
        }
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied,
        ] {
            assert_eq!(advice_for(kind), RetryAdvice::No, "{kind:?}");
        }
    }
}
