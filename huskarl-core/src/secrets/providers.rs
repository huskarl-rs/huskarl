use std::ffi::OsString;

use crate::{
    error::{Error, ErrorKind},
    platform::{MaybeSendBoxFuture, MaybeSendSync},
    secrets::{Secret, SecretDecoder, SecretOutput, SecretString, encodings::StringEncoding},
};

/// Retrieves secrets from environment variables with configurable encoding.
#[derive(Debug, Clone)]
pub struct EnvVarSecret<Output = SecretString> {
    /// The name of the value read from the environment.
    value: Output,
}

impl<O> EnvVarSecret<O> {
    /// Creates a new environment variable secret provider with the specified encoding.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`] if the environment variable doesn't
    /// exist, or if the value cannot be decoded.
    pub fn new<E: SecretDecoder<Output = O>>(
        var_name: impl Into<OsString>,
        encoding: &E,
    ) -> Result<Self, Error> {
        let var_name = var_name.into();

        let encoded_value = std::env::var(&var_name).map_err(|source| {
            Error::new(ErrorKind::Config, source).with_context(format!(
                "reading environment variable {}",
                var_name.to_string_lossy()
            ))
        })?;
        let value = encoding.decode(encoded_value.as_bytes()).map_err(|err| {
            err.with_context(format!(
                "decoding environment variable {}",
                var_name.to_string_lossy()
            ))
        })?;

        Ok(Self { value })
    }
}

impl EnvVarSecret<SecretString> {
    /// Creates a new environment variable secret provider returning a `SecretString`.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`] if the environment variable doesn't
    /// exist, or if the value isn't valid UTF-8.
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

#[cfg(feature = "fs")]
mod file_secret {
    use std::path::PathBuf;

    use crate::{
        error::{Error, ErrorKind},
        platform::MaybeSendBoxFuture,
        secrets::{Secret, SecretDecoder, SecretOutput, encodings::StringEncoding},
    };

    /// A secret read from a file on each access.
    ///
    /// The file is read asynchronously on each call to
    /// [`Secret::get_secret_value()`].
    /// For secret rotation schemes that replace files atomically (write to a
    /// temporary file then rename), no file locking is needed.
    ///
    /// Wrap in [`CachedSecret`](crate::secrets::CachedSecret) to add TTL-based caching or
    /// to read the file only once.
    #[derive(Debug, Clone)]
    pub struct FileSecret<D: SecretDecoder = StringEncoding> {
        path: PathBuf,
        decoder: D,
    }

    impl<D: SecretDecoder> FileSecret<D> {
        /// Creates a new file secret provider with the specified decoder.
        pub fn new(path: impl Into<PathBuf>, decoder: D) -> Self {
            Self {
                path: path.into(),
                decoder,
            }
        }
    }

    impl FileSecret {
        /// Creates a new file secret provider returning a [`SecretString`](crate::secrets::SecretString).
        pub fn string(path: impl Into<PathBuf>) -> Self {
            Self::new(path, StringEncoding)
        }
    }

    impl<D: SecretDecoder> Secret for FileSecret<D> {
        type Output = D::Output;

        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
            Box::pin(async move {
                let bytes = tokio::fs::read(&self.path).await.map_err(|source| {
                    // Transient I/O conditions stay retryable; everything else
                    // (missing file, permissions) is a configuration problem.
                    let kind = match source.kind() {
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                            ErrorKind::Transport { retryable: true }
                        }
                        _ => ErrorKind::Config,
                    };
                    Error::new(kind, source)
                        .with_context(format!("reading secret file {}", self.path.display()))
                })?;
                let value = self.decoder.decode(&bytes).map_err(|err| {
                    err.with_context(format!("decoding secret file {}", self.path.display()))
                })?;
                Ok(SecretOutput {
                    value,
                    identity: None,
                })
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io::Write;

        use super::*;

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
            assert_eq!(err.kind(), ErrorKind::Config);
            assert!(!err.is_retryable());
        }
    }
}

#[cfg(feature = "fs")]
pub use file_secret::FileSecret;
