use std::{convert::Infallible, ffi::OsString};

use snafu::prelude::*;

use crate::{
    platform::MaybeSendSync,
    secrets::{
        DecodingError, Secret, SecretDecoder, SecretOutput, SecretString, encodings::StringEncoding,
    },
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
    /// Returns an error if the environment variable doesn't exist, or if the value
    /// isn't valid UTF-8.
    pub fn new<E: SecretDecoder<Output = O>>(
        var_name: impl Into<OsString>,
        encoding: &E,
    ) -> Result<Self, EnvVarSecretError> {
        let var_name = var_name.into();

        let encoded_value = std::env::var(var_name.clone()).context(EnvAccessSnafu { var_name })?;
        let value = encoding
            .decode(encoded_value.as_bytes())
            .context(DecodeSnafu)?;

        Ok(Self { value })
    }
}

impl EnvVarSecret<SecretString> {
    /// Creates a new environment variable secret provider returning a `SecretString`.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable doesn't exist, or if the value
    /// isn't valid UTF-8.
    pub fn string(var_name: impl Into<OsString>) -> Result<Self, EnvVarSecretError> {
        Self::new(var_name, &StringEncoding)
    }
}

impl<O: Clone + MaybeSendSync> Secret for EnvVarSecret<O> {
    type Output = O;
    type Error = Infallible;

    async fn get_secret_value(&self) -> Result<SecretOutput<Self::Output>, Self::Error> {
        Ok(SecretOutput {
            value: self.value.clone(),
            identity: None,
        })
    }
}

/// Errors that can occur when using [`EnvVarSecret`].
#[derive(Debug, Snafu)]
pub enum EnvVarSecretError {
    /// The environment variable was not found or was not valid unicode.
    #[snafu(display("Failed to read env variable '{}'", var_name.to_string_lossy()))]
    EnvAccess {
        /// The name of the environment variable that could not be accessed.
        var_name: OsString,
        /// The underlying error from the environment variable lookup.
        source: std::env::VarError,
    },
    /// Failed to decode the secret.
    #[snafu(display("Failed to decode secret"))]
    Decode {
        /// The encoding error.
        source: DecodingError,
    },
}

impl crate::Error for EnvVarSecretError {
    fn is_retryable(&self) -> bool {
        false
    }
}

#[cfg(feature = "fs")]
mod file_secret {
    use std::path::PathBuf;

    use snafu::prelude::*;

    use crate::secrets::{
        DecodingError, Secret, SecretDecoder, SecretOutput, encodings::StringEncoding,
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
        type Error = FileSecretError;

        async fn get_secret_value(&self) -> Result<SecretOutput<Self::Output>, Self::Error> {
            let bytes = tokio::fs::read(&self.path).await.context(ReadFileSnafu)?;
            let value = self.decoder.decode(&bytes).context(FileDecodeSnafu)?;
            Ok(SecretOutput {
                value,
                identity: None,
            })
        }
    }

    /// Errors that can occur when using [`FileSecret`].
    #[derive(Debug, Snafu)]
    pub enum FileSecretError {
        /// Failed to read the secret file.
        #[snafu(display("Failed to read secret file"))]
        ReadFile {
            /// The underlying I/O error.
            source: std::io::Error,
        },
        /// Failed to decode the file contents.
        #[snafu(display("Failed to decode secret file contents"))]
        FileDecode {
            /// The decoding error.
            source: DecodingError,
        },
    }

    impl crate::Error for FileSecretError {
        fn is_retryable(&self) -> bool {
            match self {
                Self::ReadFile { source } => matches!(
                    source.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                Self::FileDecode { .. } => false,
            }
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
    }
}

#[cfg(feature = "fs")]
pub use file_secret::{FileSecret, FileSecretError};
