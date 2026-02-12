use std::{convert::Infallible, ffi::OsString, sync::Arc};

use snafu::prelude::*;

use crate::{
    platform::MaybeSendSync,
    secrecy::SecretString,
    secrets::{DecodingError, Secret, SecretDecoder, encodings::StringEncoding},
};

/// Retrieves secrets from environment variables with configurable encoding.
#[derive(Debug, Clone)]
pub struct EnvVarSecret<Output = SecretString> {
    /// The name of the value read from the environment.
    value: Arc<Output>,
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

        Ok(Self {
            value: Arc::new(value),
        })
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

    async fn get_secret_value(&self) -> Result<Self::Output, Self::Error> {
        Ok(self.value.as_ref().clone())
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
