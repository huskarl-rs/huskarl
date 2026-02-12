//! `OAuth2` refresh token support.

use secrecy::zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// An `OAuth2` refresh token.
#[derive(Debug, Clone, Deserialize)]
pub struct RefreshToken(pub SecretString);

impl Serialize for RefreshToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.expose_secret())
    }
}

impl Zeroize for RefreshToken {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl From<&str> for RefreshToken {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl From<String> for RefreshToken {
    fn from(value: String) -> Self {
        Self(value.into())
    }
}

impl From<SecretString> for RefreshToken {
    fn from(value: SecretString) -> Self {
        Self(value)
    }
}

impl ExposeSecret<str> for RefreshToken {
    fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}
