use secrecy::{ExposeSecret, SecretString, zeroize::Zeroize};
use serde::{Deserialize, Serialize};

/// An `OAuth2` access token.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessToken(pub SecretString);

impl Serialize for AccessToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.expose_secret())
    }
}

impl Zeroize for AccessToken {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl From<&str> for AccessToken {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl From<String> for AccessToken {
    fn from(value: String) -> Self {
        Self(value.into())
    }
}

impl From<SecretString> for AccessToken {
    fn from(value: SecretString) -> Self {
        Self(value)
    }
}

impl ExposeSecret<str> for AccessToken {
    fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}
