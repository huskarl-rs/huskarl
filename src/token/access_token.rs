use serde::{Deserialize, Serialize};

use crate::secrets::SecretString;

/// An `OAuth2` access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken(SecretString);

impl AccessToken {
    /// Exposes the token as a string.
    #[must_use] 
    pub fn expose_token(&self) -> &str {
        self.0.expose_secret()
    }
}

impl From<&str> for AccessToken {
    fn from(value: &str) -> Self {
        Self(SecretString::new(value.into()))
    }
}

impl From<String> for AccessToken {
    fn from(value: String) -> Self {
        Self(SecretString::new(value))
    }
}

impl From<SecretString> for AccessToken {
    fn from(value: SecretString) -> Self {
        Self(value)
    }
}
