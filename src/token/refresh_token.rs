use serde::{Deserialize, Serialize};

use crate::secrets::SecretString;

/// An `OAuth2` refresh token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken(SecretString);

impl RefreshToken {
    /// Exposes the token as a string.
    #[must_use] 
    pub fn expose_token(&self) -> &str {
        self.0.expose_secret()
    }
}

impl From<&str> for RefreshToken {
    fn from(value: &str) -> Self {
        Self(SecretString::new(value.into()))
    }
}

impl From<String> for RefreshToken {
    fn from(value: String) -> Self {
        Self(SecretString::new(value))
    }
}

impl From<SecretString> for RefreshToken {
    fn from(value: SecretString) -> Self {
        Self(value)
    }
}
