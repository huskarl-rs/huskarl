use serde::{Deserialize, Serialize};

use crate::secrets::SecretString;

/// An `OAuth2` refresh token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    token: SecretString,
    dpop_jkt: Option<String>,
}

impl RefreshToken {
    /// Creates a new `RefreshToken` with the given token and `DPoP` JWT thumbprint.
    #[must_use]
    pub fn new(token: SecretString, dpop_jkt: Option<String>) -> Self {
        Self { token, dpop_jkt }
    }
}

impl RefreshToken {
    /// Exposes the token as a string.
    #[must_use]
    pub fn expose_token(&self) -> &str {
        self.token.expose_secret()
    }

    /// Returns the `DPoP` JWT thumbprint, if present.
    #[must_use]
    pub fn dpop_jkt(&self) -> Option<&str> {
        self.dpop_jkt.as_deref()
    }
}
