use serde::{Deserialize, Serialize};

use crate::core::secrets::SecretString;

/// An `OAuth2` refresh token, used to obtain new access tokens without
/// re-running the interactive flow.
///
/// May be `DPoP`-bound (RFC 9449): [`dpop_jkt`](Self::dpop_jkt) carries the
/// thumbprint of the key the refresh request must be proven with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    token: SecretString,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    /// Returns the token as a [`SecretString`].
    #[must_use]
    pub fn token(&self) -> &SecretString {
        &self.token
    }

    /// Returns the `DPoP` JWT thumbprint, if present.
    #[must_use]
    pub fn dpop_jkt(&self) -> Option<&str> {
        self.dpop_jkt.as_deref()
    }
}
