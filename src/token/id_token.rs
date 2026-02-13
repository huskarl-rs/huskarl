//! `OpenID` Connect ID token support.

use serde::{Deserialize, Serialize};

/// An `OpenID` Connect ID token.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IdToken(String);

impl IdToken {
    /// Exposes the token as a string.
    #[must_use] 
    pub fn expose_token(&self) -> &str {
        self.0.as_str()
    }
}

impl From<&str> for IdToken {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl From<String> for IdToken {
    fn from(value: String) -> Self {
        Self(value)
    }
}
