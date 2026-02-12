use std::convert::Infallible;

use huskarl_core::secrets::{Secret, SecretOutput, SecretString};

/// A [`Secret`] that returns a fixed string — for use with [`huskarl_core::client_auth::ClientSecret`]
/// in integration tests where the secret value is known up front.
#[derive(Debug, Clone)]
pub struct PlainSecret(SecretString);

impl PlainSecret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(SecretString::new(s.into()))
    }
}

impl Secret for PlainSecret {
    type Error = Infallible;
    type Output = SecretString;

    async fn get_secret_value(&self) -> Result<SecretOutput<SecretString>, Infallible> {
        Ok(SecretOutput {
            value: self.0.clone(),
            identity: None,
        })
    }
}
