use huskarl_core::{
    Error,
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretOutput, SecretString},
};

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
    type Output = SecretString;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<SecretString>, Error>> {
        Box::pin(async {
            Ok(SecretOutput {
                value: self.0.clone(),
                identity: None,
            })
        })
    }
}
