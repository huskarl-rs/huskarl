use std::collections::HashMap;

use bon::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::token::{AccessToken, IdToken, RefreshToken};

/// The response from the token endpoint.
#[derive(Debug, Clone, Builder, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token.
    #[builder(into)]
    pub access_token: AccessToken,
    /// The token type.
    #[builder(into)]
    pub token_type: String,
    /// Number of seconds until token expiry.
    pub expires_in: Option<u64>,
    /// The refresh token.
    #[builder(into)]
    pub refresh_token: Option<RefreshToken>,
    /// The scopes of the token, usually provided if different to requested scopes.
    #[builder(into)]
    pub scope: Option<String>,
    /// The ID token, usually provided with the `oidc` scope.
    #[builder(into)]
    pub id_token: Option<IdToken>,
    /// The issued token type.
    #[builder(into)]
    pub issued_token_type: Option<String>,
    /// A synthetic field which is set to the received time.
    #[builder(skip = crate::platform::SystemTime::now())]
    #[serde(skip, default = "crate::platform::SystemTime::now")]
    pub received_at: crate::platform::SystemTime,
    /// Other fields received from the token endpoint.
    #[serde(flatten)]
    extra: Option<HashMap<String, Value>>,
}

impl TokenResponse {
    /// Gets a value from the "extra" token fields.
    #[must_use]
    pub fn get_extra(&self, key: &str) -> Option<&Value> {
        self.extra.as_ref().and_then(|extra| extra.get(key))
    }

    /// Returns `true` if the underlying access token has expired.
    pub fn is_expired(
        &self,
        default_expires_in: crate::platform::Duration,
        expires_margin: crate::platform::Duration,
    ) -> bool {
        let expires_in = self
            .expires_in
            .map_or(default_expires_in, crate::platform::Duration::from_secs);

        crate::platform::SystemTime::now() >= self.received_at + expires_in - expires_margin
    }
}
