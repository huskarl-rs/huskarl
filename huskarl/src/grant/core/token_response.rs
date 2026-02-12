use std::collections::HashMap;

use bon::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::token::{AccessToken, IdToken, RefreshToken};

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
    #[serde(
        default,
        deserialize_with = "crate::serde_utils::deserialize_u64_or_string"
    )]
    pub expires_in: Option<u64>,
    /// The refresh token.
    #[builder(into)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<RefreshToken>,
    /// The scopes of the token, usually provided if different to requested scopes.
    #[builder(into)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The ID token, usually provided with the `oidc` scope.
    #[builder(into)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) id_token: Option<IdToken>,
    /// The issued token type.
    #[builder(into)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<String>,
    /// A synthetic field which is set to the received time.
    #[builder(skip = crate::core::platform::SystemTime::now())]
    #[serde(skip, default = "crate::core::platform::SystemTime::now")]
    pub received_at: crate::core::platform::SystemTime,
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

    /// Returns the effective expiry time of the token: `received_at + expires_in - margin`.
    ///
    /// This is the point in time after which the token should be considered stale.
    /// The token is valid while `SystemTime::now() < effective_expiry(...)`.
    pub fn effective_expiry(
        &self,
        default_expires_in: crate::core::platform::Duration,
        expires_margin: crate::core::platform::Duration,
    ) -> crate::core::platform::SystemTime {
        let expires_in = self.expires_in.map_or(
            default_expires_in,
            crate::core::platform::Duration::from_secs,
        );
        self.received_at + expires_in - expires_margin
    }

    /// Returns `true` if the underlying access token has expired.
    #[must_use]
    pub fn is_expired(
        &self,
        default_expires_in: crate::core::platform::Duration,
        expires_margin: crate::core::platform::Duration,
    ) -> bool {
        crate::core::platform::SystemTime::now()
            >= self.effective_expiry(default_expires_in, expires_margin)
    }
}
