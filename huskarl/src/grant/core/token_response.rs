use std::collections::HashMap;

use crate::core::{platform::Duration, secrets::SecretString};
use bon::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use snafu::Snafu;

use crate::token::{AccessToken, BearerAccessToken, DpopAccessToken, IdToken, RefreshToken};

/// The response from the token endpoint.
#[derive(Debug, Clone, Builder, Serialize, Deserialize)]
pub struct RawTokenResponse {
    /// The access token.
    #[builder(into)]
    pub access_token: SecretString,
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
    pub refresh_token: Option<SecretString>,
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
    /// Other fields received from the token endpoint.
    #[serde(flatten)]
    extra: Option<HashMap<String, Value>>,
}

/// The token response, after processing into a valid access and refresh token.
#[derive(Debug, Clone)]
pub struct TokenResponse {
    raw: RawTokenResponse,
    access_token: AccessToken,
    refresh_token: Option<RefreshToken>,
}

impl TokenResponse {
    /// Returns the access token from the token response.
    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    /// Returns the refresh token from the token response.
    pub fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }

    /// Returns the ID token from the token response.
    pub fn id_token(&self) -> Option<&IdToken> {
        self.raw.id_token.as_ref()
    }

    /// Returns the token response.
    pub fn raw_token_response(&self) -> &RawTokenResponse {
        &self.raw
    }
}

#[derive(Debug, Clone)]
enum ResolvedTokenType {
    DPoP { jkt: String },
    Bearer,
}

impl RawTokenResponse {
    /// Gets a value from the "extra" token fields.
    #[must_use]
    pub fn get_extra(&self, key: &str) -> Option<&Value> {
        self.extra.as_ref().and_then(|extra| extra.get(key))
    }

    pub fn into_token_response(
        self,
        dpop_jkt: Option<String>,
        received_at: crate::core::platform::SystemTime,
    ) -> Result<TokenResponse, InvalidTokenResponse> {
        let token_type = self.resolve_token_type(dpop_jkt)?;
        let access_token = self.build_access_token(token_type.clone(), received_at);
        let refresh_token = self.build_refresh_token(token_type);

        Ok(TokenResponse {
            raw: self,
            access_token,
            refresh_token,
        })
    }

    fn resolve_token_type(
        &self,
        dpop_jkt: Option<String>,
    ) -> Result<ResolvedTokenType, InvalidTokenResponse> {
        if self.token_type.eq_ignore_ascii_case("DPoP") {
            dpop_jkt
                .map(|jkt| ResolvedTokenType::DPoP { jkt })
                .ok_or_else(|| NoDpopThumbprintSnafu.build())
        } else if self.token_type.eq_ignore_ascii_case("bearer") {
            Ok(ResolvedTokenType::Bearer)
        } else {
            InvalidTokenTypeSnafu {
                token_type: self.token_type.clone(),
            }
            .fail()
        }
    }

    fn build_access_token(
        &self,
        token_type: ResolvedTokenType,
        received_at: crate::core::platform::SystemTime,
    ) -> AccessToken {
        match token_type {
            ResolvedTokenType::DPoP { jkt } => AccessToken::Dpop(DpopAccessToken::new(
                self.access_token.clone(),
                jkt,
                received_at,
                self.expires_in.map(Duration::from_secs),
            )),
            ResolvedTokenType::Bearer => AccessToken::Bearer(BearerAccessToken::new(
                self.access_token.clone(),
                received_at,
                self.expires_in.map(Duration::from_secs),
            )),
        }
    }

    fn build_refresh_token(&self, token_type: ResolvedTokenType) -> Option<RefreshToken> {
        let Some(refresh_token) = self.refresh_token.as_ref() else {
            return None;
        };

        let result = match token_type {
            ResolvedTokenType::DPoP { jkt } => RefreshToken::new(refresh_token.clone(), Some(jkt)),
            ResolvedTokenType::Bearer => RefreshToken::new(refresh_token.clone(), None),
        };

        Some(result)
    }
}

#[derive(Debug, Clone, PartialEq, Snafu)]
pub enum InvalidTokenResponse {
    #[snafu(display("No DPoP thumbprint provided"))]
    NoDpopThumbprint,
    #[snafu(display("Invalid token type: {}", token_type))]
    InvalidTokenType { token_type: String },
}

impl InvalidTokenResponse {
    pub fn is_retryable(&self) -> bool {
        false
    }
}
