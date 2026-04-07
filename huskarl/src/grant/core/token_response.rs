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
    #[must_use]
    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    /// Returns the refresh token from the token response.
    #[must_use]
    pub fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }

    /// Returns the ID token from the token response.
    #[must_use]
    pub fn id_token(&self) -> Option<&IdToken> {
        self.raw.id_token.as_ref()
    }

    /// Returns the token response.
    #[must_use]
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
        let refresh_token = self.refresh_token.as_ref()?;

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
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn is_retryable(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod test {
    use crate::{
        core::platform::{Duration, SystemTime},
        grant::core::token_response::InvalidTokenResponse,
    };

    use crate::core::secrets::SecretString;
    use http::HeaderValue;

    use crate::grant::core::token_response::RawTokenResponse;

    #[test]
    fn parse_rfc6749_token_response() {
        let token_response_str = r#"
{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"example",
  "expires_in":3600,
  "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
  "example_parameter":"example_value"
}
            "#;

        let raw_token_response: RawTokenResponse =
            serde_json::from_str(token_response_str).expect("Basic token parsing succeeds");

        assert_eq!(
            raw_token_response.access_token.expose_secret(),
            "2YotnFZFEjr1zCsicMWpAA"
        );
        assert_eq!(raw_token_response.token_type, "example");
        assert_eq!(raw_token_response.expires_in, Some(3600));
        assert_eq!(
            raw_token_response
                .refresh_token
                .as_ref()
                .map(SecretString::expose_secret),
            Some("tGzv3JOkF0XG5Qx2TlKWIA")
        );
        assert_eq!(
            raw_token_response.get_extra("example_parameter"),
            Some(&serde_json::Value::String("example_value".into()))
        );
    }

    #[test]
    fn parse_token_response_with_string_expires_in() {
        let token_response_str = r#"
{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"example",
  "expires_in":"3600",
  "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
  "example_parameter":"example_value"
}
            "#;

        let raw_token_response: RawTokenResponse =
            serde_json::from_str(token_response_str).expect("Basic token parsing succeeds");

        assert_eq!(
            raw_token_response.access_token.expose_secret(),
            "2YotnFZFEjr1zCsicMWpAA"
        );
        assert_eq!(raw_token_response.token_type, "example");
        assert_eq!(raw_token_response.expires_in, Some(3600));
        assert_eq!(
            raw_token_response
                .refresh_token
                .as_ref()
                .map(SecretString::expose_secret),
            Some("tGzv3JOkF0XG5Qx2TlKWIA")
        );
        assert_eq!(
            raw_token_response.get_extra("example_parameter"),
            Some(&serde_json::Value::String("example_value".into()))
        );
    }

    #[test]
    fn test_invalid_token() {
        let token_type = "N_A".to_string();

        let raw_token_response = RawTokenResponse::builder()
            .access_token(SecretString::new("2YotnFZFEjr1zCsicMWpAA"))
            .token_type(&token_type)
            .build();

        let token_response = raw_token_response.into_token_response(
            None,
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_hours(1_000_000))
                .unwrap(),
        );

        let err_token_response = token_response.expect_err("Token response is invalid");

        assert!(matches!(
            err_token_response,
            InvalidTokenResponse::InvalidTokenType { token_type: _ }
        ));
    }

    #[test]
    fn test_bearer_token() {
        let raw_token_response = RawTokenResponse::builder()
            .access_token(SecretString::new("2YotnFZFEjr1zCsicMWpAA"))
            .token_type("BeaRer")
            .build();

        let token_response = raw_token_response
            .into_token_response(
                None,
                SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_hours(1_000_000))
                    .unwrap(),
            )
            .expect("valid TokenResponse");

        let access_token = token_response.access_token();
        assert_eq!(access_token.dpop_jkt(), None);
        assert_eq!(
            access_token.expose_header_value().unwrap(),
            HeaderValue::from_static("Bearer 2YotnFZFEjr1zCsicMWpAA")
        );
    }

    #[test]
    fn test_dpop_token() {
        let raw_token_response = RawTokenResponse::builder()
            .access_token(SecretString::new("2YotnFZFEjr1zCsicMWpAA"))
            .token_type("DpOp")
            .build();

        let token_response = raw_token_response
            .into_token_response(
                Some("dpop_jkt".into()),
                SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_hours(1_000_000))
                    .unwrap(),
            )
            .expect("valid TokenResponse");

        let access_token = token_response.access_token();
        assert_eq!(access_token.dpop_jkt(), Some("dpop_jkt"));
        assert_eq!(
            access_token.expose_header_value().unwrap(),
            HeaderValue::from_static("DPoP 2YotnFZFEjr1zCsicMWpAA")
        );
    }

    #[test]
    fn test_dpop_token_no_dpop_jkt() {
        let raw_token_response = RawTokenResponse::builder()
            .access_token(SecretString::new("2YotnFZFEjr1zCsicMWpAA"))
            .token_type("DPoP")
            .build();

        let token_response = raw_token_response.into_token_response(
            None,
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_hours(1_000_000))
                .unwrap(),
        );

        let err_token_response = token_response.expect_err("No dpop_jkt for DPoP token");

        assert!(matches!(
            err_token_response,
            InvalidTokenResponse::NoDpopThumbprint
        ));
    }
}
