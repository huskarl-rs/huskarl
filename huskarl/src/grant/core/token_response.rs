use std::collections::HashMap;

use bon::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use snafu::Snafu;

use crate::{
    core::{AuthorizationDetail, platform::Duration, secrets::SecretString},
    token::{AccessToken, BearerAccessToken, DpopAccessToken, IdToken, RefreshToken},
};

/// The response from the token endpoint (RFC 6749 §5.1), as received.
///
/// Grants produce this internally and convert it via
/// [`into_token_response`](Self::into_token_response). The builder exists so
/// tests and integrations can fabricate a [`TokenResponse`] — e.g. to
/// [`prime`](crate::cache::GrantTokenSource::prime) a token source without
/// running a real exchange. Production cold-start should still persist only the
/// refresh token (via a
/// [`RefreshTokenStore`](crate::cache::RefreshTokenStore)) and refresh into
/// a fresh access token, rather than persisting responses.
#[derive(Debug, Clone, Builder, Serialize, Deserialize)]
#[builder(on(String, into), on(SecretString, into))]
pub struct RawTokenResponse {
    /// The access token.
    pub access_token: SecretString,
    /// The token type.
    pub token_type: String,
    /// Number of seconds until token expiry.
    #[serde(
        default,
        deserialize_with = "crate::serde_utils::deserialize_u64_or_string"
    )]
    pub expires_in: Option<u64>,
    /// The refresh token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<SecretString>,
    /// The scopes of the token, usually provided if different to requested scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The ID token, usually provided with the `oidc` scope.
    #[builder(into)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) id_token: Option<IdToken>,
    /// The issued token type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<String>,
    /// The authorization details granted to the token (RFC 9396 §7), which may
    /// differ from those requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
    /// Other fields received from the token endpoint.
    #[serde(flatten)]
    extra: Option<HashMap<String, Value>>,
}

/// A processed token-endpoint response — what [`exchange`] hands back.
///
/// Wraps the [`RawTokenResponse`] with the access and refresh tokens resolved
/// into typed form (the access token already classified as bearer or
/// `DPoP`-bound). Read them via [`access_token`](Self::access_token),
/// [`refresh_token`](Self::refresh_token), and [`id_token`](Self::id_token);
/// reach any non-standard fields through
/// [`raw_token_response`](Self::raw_token_response).
///
/// [`exchange`]: crate::grant::core::OAuth2ExchangeGrant::exchange
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

    /// Returns the authorization details granted to the token (RFC 9396 §7).
    #[must_use]
    pub fn authorization_details(&self) -> Option<&[AuthorizationDetail]> {
        self.raw.authorization_details.as_deref()
    }

    /// Returns the underlying raw response, for reading non-standard
    /// token-endpoint fields not surfaced by the typed accessors.
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

    /// Converts the raw response into a validated [`TokenResponse`].
    ///
    /// Resolves the `token_type` (`bearer` or `DPoP`, case-insensitive) and
    /// builds the typed access and refresh tokens. `received_at` anchors
    /// `expires_in` to wall-clock expiry; `dpop_jkt` is the `DPoP` key
    /// thumbprint the token is bound to, required when `token_type` is
    /// `DPoP`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTokenResponse::InvalidTokenType`] for an unknown
    /// `token_type`, and [`InvalidTokenResponse::NoDpopThumbprint`] for a
    /// `DPoP` response without a thumbprint.
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

/// A [`RawTokenResponse`] that cannot be converted into a [`TokenResponse`].
#[derive(Debug, Clone, PartialEq, Snafu)]
pub enum InvalidTokenResponse {
    /// The response is `DPoP`-typed but no `DPoP` key thumbprint was provided.
    #[snafu(display("No DPoP thumbprint provided"))]
    NoDpopThumbprint,
    /// The `token_type` is neither `bearer` nor `DPoP`.
    #[snafu(display("Invalid token type: {}", token_type))]
    InvalidTokenType {
        /// The unrecognized `token_type` value.
        token_type: String,
    },
}

impl InvalidTokenResponse {
    /// Whether retrying the conversion could succeed (it cannot — the
    /// response itself is malformed).
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn is_retryable(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod test {
    use http::HeaderValue;

    use crate::{
        core::{
            platform::{Duration, SystemTime},
            secrets::SecretString,
        },
        grant::core::token_response::{InvalidTokenResponse, RawTokenResponse},
    };

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

    #[test]
    fn parse_token_response_with_authorization_details() {
        let token_response_str = r#"
{
  "access_token":"tok",
  "token_type":"DPoP",
  "authorization_details":[
    {"type":"payment_initiation","actions":["initiate"]}
  ]
}
            "#;

        let raw: RawTokenResponse =
            serde_json::from_str(token_response_str).expect("parsing succeeds");

        let details = raw
            .authorization_details
            .as_deref()
            .expect("authorization_details present");
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].r#type, "payment_initiation");
        assert_eq!(
            details[0].fields.get("actions"),
            Some(&serde_json::json!(["initiate"]))
        );
        // It deserializes into the typed field rather than being swept into `extra`.
        assert!(raw.get_extra("authorization_details").is_none());
    }
}
