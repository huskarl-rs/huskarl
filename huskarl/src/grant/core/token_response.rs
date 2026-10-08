use std::collections::HashMap;

use bon::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use snafu::Snafu;

use crate::{
    core::{AuthorizationDetail, platform::Duration, secrets::SecretString},
    token::{
        AccessToken, BearerAccessToken, DPoPAccessToken, IdToken, NonAccessToken, RefreshToken,
    },
};

/// The response from the token endpoint (RFC 6749 §5.1), as received.
///
/// Grants produce this internally and convert it via
/// [`into_token_response`](Self::into_token_response). The builder exists so
/// tests and integrations can fabricate a [`TokenResponse`] — e.g. to
/// [`prime`](crate::cache::GrantTokenSource::prime) a token source without
/// running a real exchange. To persist credentials across restarts, store the
/// refresh token in a [`RefreshTokenStore`](crate::cache::RefreshTokenStore) and
/// refresh into a fresh access token, rather than persisting whole responses.
#[derive(Clone, Builder, Serialize, Deserialize)]
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
    #[builder(default)]
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

impl std::fmt::Debug for RawTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawTokenResponse")
            .field("access_token", &self.access_token)
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &self.refresh_token)
            .field("scope", &self.scope)
            .field("id_token", &self.id_token)
            .field("issued_token_type", &self.issued_token_type)
            .field("authorization_details", &self.authorization_details)
            .finish_non_exhaustive()
    }
}

/// A processed token-endpoint response — what [`exchange`] hands back.
///
/// Wraps the [`RawTokenResponse`] with the access and refresh tokens resolved
/// into typed form (the access token already classified as bearer or
/// `DPoP`-bound). Read them via [`access_token`](Self::access_token),
/// [`refresh_token`](Self::refresh_token), and [`id_token`](Self::id_token);
/// read any non-standard fields with [`get_extra`](Self::get_extra) (or the
/// whole [`raw_token_response`](Self::raw_token_response)).
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

    /// Returns the ID token from the token response, as received.
    ///
    /// The library validates it only on the authorization-code callback path
    /// — use the validated form returned by
    /// [`complete`](crate::grant::authorization_code::AuthorizationCodeGrant::complete)
    /// there. On every other grant (refresh, device, token exchange) this is
    /// untrusted wire data: validate it before use.
    #[must_use]
    pub fn id_token(&self) -> Option<&IdToken> {
        self.raw.id_token.as_ref()
    }

    /// Returns the authorization details granted to the token (RFC 9396 §7).
    #[must_use]
    pub fn authorization_details(&self) -> Option<&[AuthorizationDetail]> {
        self.raw.authorization_details.as_deref()
    }

    /// Returns a non-standard field from the token response.
    ///
    /// These fields may contain credentials and are omitted from `Debug` output.
    #[must_use]
    pub fn get_extra(&self, key: &str) -> Option<&Value> {
        self.raw.get_extra(key)
    }

    /// Returns the underlying raw response, for reading non-standard
    /// token-endpoint fields not surfaced by the typed accessors.
    #[must_use]
    pub fn raw_token_response(&self) -> &RawTokenResponse {
        &self.raw
    }
}

/// Request proof key thumbprint and refresh-token binding policy.
///
/// Used by [`RawTokenResponse::into_token_response_with_context`]. The conversion
/// stores the request proof's key thumbprint in the returned access-token value
/// only when `token_type` is `DPoP`. When `bind_refresh_token` is `true`, it also
/// stores the same thumbprint in any returned `RefreshToken` value, including
/// for bearer responses.
/// Built-in grants record new bindings for public clients (RFC 9449 §5), and
/// refresh grants preserve any existing binding for either client type. Without a request proof thumbprint,
/// refresh tokens remain unbound.
///
/// This context neither establishes nor validates an ID-token binding. ID
/// tokens remain subject to their own protocol-specific validation.
#[derive(Debug, Clone, Default, Builder)]
#[builder(on(String, into))]
pub struct TokenResponseContext {
    /// Thumbprint of the key used to sign the token request's proof. Required
    /// for a `DPoP` access-token response. Also used for refresh-token binding
    /// when `bind_refresh_token` is `true`.
    dpop_jkt: Option<String>,
    /// Whether to store `dpop_jkt` in a returned `RefreshToken` value, independently
    /// of the access-token type. Defaults to `false`. If `dpop_jkt` is `None`,
    /// the refresh token remains unbound even when this is `true`.
    #[builder(default)]
    bind_refresh_token: bool,
}

#[derive(Debug)]
enum ResolvedTokenType {
    DPoP {
        jkt: String,
    },
    Bearer,
    /// RFC 8693 `N_A`: the issued token is not an access token.
    NotApplicable,
}

impl RawTokenResponse {
    /// Returns a value from the extra token fields.
    #[must_use]
    pub fn get_extra(&self, key: &str) -> Option<&Value> {
        self.extra.get(key)
    }

    /// Converts the raw response into a validated [`TokenResponse`].
    ///
    /// Resolves the `token_type` (`bearer` or `DPoP`, case-insensitive) and
    /// builds the typed access and refresh tokens. The expiry time is calculated
    /// from `received_at` and `expires_in`; `dpop_jkt` is the `DPoP` key
    /// thumbprint the token is bound to, required when `token_type` is
    /// `DPoP`.
    ///
    /// For compatibility, this method also stores the thumbprint in the returned
    /// `RefreshToken` value only for `DPoP` responses. It has no
    /// client-authentication context. Use
    /// [`into_token_response_with_context`](Self::into_token_response_with_context)
    /// to resolve refresh binding independently, as built-in grants do.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTokenResponse::InvalidTokenType`] for an unknown
    /// `token_type`, and [`InvalidTokenResponse::NoDPoPThumbprint`] for a
    /// `DPoP` response without a thumbprint.
    pub fn into_token_response(
        self,
        dpop_jkt: Option<String>,
        received_at: crate::core::platform::SystemTime,
    ) -> Result<TokenResponse, InvalidTokenResponse> {
        let bind_refresh_token = self.token_type.eq_ignore_ascii_case("DPoP");
        self.into_token_response_with_context(
            TokenResponseContext::builder()
                .maybe_dpop_jkt(dpop_jkt)
                .bind_refresh_token(bind_refresh_token)
                .build(),
            received_at,
        )
    }

    /// Resolves access and refresh bindings independently using request context.
    ///
    /// Calculates the expiry time from `received_at` and `expires_in`.
    /// The access-token type follows `token_type`. If `bind_refresh_token` is
    /// `true`, stores the same `dpop_jkt` supplied in `context` in any returned
    /// `RefreshToken` value, even for a bearer response. Without a thumbprint,
    /// the returned value contains no `DPoP` binding.
    /// No ID-token validation or binding is performed here.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTokenResponse::InvalidTokenType`] for an unknown token
    /// type, or [`InvalidTokenResponse::NoDPoPThumbprint`] for a `DPoP` response
    /// without the request proof's key thumbprint, regardless of
    /// `bind_refresh_token`.
    pub fn into_token_response_with_context(
        self,
        context: TokenResponseContext,
        received_at: crate::core::platform::SystemTime,
    ) -> Result<TokenResponse, InvalidTokenResponse> {
        let refresh_token_dpop_jkt = context
            .dpop_jkt
            .clone()
            .filter(|_| context.bind_refresh_token);
        let token_type = self.resolve_token_type(context.dpop_jkt)?;
        let access_token = self.build_access_token(token_type, received_at);
        let refresh_token = self.build_refresh_token(refresh_token_dpop_jkt);

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
                .ok_or_else(|| NoDPoPThumbprintSnafu.build())
        } else if self.token_type.eq_ignore_ascii_case("bearer") {
            Ok(ResolvedTokenType::Bearer)
        } else if self.token_type.eq_ignore_ascii_case("N_A") && self.issued_token_type.is_some() {
            // RFC 8693 §2.2.1: N_A is mandated when the issued token is not
            // an access token. Only exchange responses carry
            // issued_token_type, so plain grants still reject N_A.
            Ok(ResolvedTokenType::NotApplicable)
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
            ResolvedTokenType::DPoP { jkt } => AccessToken::DPoP(DPoPAccessToken::new(
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
            ResolvedTokenType::NotApplicable => AccessToken::NotAccessToken(NonAccessToken::new(
                self.access_token.clone(),
                received_at,
                self.expires_in.map(Duration::from_secs),
            )),
        }
    }

    fn build_refresh_token(&self, dpop_jkt: Option<String>) -> Option<RefreshToken> {
        let refresh_token = self.refresh_token.as_ref()?;
        Some(RefreshToken::new(refresh_token.clone(), dpop_jkt))
    }
}

/// A [`RawTokenResponse`] that cannot be converted into a [`TokenResponse`].
///
/// Both variants describe a specification violation that retrying cannot fix.
#[derive(Debug, Clone, PartialEq, Snafu, huskarl_macros::Classify)]
#[non_exhaustive]
pub enum InvalidTokenResponse {
    /// The response is `DPoP`-typed but no `DPoP` key thumbprint was provided.
    #[snafu(display("no DPoP thumbprint provided"))]
    #[classify(no)]
    NoDPoPThumbprint,
    /// The `token_type` is neither `bearer` nor `DPoP`.
    #[snafu(display("invalid token type: {}", token_type))]
    #[classify(no)]
    InvalidTokenType {
        /// The unrecognized `token_type` value.
        token_type: String,
    },
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
    fn extras_round_trip_without_appearing_in_debug() {
        let raw: RawTokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "access-token",
            "token_type": "Bearer",
            "provider_secret": {"nested": "secret-extension"},
            "nullable": null
        }))
        .unwrap();
        assert_eq!(raw.get_extra("nullable"), Some(&serde_json::Value::Null));
        assert!(raw.get_extra("missing").is_none());
        assert!(raw.get_extra("access_token").is_none());
        let serialized = serde_json::to_value(&raw).unwrap();
        assert_eq!(
            serialized["provider_secret"],
            serde_json::json!({"nested": "secret-extension"})
        );
        assert!(!serialized.as_object().unwrap().contains_key("extra"));
        let response = raw
            .clone()
            .into_token_response(None, SystemTime::now())
            .unwrap();
        assert_eq!(
            response.get_extra("provider_secret"),
            raw.get_extra("provider_secret")
        );
        for debug in [format!("{raw:?}"), format!("{response:?}")] {
            assert!(!debug.contains("secret-extension"));
            assert!(!debug.contains("provider_secret"));
            assert!(debug.contains("Bearer"));
        }
    }

    #[test]
    fn absent_extras_and_builder_setters_remain_supported() {
        let raw: RawTokenResponse =
            serde_json::from_str(r#"{"access_token":"token","token_type":"Bearer"}"#).unwrap();
        assert!(raw.extra.is_empty());
        let built = RawTokenResponse::builder()
            .access_token("token")
            .token_type("Bearer")
            .build();
        assert!(built.extra.is_empty());
        let built = RawTokenResponse::builder()
            .access_token("token")
            .token_type("Bearer")
            .maybe_extra(None)
            .build();
        assert!(built.extra.is_empty());
        let built = RawTokenResponse::builder()
            .access_token("token")
            .token_type("Bearer")
            .extra(std::collections::HashMap::from([(
                "custom".into(),
                serde_json::json!(42),
            )]))
            .build();
        assert_eq!(built.get_extra("custom"), Some(&serde_json::json!(42)));
    }

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

    /// Some authorization servers emit `expires_in` as a JSON float
    /// (e.g. `3600.0`) or as a float in a string (`"3600.0"`); fractional
    /// values truncate toward earlier expiry.
    #[rstest::rstest]
    #[case::integral("3600.0", Some(3600))]
    #[case::fractional("3599.5", Some(3599))]
    #[case::string_float(r#""3600.0""#, Some(3600))]
    #[case::string_fractional(r#""3599.5""#, Some(3599))]
    fn parse_token_response_with_float_expires_in(
        #[case] expires_in: &str,
        #[case] expected: Option<u64>,
    ) {
        let token_response_str = format!(
            r#"{{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"example",
  "expires_in":{expires_in}
}}"#
        );

        let raw_token_response: RawTokenResponse =
            serde_json::from_str(&token_response_str).expect("float expires_in parses");
        assert_eq!(raw_token_response.expires_in, expected);
    }

    /// `N_A` outside a token-exchange response (no `issued_token_type`) stays
    /// invalid — plain grants must not accept it.
    #[test]
    fn test_na_without_issued_token_type_is_invalid() {
        let raw_token_response = RawTokenResponse::builder()
            .access_token(SecretString::new("2YotnFZFEjr1zCsicMWpAA"))
            .token_type("N_A")
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

    /// RFC 8693 §2.2.1: a token-exchange response for a non-access-token
    /// `requested_token_type` carries `token_type: "N_A"` and must complete.
    #[test]
    fn test_na_exchange_response_resolves_to_non_access_token() {
        let raw_token_response = RawTokenResponse::builder()
            .access_token(SecretString::new("eyJhbGciOi...an-id-token"))
            .token_type("N_A")
            .issued_token_type("urn:ietf:params:oauth:token-type:id_token".to_string())
            .expires_in(300)
            .build();

        let token_response = raw_token_response
            .into_token_response(
                None,
                SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_hours(1_000_000))
                    .unwrap(),
            )
            .expect("a spec-valid N_A exchange response must complete");

        let token = token_response.access_token();
        assert!(matches!(
            token,
            crate::token::AccessToken::NotAccessToken(_)
        ));
        assert_eq!(token.token_type(), "N_A");
        assert_eq!(token.dpop_jkt(), None);
        assert!(
            token.expose_header_value().is_err(),
            "an N_A token must have no Authorization-header form"
        );
        assert_eq!(token.token().expose_secret(), "eyJhbGciOi...an-id-token");
    }

    #[test]
    fn test_invalid_token() {
        let raw_token_response = RawTokenResponse::builder()
            .access_token(SecretString::new("2YotnFZFEjr1zCsicMWpAA"))
            .token_type("mac")
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

    #[rstest::rstest]
    #[case::bearer("Bearer", Some("proof"), false, None, None)]
    #[case::public_bearer("Bearer", Some("proof"), true, None, Some("proof"))]
    #[case::confidential_dpop("DPoP", Some("proof"), false, Some("proof"), None)]
    #[case::public_dpop("DPoP", Some("proof"), true, Some("proof"), Some("proof"))]
    #[case::public_without_dpop("Bearer", None, true, None, None)]
    #[case::confidential_without_dpop("Bearer", None, false, None, None)]
    fn refresh_binding_policy_is_independent_of_access_token_type(
        #[case] token_type: &str,
        #[case] request_key: Option<&str>,
        #[case] bind_refresh_token: bool,
        #[case] access_key: Option<&str>,
        #[case] refresh_key: Option<&str>,
    ) {
        let response = RawTokenResponse::builder()
            .access_token("access")
            .token_type(token_type)
            .refresh_token("refresh")
            .build()
            .into_token_response_with_context(
                super::TokenResponseContext::builder()
                    .maybe_dpop_jkt(request_key.map(str::to_owned))
                    .bind_refresh_token(bind_refresh_token)
                    .build(),
                SystemTime::now(),
            )
            .unwrap();
        assert_eq!(response.access_token().dpop_jkt(), access_key);
        assert_eq!(response.refresh_token().unwrap().dpop_jkt(), refresh_key);
    }

    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    fn dpop_response_requires_a_thumbprint(#[case] bind_refresh_token: bool) {
        let error = RawTokenResponse::builder()
            .access_token("access")
            .token_type("DPoP")
            .build()
            .into_token_response_with_context(
                super::TokenResponseContext::builder()
                    .bind_refresh_token(bind_refresh_token)
                    .build(),
                SystemTime::now(),
            )
            .unwrap_err();
        assert_eq!(error, InvalidTokenResponse::NoDPoPThumbprint);
    }

    #[test]
    fn context_builder_leaves_refresh_tokens_unbound_by_default() {
        let response = RawTokenResponse::builder()
            .access_token("access")
            .token_type("DPoP")
            .refresh_token("refresh")
            .build()
            .into_token_response_with_context(
                super::TokenResponseContext::builder()
                    .dpop_jkt("proof")
                    .build(),
                SystemTime::now(),
            )
            .unwrap();
        assert_eq!(response.access_token().dpop_jkt(), Some("proof"));
        assert_eq!(response.refresh_token().unwrap().dpop_jkt(), None);
    }

    #[rstest::rstest]
    #[case("Bearer", None)]
    #[case("DPoP", Some("key"))]
    fn legacy_conversion_preserves_refresh_binding_behavior(
        #[case] token_type: &str,
        #[case] expected_key: Option<&str>,
    ) {
        let response = RawTokenResponse::builder()
            .access_token("access")
            .token_type(token_type)
            .refresh_token("refresh")
            .build()
            .into_token_response(Some("key".into()), SystemTime::now())
            .unwrap();
        assert_eq!(response.refresh_token().unwrap().dpop_jkt(), expected_key);
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
            InvalidTokenResponse::NoDPoPThumbprint
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

#[cfg(test)]
mod classification {
    use super::*;
    use crate::core::{Error, RetryAdvice};

    // Classification is exposed through the wrapping `Error`.
    #[test]
    fn the_verdict_is_read_off_the_wrapping_error() {
        let err = Error::from(InvalidTokenResponse::InvalidTokenType {
            token_type: String::from("mac"),
        });
        assert_eq!(err.retry_advice(), RetryAdvice::No);
        // The cause is erased, so it is reached through the test seam.
        assert!(err.cause().is::<InvalidTokenResponse>());
    }
}
