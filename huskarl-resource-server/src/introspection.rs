//! Low-level RFC 7662 token introspection call.

use std::sync::Arc;

use crate::core::jwt::ConfirmationClaim;
use crate::core::secrets::SecretString;
use bytes::Bytes;
use http::{HeaderValue, Method, Request, StatusCode};
use serde::Deserialize;
use serde::Deserializer;
use snafu::OptionExt as _;
use snafu::{ResultExt as _, Snafu, ensure};

use crate::core::BoxedError;
use crate::core::EndpointUrl;
use crate::core::client_auth::{ClientAuthentication, FormValue};
use crate::core::crypto::verifier::{JwsVerifierFactory, JwsVerifierPlatform};
use crate::core::http::{HttpClient, HttpResponse};
use crate::core::jwt::validator::{ClaimCheck, JwtValidationError, JwtValidator};
use crate::core::platform::{Duration, SystemTime};
use crate::validator::ValidatedRequest;

/// Performs a raw RFC 7662 token introspection call.
///
/// Unlike [`crate::validator::introspection::IntrospectionValidator`], this type does not extract tokens from request
/// headers or perform sender-constraint binding checks. It only calls the introspection endpoint
/// and returns the result.
///
/// Use [`TokenIntrospection::builder`] to construct an instance.
pub struct TokenIntrospection<Auth: ClientAuthentication> {
    client_id: String,
    issuer: Option<String>,
    introspection_endpoint: EndpointUrl,
    client_auth: Auth,
    request_jwt_response: bool,
    jwt_validator: Option<JwtValidator>,
}

#[bon::bon]
impl<Auth: ClientAuthentication> TokenIntrospection<Auth> {
    /// Creates a new [`TokenIntrospection`].
    #[builder]
    pub async fn new(
        /// The client ID of this resource server, used for authenticating to the introspection
        /// endpoint.
        #[builder(into)]
        client_id: String,
        /// The issuer URL of the authorization server.
        ///
        /// Used for client authentication methods that require an audience (e.g.
        /// `private_key_jwt`) and for RFC 9701 JWT response issuer (`iss`) validation.
        #[builder(into)]
        issuer: Option<String>,
        /// The URL of the token introspection endpoint.
        introspection_endpoint: EndpointUrl,
        /// The client authentication strategy.
        client_auth: Auth,
        /// If `true`, adds `Accept: application/token-introspection+jwt` to introspection
        /// requests, requesting an RFC 9701 JWT response.
        ///
        /// The AS may still respond with JSON even when this is `true`.
        #[builder(default)]
        request_jwt_response: bool,
        /// JWKS URI for RFC 9701 JWT response validation.
        ///
        /// Must be provided together with `jws_verifier_factory` to enable JWT response
        /// validation.
        jwks_uri: Option<EndpointUrl>,
        /// JWS verifier factory for RFC 9701 JWT response validation.
        ///
        /// When provided (along with `jwks_uri`), a [`JwtValidator`] is built that validates
        /// the outer JWT of introspection responses with content type
        /// `application/token-introspection+jwt`. If the AS returns a JWT response without a
        /// validator configured, [`IntrospectionCallError::UnexpectedJwtResponse`] is returned.
        jws_verifier_factory: Option<Arc<dyn JwsVerifierFactory>>,
        /// JWS verifier platform for JWT response validation.
        ///
        /// Required when `jws_verifier_factory` is provided. When the
        /// `default-jws-verifier-platform` feature is enabled, defaults to the platform default.
        #[cfg(not(feature = "default-jws-verifier-platform"))]
        jws_verifier_platform: Option<Arc<dyn JwsVerifierPlatform>>,
        #[cfg(feature = "default-jws-verifier-platform")]
        #[cfg_attr(feature = "default-jws-verifier-platform", builder(default = crate::DefaultJwsVerifierPlatform::default().into()))]
        jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
    ) -> Result<Self, BoxedError> {
        #[cfg(feature = "default-jws-verifier-platform")]
        let jws_verifier_platform = Some(jws_verifier_platform);

        let jwt_validator = if let Some(jws_verifier_platform) = jws_verifier_platform
            && let Some(factory) = jws_verifier_factory
            && jwks_uri.is_some()
        {
            let verifier = factory
                .build(jwks_uri.as_ref(), jws_verifier_platform)
                .await?;

            // RFC 9701 §4.3: aud = this client's ID; iss = AS issuer (if known)
            let aud_check = ClaimCheck::required_value(client_id.clone());
            let iss_check = issuer
                .as_ref()
                .map(|i| ClaimCheck::required_value(i.clone()))
                .unwrap_or(ClaimCheck::NoCheck);

            Some(
                JwtValidator::builder()
                    .verifier(verifier)
                    .typ(ClaimCheck::required_value("token-introspection+jwt"))
                    .require_exp(true)
                    .aud(aud_check)
                    .iss(iss_check)
                    .build(),
            )
        } else {
            None
        };

        Ok(Self {
            client_id,
            issuer,
            introspection_endpoint,
            client_auth,
            request_jwt_response,
            jwt_validator,
        })
    }
}

impl<Auth: ClientAuthentication> TokenIntrospection<Auth> {
    /// Calls the introspection endpoint and returns a [`ValidatedRequest`] if the token is active.
    ///
    /// Returns [`IntrospectionCallError::TokenInactive`] if the token exists but is not active.
    pub async fn introspect<C: HttpClient, Claims: for<'de> Deserialize<'de> + Clone + 'static>(
        &self,
        http_client: &C,
        access_token: &SecretString,
    ) -> Result<
        ValidatedRequest<Claims>,
        IntrospectionCallError<Auth::Error, C::Error, C::ResponseError>,
    > {
        let auth_params = self
            .client_auth
            .authentication_params(
                &self.client_id,
                self.issuer.as_deref(),
                self.introspection_endpoint.as_uri(),
                None,
            )
            .await
            .context(ClientAuthSnafu)?;

        let (body, auth_headers) = {
            let mut serializer = form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("token", access_token.expose_secret());
            serializer.append_pair("token_type_hint", "access_token");
            if let Some(form_params) = &auth_params.form_params {
                for (key, value) in form_params {
                    let value_str: &str = match value {
                        FormValue::NonSensitive(s) => s.as_ref(),
                        FormValue::Sensitive(s) => s.expose_secret(),
                    };
                    serializer.append_pair(key, value_str);
                }
            }
            (Bytes::from(serializer.finish()), auth_params.headers)
        };

        let (mut parts, ()) = Request::new(()).into_parts();
        parts.method = Method::POST;
        parts.uri = self.introspection_endpoint.clone().into_uri();
        parts.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        if self.request_jwt_response {
            parts.headers.insert(
                http::header::ACCEPT,
                HeaderValue::from_static("application/token-introspection+jwt"),
            );
        }
        if let Some(extra_headers) = auth_headers {
            parts.headers.extend(extra_headers);
        }
        let request = Request::from_parts(parts, body);

        let response = http_client
            .execute(request)
            .await
            .context(HttpRequestSnafu)?;

        let status = response.status();
        let is_jwt_response = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| {
                let ct = ct.trim().to_ascii_lowercase();
                ct.starts_with("application/token-introspection+jwt")
                    || ct.starts_with("token-introspection+jwt")
            })
            .unwrap_or(false);
        let body = response.body().await.context(HttpResponseBodySnafu)?;

        if !status.is_success() {
            return BadStatusSnafu {
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
            }
            .fail();
        }

        let (introspection, introspection_jwt): (IntrospectionResponse<Claims>, Option<String>) =
            if is_jwt_response {
                let jwt_validator = self
                    .jwt_validator
                    .as_ref()
                    .ok_or_else(|| UnexpectedJwtResponseSnafu.build())?;

                let jwt_str = std::str::from_utf8(&body)
                    .map_err(|_| MalformedJwtResponseBodySnafu.build())?
                    .trim();

                let validated = jwt_validator
                    .validate::<TokenIntrospectionJwtClaims<Claims>>(jwt_str)
                    .await
                    .context(JwtResponseSnafu)?;

                let inner = validated
                    .claims
                    .map(|c| c.token_introspection)
                    .context(MissingIntrospectionClaimSnafu)?;

                (inner, Some(jwt_str.to_owned()))
            } else {
                let response: IntrospectionResponse<Claims> =
                    serde_json::from_slice(&body).context(ParseJsonResponseSnafu)?;
                (response, None)
            };

        ensure!(introspection.active, TokenInactiveSnafu);

        let expiration = introspection
            .exp
            .map(|ts| {
                u64::try_from(ts).map_err(|_| {
                    InvalidTimestampSnafu {
                        field: "exp",
                        value: ts,
                    }
                    .build()
                })
            })
            .transpose()?
            .map(|ts| SystemTime::UNIX_EPOCH + Duration::from_secs(ts));
        let issued_at = introspection
            .iat
            .map(|ts| {
                u64::try_from(ts).map_err(|_| {
                    InvalidTimestampSnafu {
                        field: "iat",
                        value: ts,
                    }
                    .build()
                })
            })
            .transpose()?
            .map(|ts| SystemTime::UNIX_EPOCH + Duration::from_secs(ts));

        Ok(ValidatedRequest {
            issuer: introspection.iss,
            subject: introspection.sub,
            audience: introspection.aud,
            jti: introspection.jti,
            issued_at,
            expiration,
            cnf: introspection.cnf,
            claims: introspection.extra,
            introspection_jwt,
        })
    }
}

/// RFC 7662 §2.2 introspection response.
///
/// The `Extra` type parameter captures any additional fields your authorization server
/// includes beyond the standard set.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct IntrospectionResponse<Extra> {
    /// Indicates whether the token is active.
    pub active: bool,
    /// The issuer of the token, if present.
    pub iss: Option<String>,
    /// The subject of the token, if present.
    pub sub: Option<String>,
    /// The audience of the token, if present.
    ///
    /// Deserialized from either a JSON string or an array of strings.
    #[serde(default, deserialize_with = "deserialize_optional_audience")]
    pub aud: Vec<String>,
    /// The expiration time of the token as a Unix timestamp, if present.
    pub exp: Option<i64>,
    /// The time the token was issued as a Unix timestamp, if present.
    pub iat: Option<i64>,
    /// The unique identifier of the token, if present.
    pub jti: Option<String>,
    /// The key confirmation claim (`cnf`, RFC 7800), if present.
    pub cnf: Option<ConfirmationClaim>,
    /// Any additional claims from the introspection response.
    #[serde(flatten)]
    pub extra: Option<Extra>,
}

/// RFC 9701 §4 outer JWT claims wrapping an introspection response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TokenIntrospectionJwtClaims<Extra: Clone> {
    /// The RFC 7662 introspection response embedded as a claim.
    pub token_introspection: IntrospectionResponse<Extra>,
}

fn deserialize_optional_audience<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OptionalStringOrVec;

    impl<'de> serde::de::Visitor<'de> for OptionalStringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string, array of strings, or absent")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(vec![v.to_owned()])
        }

        fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(vec![v])
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(1));
            while let Some(v) = seq.next_element::<String>()? {
                vec.push(v);
            }
            Ok(vec)
        }

        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_some<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            deserializer.deserialize_any(self)
        }
    }

    deserializer.deserialize_option(OptionalStringOrVec)
}

/// Error returned by [`TokenIntrospection::introspect`].
#[derive(Debug, Snafu)]
pub enum IntrospectionCallError<
    AuthErr: crate::core::Error,
    HttpErr: crate::core::Error,
    HttpRespErr: crate::core::Error,
> {
    /// Client authentication failed.
    #[snafu(display("Client authentication failed"))]
    ClientAuth {
        /// The underlying authentication error.
        source: AuthErr,
    },
    /// Failed to build or execute the HTTP request to the introspection endpoint.
    #[snafu(display("HTTP request to introspection endpoint failed"))]
    HttpRequest {
        /// The underlying HTTP error.
        source: HttpErr,
    },
    /// Failed to read the introspection response body.
    #[snafu(display("Failed to read introspection response body"))]
    HttpResponseBody {
        /// The underlying response body error.
        source: HttpRespErr,
    },
    /// The introspection endpoint returned a non-2xx status code.
    #[snafu(display("Introspection endpoint returned status {status}"))]
    BadStatus {
        /// The HTTP status code.
        status: StatusCode,
        /// The response body, as a lossy UTF-8 string.
        body: String,
    },
    /// Failed to parse the JSON introspection response.
    #[snafu(display("Failed to parse introspection JSON response"))]
    ParseJsonResponse {
        /// The underlying JSON parse error.
        source: serde_json::Error,
    },
    /// The AS returned `application/token-introspection+jwt` but no JWT validator was configured.
    #[snafu(display(
        "AS returned a JWT introspection response but no JWT validator was configured"
    ))]
    UnexpectedJwtResponse,
    /// JWT validation of the introspection response (RFC 9701) failed.
    #[snafu(display("JWT introspection response validation failed"))]
    JwtResponse {
        /// The underlying JWT validation error.
        source: JwtValidationError,
    },
    /// The token is not active (`active: false`).
    #[snafu(display("Token is not active"))]
    TokenInactive,
    /// The JWT introspection response body is not valid UTF-8.
    #[snafu(display("JWT introspection response body is not valid UTF-8"))]
    MalformedJwtResponseBody,
    /// The validated JWT introspection response is missing the `token_introspection` claim.
    #[snafu(display("JWT introspection response is missing the token_introspection claim"))]
    MissingIntrospectionClaim,
    /// The introspection response contains a timestamp that cannot be represented as a Unix timestamp.
    #[snafu(display("Introspection response field '{field}' has invalid timestamp: {value}"))]
    InvalidTimestamp {
        /// The name of the field with the invalid timestamp.
        field: &'static str,
        /// The invalid timestamp value.
        value: i64,
    },
}

impl<AuthErr: crate::core::Error, HttpErr: crate::core::Error, HttpRespErr: crate::core::Error>
    IntrospectionCallError<AuthErr, HttpErr, HttpRespErr>
{
    /// Classifies this error as a client-side or server-side failure.
    ///
    /// Only [`Self::TokenInactive`] is a client error. All other variants represent
    /// server-side failures (unreachable AS, misconfigured credentials, malformed response)
    /// that should result in a 5xx response with no RFC 6750 error details.
    pub fn token_error(&self) -> crate::error::TokenValidationError {
        use crate::error::{TokenErrorCode, TokenValidationError};
        match self {
            Self::TokenInactive => TokenValidationError::Client(TokenErrorCode::InvalidToken),
            Self::ClientAuth { .. }
            | Self::HttpRequest { .. }
            | Self::HttpResponseBody { .. }
            | Self::BadStatus { .. } => {
                TokenValidationError::Server(http::StatusCode::SERVICE_UNAVAILABLE)
            }
            Self::ParseJsonResponse { .. }
            | Self::UnexpectedJwtResponse
            | Self::JwtResponse { .. }
            | Self::MalformedJwtResponseBody
            | Self::MissingIntrospectionClaim
            | Self::InvalidTimestamp { .. } => {
                TokenValidationError::Server(http::StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }

    /// Returns a human-readable description of the error for the RFC 6750 `error_description` parameter, if applicable.
    pub fn error_description(&self) -> Option<String> {
        match self {
            Self::TokenInactive => Some("The access token is revoked".to_string()),
            Self::ClientAuth { .. }
            | Self::HttpRequest { .. }
            | Self::HttpResponseBody { .. }
            | Self::BadStatus { .. }
            | Self::ParseJsonResponse { .. }
            | Self::UnexpectedJwtResponse
            | Self::JwtResponse { .. }
            | Self::MalformedJwtResponseBody
            | Self::MissingIntrospectionClaim
            | Self::InvalidTimestamp { .. } => None,
        }
    }
}
