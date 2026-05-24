//! `OpenID` Connect `UserInfo` endpoint (OIDC Core §5.3).

use std::{marker::PhantomData, sync::Arc};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header::InvalidHeaderValue};
use serde::Deserialize;
use snafu::prelude::*;

use crate::{
    core::{
        BoxedError, EndpointUrl,
        crypto::verifier::{JwsVerifierFactory, JwsVerifierPlatform},
        dpop::{AuthorizationServerDPoP, ResourceServerDPoP},
        http::{HttpClient, HttpResponse},
        jwt::{
            JwsParseError, parse_compact_jws,
            validator::{ClaimCheck, JwtValidationError, JwtValidator},
        },
        server_metadata::AuthorizationServerMetadata,
    },
    grant::core::OAuth2ExchangeGrant,
    token::AccessToken,
};

/// `OpenID` Connect `UserInfo` client.
///
/// The `Extra` type parameter controls the claims type returned by [`get`](Self::get).
/// It defaults to `()` (standard claims only). Specify a custom type to capture
/// additional provider-specific claims.
#[derive(Debug)]
pub struct UserInfoClient<
    D: ResourceServerDPoP,
    Extra: Clone + for<'de> Deserialize<'de> + 'static = (),
> {
    /// The URL of the `UserInfo` endpoint.
    userinfo_endpoint: EndpointUrl,

    /// The mTLS alias for the `UserInfo` endpoint (RFC 8705 §5).
    mtls_userinfo_endpoint: Option<EndpointUrl>,

    /// The `DPoP` proof implementation for resource server requests.
    dpop: D,

    /// Optional JWT validator for `application/jwt` `UserInfo` responses (OIDC Core §5.3.2).
    jwt_validator: Option<JwtValidator>,

    _phantom: PhantomData<Extra>,
}

#[bon::bon]
impl<D: ResourceServerDPoP, Extra: Clone + for<'de> Deserialize<'de> + 'static>
    UserInfoClient<D, Extra>
{
    /// Creates a new [`UserInfoClient`].
    #[builder(state_mod(name = "builder"))]
    pub async fn new(
        /// The URL of the `UserInfo` endpoint.
        userinfo_endpoint: EndpointUrl,
        /// The mTLS alias for the `UserInfo` endpoint (RFC 8705 §5).
        mtls_userinfo_endpoint: Option<EndpointUrl>,
        /// The `DPoP` proof implementation for resource server requests.
        ///
        /// Use [`NoDPoP`](crate::core::dpop::NoDPoP) for plain bearer token flows.
        dpop: D,
        /// JWKS URI for `application/jwt` `UserInfo` response validation.
        ///
        /// Must be provided together with `jws_verifier_factory` to enable JWT response
        /// validation.
        jwks_uri: Option<EndpointUrl>,
        /// JWS verifier factory for JWT response validation.
        ///
        /// When provided (along with `jwks_uri`), a [`JwtValidator`] is built that validates
        /// signed `UserInfo` responses. If the provider returns a JWT response without a
        /// validator configured, [`UserInfoError::JwtResponseNotSupported`] is returned.
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
        /// The issuer URL, used for JWT `iss` claim validation (OIDC Core §5.3.2).
        ///
        /// Required when JWT validation is configured (`jwks_uri` and
        /// `jws_verifier_factory` are provided).
        #[builder(into)]
        issuer: Option<String>,
        /// The client ID, used for JWT `aud` claim validation (OIDC Core §5.3.2).
        ///
        /// Required when JWT validation is configured (`jwks_uri` and
        /// `jws_verifier_factory` are provided).
        #[builder(into)]
        client_id: Option<String>,
    ) -> Result<Self, BoxedError> {
        #[cfg(feature = "default-jws-verifier-platform")]
        let jws_verifier_platform = Some(jws_verifier_platform);

        let jwt_validator = if let Some(jws_verifier_platform) = jws_verifier_platform
            && let Some(factory) = jws_verifier_factory
            && jwks_uri.is_some()
        {
            let issuer = issuer.ok_or_else(|| BoxedError::from_err(MissingIssuerSnafu.build()))?;
            let client_id =
                client_id.ok_or_else(|| BoxedError::from_err(MissingClientIdSnafu.build()))?;

            let verifier = factory
                .build(jwks_uri.as_ref(), jws_verifier_platform)
                .await?;

            Some(
                JwtValidator::builder()
                    .verifier(verifier)
                    .aud(ClaimCheck::required_value(client_id))
                    .iss(ClaimCheck::required_value(issuer))
                    .build(),
            )
        } else {
            None
        };

        Ok(Self {
            userinfo_endpoint,
            mtls_userinfo_endpoint,
            dpop,
            jwt_validator,
            _phantom: PhantomData,
        })
    }
}

impl<D: ResourceServerDPoP> UserInfoClient<D> {
    /// Creates a `UserInfo` client from an `OAuth2` grant and authorization server metadata.
    ///
    /// The `DPoP` configuration is derived from the grant, converted to its resource
    /// server form — the same pattern used by [`InMemoryTokenCache`](crate::cache::InMemoryTokenCache).
    ///
    /// Returns `None` if the metadata does not include a `userinfo_endpoint`.
    pub fn from_grant<G>(grant: &G, metadata: &AuthorizationServerMetadata) -> Option<Self>
    where
        G: OAuth2ExchangeGrant,
        G::DPoP: AuthorizationServerDPoP<ResourceServerDPoP = D>,
    {
        let userinfo_endpoint = metadata.userinfo_endpoint.clone()?;

        Some(Self {
            userinfo_endpoint,
            mtls_userinfo_endpoint: metadata
                .mtls_endpoint_aliases
                .as_ref()
                .and_then(|a| a.userinfo_endpoint.clone()),
            dpop: grant.dpop().to_resource_server_dpop(),
            jwt_validator: None,
            _phantom: PhantomData,
        })
    }

    /// Fills builder parameters relevant to `UserInfo` from authorization server metadata.
    ///
    /// Returns `None` if the `userinfo_endpoint` is not included in metadata.
    #[allow(clippy::type_complexity)]
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> Option<
        UserInfoClientBuilder<
            D,
            (),
            builder::SetIssuer<
                builder::SetJwksUri<
                    builder::SetMtlsUserinfoEndpoint<builder::SetUserinfoEndpoint<builder::Empty>>,
                >,
            >,
        >,
    > {
        let userinfo_endpoint = metadata.userinfo_endpoint.clone()?;

        Some(
            Self::builder()
                .userinfo_endpoint(userinfo_endpoint)
                .maybe_mtls_userinfo_endpoint(
                    metadata
                        .mtls_endpoint_aliases
                        .as_ref()
                        .and_then(|a| a.userinfo_endpoint.clone()),
                )
                .maybe_jwks_uri(metadata.jwks_uri.clone())
                .issuer(metadata.issuer.clone()),
        )
    }
}

impl<D: ResourceServerDPoP, Extra: Clone + for<'de> Deserialize<'de> + 'static>
    UserInfoClient<D, Extra>
{
    /// Call the `UserInfo` endpoint with the given access token.
    ///
    /// The `expected_sub` parameter is the `sub` claim from the ID Token. Per
    /// OIDC Core §5.3.2, the `sub` in the `UserInfo` response MUST exactly match
    /// the `sub` in the ID Token; if they differ, this method returns
    /// [`UserInfoError::SubMismatch`].
    ///
    /// # Errors
    ///
    /// Returns [`UserInfoError::SubMismatch`] if the response `sub` does not match
    /// `expected_sub`, [`UserInfoError::BadAuthorizationHeader`] if the access token
    /// cannot be represented as a valid HTTP header value, [`UserInfoError::DPoP`] if
    /// the `DPoP` proof cannot be generated, or [`UserInfoError::Request`] /
    /// [`UserInfoError::BadStatus`] if the HTTP request fails.
    pub async fn get<C: HttpClient>(
        &self,
        http_client: &C,
        access_token: &AccessToken,
        expected_sub: &str,
    ) -> Result<UserInfo<Extra>, UserInfoError<C::Error, C::ResponseError, D::Error>> {
        let endpoint = if http_client.uses_mtls() {
            self.mtls_userinfo_endpoint
                .as_ref()
                .unwrap_or(&self.userinfo_endpoint)
        } else {
            &self.userinfo_endpoint
        };

        let header_value = access_token
            .expose_header_value()
            .context(BadAuthorizationHeaderSnafu)?;

        let dpop_jkt = access_token.dpop_jkt();
        let mut retried = false;

        loop {
            let mut headers = HeaderMap::new();
            headers.insert(http::header::AUTHORIZATION, header_value.clone());

            // Add a DPoP proof if the access token is DPoP-bound.
            if let Some(jkt) = dpop_jkt
                && let Some(proof) = self
                    .dpop
                    .proof(&Method::GET, endpoint.as_uri(), access_token.token(), jkt)
                    .await
                    .context(DPoPSnafu)?
            {
                headers.insert(
                    "DPoP",
                    HeaderValue::from_str(proof.expose_secret()).context(DPoPHeaderSnafu)?,
                );
            }

            let (mut parts, ()) = http::Request::new(()).into_parts();
            parts.headers = headers;
            parts.uri = endpoint.as_uri().clone();
            let request = http::Request::from_parts(parts, Bytes::new());

            let response = http_client.execute(request).await.context(RequestSnafu)?;

            let status = response.status();
            let response_headers = response.headers();
            let body = response.body().await.context(ResponseBodySnafu)?;

            // Retry once if the server challenges with a DPoP nonce (RFC 9449 §7.2).
            if !retried
                && status == StatusCode::UNAUTHORIZED
                && let Some(nonce) = response_headers
                    .get("DPoP-Nonce")
                    .and_then(|v| v.to_str().ok())
            {
                self.dpop.update_nonce(endpoint.as_uri(), nonce.to_string());
                retried = true;
                continue;
            }

            ensure!(
                status.is_success(),
                BadStatusSnafu {
                    status,
                    headers: response_headers,
                    body: body.to_vec(),
                }
            );

            // OIDC Core §5.3.2: content-type MUST be "application/json" for plain
            // JSON responses, or "application/jwt" for signed/encrypted responses.
            let ct_header = response_headers
                .get(http::header::CONTENT_TYPE)
                .context(MissingContentTypeSnafu)?;
            let ct_str = ct_header
                .to_str()
                .ok()
                .context(UnexpectedContentTypeSnafu {
                    content_type: String::from_utf8_lossy(ct_header.as_bytes()),
                })?;

            let media_type = ct_str.split(';').next().unwrap_or(ct_str).trim();
            let is_jwt_response = media_type.eq_ignore_ascii_case("application/jwt");

            if !is_jwt_response {
                ensure!(
                    media_type.eq_ignore_ascii_case("application/json"),
                    UnexpectedContentTypeSnafu {
                        content_type: media_type,
                    }
                );
            }

            let user_info: UserInfo<Extra> = if is_jwt_response {
                self.decode_jwt_response::<C>(&body).await?
            } else {
                serde_json::from_slice(&body).context(DeserializeSnafu)?
            };

            ensure!(
                user_info.sub == expected_sub,
                SubMismatchSnafu {
                    expected: expected_sub,
                    actual: &user_info.sub,
                }
            );

            return Ok(user_info);
        }
    }

    /// Decode and validate a JWT-encoded `UserInfo` response body.
    async fn decode_jwt_response<C: HttpClient>(
        &self,
        body: &[u8],
    ) -> Result<UserInfo<Extra>, UserInfoError<C::Error, C::ResponseError, D::Error>> {
        let jwt_validator = self
            .jwt_validator
            .as_ref()
            .context(JwtResponseNotSupportedSnafu)?;

        let jwt_str = std::str::from_utf8(body)
            .ok()
            .context(MalformedJwtResponseBodySnafu)?;

        // Parse and validate the JWT (signature, iss, aud, exp) with
        // claims as a raw Value. `JwtClaims` splits standard JWT claims
        // (sub, iss, aud, …) from the rest via `#[serde(flatten)]`, so
        // `validated.claims` is everything *except* the registered set.
        let parsed =
            parse_compact_jws::<(), serde_json::Value>(jwt_str.trim()).context(JwtParseSnafu)?;
        let validated = jwt_validator
            .validate_parsed_jws(parsed)
            .await
            .context(JwtValidationSnafu)?;

        // Reconstruct the full claim set: re-insert `sub` (which
        // `JwtClaims` consumed) so `UserInfo` can deserialize it.
        let mut claims_map = match validated.claims {
            serde_json::Value::Object(m) => m,
            _ => serde_json::Map::new(),
        };
        if let Some(sub) = &validated.subject {
            claims_map.insert("sub".to_owned(), serde_json::Value::String(sub.clone()));
        }

        serde_json::from_value(serde_json::Value::Object(claims_map)).context(DeserializeSnafu)
    }
}

/// Standard OIDC `UserInfo` claims (OIDC Core §5.1).
///
/// The `Extra` type parameter captures additional claims beyond the standard set.
/// By default extra claims are ignored; specify a custom type to capture them.
#[derive(Debug, Clone, Deserialize)]
pub struct UserInfo<Extra = ()> {
    /// Subject identifier.
    pub sub: String,
    /// Full name.
    pub name: Option<String>,
    /// Given name(s) or first name(s).
    pub given_name: Option<String>,
    /// Surname(s) or last name(s).
    pub family_name: Option<String>,
    /// Middle name(s).
    pub middle_name: Option<String>,
    /// Casual name.
    pub nickname: Option<String>,
    /// Shorthand name by which the End-User wishes to be referred to.
    pub preferred_username: Option<String>,
    /// URL of the End-User's profile page.
    pub profile: Option<String>,
    /// URL of the End-User's profile picture.
    pub picture: Option<String>,
    /// URL of the End-User's Web page or blog.
    pub website: Option<String>,
    /// End-User's preferred e-mail address.
    pub email: Option<String>,
    /// `true` if the End-User's e-mail address has been verified.
    pub email_verified: Option<bool>,
    /// End-User's gender.
    pub gender: Option<String>,
    /// End-User's birthday.
    pub birthdate: Option<String>,
    /// Time zone database string.
    pub zoneinfo: Option<String>,
    /// End-User's locale.
    pub locale: Option<String>,
    /// End-User's preferred telephone number.
    pub phone_number: Option<String>,
    /// `true` if the End-User's phone number has been verified.
    pub phone_number_verified: Option<bool>,
    /// End-User's preferred postal address (OIDC Core §5.1.1).
    pub address: Option<Address>,
    /// Time the End-User's information was last updated (seconds since epoch).
    pub updated_at: Option<i64>,

    /// Extra claims beyond the standard OIDC `UserInfo` set.
    #[serde(flatten)]
    pub extra: Extra,
}

/// Postal address claim (OIDC Core §5.1.1).
#[derive(Debug, Clone, Deserialize)]
pub struct Address {
    /// Full mailing address, formatted for display or use on a mailing label.
    pub formatted: Option<String>,
    /// Full street address component, which MAY include house number, street
    /// name, Post Office Box, and multi-line extended street address information.
    pub street_address: Option<String>,
    /// City or locality component.
    pub locality: Option<String>,
    /// State, province, prefecture, or region component.
    pub region: Option<String>,
    /// Zip code or postal code component.
    pub postal_code: Option<String>,
    /// Country name component.
    pub country: Option<String>,
}

/// An error that occurs when building a [`UserInfoClient`].
#[derive(Debug, Snafu)]
pub enum UserInfoBuildError {
    /// `issuer` is required when JWT validation is configured.
    #[snafu(display("issuer is required when JWT validation is configured for UserInfo"))]
    MissingIssuer,
    /// `client_id` is required when JWT validation is configured.
    #[snafu(display("client_id is required when JWT validation is configured for UserInfo"))]
    MissingClientId,
}

impl crate::core::Error for UserInfoBuildError {
    fn is_retryable(&self) -> bool {
        false
    }
}

/// Errors that can occur when calling the `UserInfo` endpoint.
#[derive(Debug, Snafu)]
pub enum UserInfoError<
    HttpReqErr: crate::core::Error,
    HttpRespErr: crate::core::Error,
    DPoPErr: crate::core::Error,
> {
    /// Could not build the Authorization header from the access token.
    #[snafu(display("Failed to build Authorization header for UserInfo request"))]
    BadAuthorizationHeader {
        /// The underlying error.
        source: InvalidHeaderValue,
    },
    /// `DPoP` proof generation failed.
    #[snafu(display("Failed to generate DPoP proof for UserInfo request"))]
    DPoP {
        /// The underlying error.
        source: DPoPErr,
    },
    /// `DPoP` proof could not be set as an HTTP header.
    #[snafu(display("Failed to set DPoP proof as HTTP header"))]
    DPoPHeader {
        /// The underlying error.
        source: InvalidHeaderValue,
    },
    /// The HTTP request to the `UserInfo` endpoint failed.
    #[snafu(display("UserInfo request failed"))]
    Request {
        /// The underlying error.
        source: HttpReqErr,
    },
    /// Reading the HTTP response body failed.
    #[snafu(display("Failed to read UserInfo response body"))]
    ResponseBody {
        /// The underlying error.
        source: HttpRespErr,
    },
    /// The `UserInfo` endpoint returned `application/jwt` but no JWT validator was configured.
    ///
    /// Provide `jwks_uri` and `jws_verifier_factory` when building the client to enable
    /// JWT response validation.
    #[snafu(display(
        "UserInfo endpoint returned application/jwt but no JWT validator was configured"
    ))]
    JwtResponseNotSupported,
    /// The `UserInfo` JWT response could not be parsed as a compact JWS.
    #[snafu(display("Failed to parse UserInfo JWT response"))]
    JwtParse {
        /// The underlying parse error.
        source: JwsParseError,
    },
    /// JWT signature or claims validation failed on a `UserInfo` JWT response.
    #[snafu(display("UserInfo JWT response validation failed"))]
    JwtValidation {
        /// The underlying JWT validation error.
        source: JwtValidationError,
    },
    /// The `UserInfo` JWT response body is not valid UTF-8.
    #[snafu(display("UserInfo JWT response body is not valid UTF-8"))]
    MalformedJwtResponseBody,
    /// The `UserInfo` response is missing the `Content-Type` header.
    ///
    /// Per OIDC Core §5.3.2, the content-type MUST be `application/json` or
    /// `application/jwt`.
    #[snafu(display("UserInfo response is missing the Content-Type header"))]
    MissingContentType,
    /// The `UserInfo` endpoint returned an unexpected Content-Type.
    ///
    /// Per OIDC Core §5.3.2, the content-type MUST be `application/json` for
    /// plain JSON responses or `application/jwt` for signed/encrypted responses.
    #[snafu(display("UserInfo endpoint returned unexpected Content-Type: {content_type}"))]
    UnexpectedContentType {
        /// The Content-Type value received.
        content_type: String,
    },
    /// The response body could not be deserialized as JSON.
    #[snafu(display("Failed to deserialize UserInfo response"))]
    Deserialize {
        /// The underlying error.
        source: serde_json::Error,
    },
    /// The `sub` claim in the `UserInfo` response does not match the ID Token (OIDC Core §5.3.2).
    #[snafu(display("UserInfo sub mismatch: expected {expected}, got {actual}"))]
    SubMismatch {
        /// The expected `sub` from the ID Token.
        expected: String,
        /// The `sub` returned by the `UserInfo` endpoint.
        actual: String,
    },
    /// The server returned a non-success HTTP status code.
    #[snafu(display("UserInfo endpoint returned HTTP {status}"))]
    BadStatus {
        /// The HTTP status code.
        status: StatusCode,
        /// The response headers.
        headers: HeaderMap,
        /// The raw response body.
        body: Vec<u8>,
    },
}

impl<HttpReqErr: crate::core::Error, HttpRespErr: crate::core::Error, DPoPErr: crate::core::Error>
    crate::core::Error for UserInfoError<HttpReqErr, HttpRespErr, DPoPErr>
{
    fn is_retryable(&self) -> bool {
        match self {
            Self::BadAuthorizationHeader { .. }
            | Self::DPoP { .. }
            | Self::DPoPHeader { .. }
            | Self::JwtResponseNotSupported
            | Self::JwtParse { .. }
            | Self::JwtValidation { .. }
            | Self::MalformedJwtResponseBody
            | Self::MissingContentType
            | Self::UnexpectedContentType { .. }
            | Self::Deserialize { .. }
            | Self::SubMismatch { .. }
            | Self::BadStatus { .. } => false,
            Self::Request { source } => source.is_retryable(),
            Self::ResponseBody { source } => source.is_retryable(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;
    use crate::{
        core::{
            IntoEndpointUrl,
            crypto::{
                KeyMatchStrength,
                verifier::{BoxedJwsVerifier, JwsVerifier, KeyMatch, VerifyError},
            },
            dpop::NoDPoP,
            secrets::SecretString,
        },
        token::BearerAccessToken,
    };

    /// Mock HTTP response with configurable status, headers, and body.
    struct MockResponse {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    }

    impl HttpResponse for MockResponse {
        type Error = Infallible;

        fn status(&self) -> StatusCode {
            self.status
        }

        fn headers(&self) -> HeaderMap {
            self.headers.clone()
        }

        async fn body(self) -> Result<Bytes, Infallible> {
            Ok(self.body)
        }
    }

    /// Mock HTTP client that returns a preconfigured response.
    struct MockHttpClient {
        response: std::sync::Mutex<Option<MockResponse>>,
    }

    impl MockHttpClient {
        fn new(response: MockResponse) -> Self {
            Self {
                response: std::sync::Mutex::new(Some(response)),
            }
        }
    }

    impl HttpClient for MockHttpClient {
        type Response = MockResponse;
        type Error = Infallible;
        type ResponseError = Infallible;

        async fn execute(
            &self,
            _request: http::Request<Bytes>,
        ) -> Result<MockResponse, Infallible> {
            Ok(self
                .response
                .lock()
                .unwrap()
                .take()
                .expect("MockHttpClient can only be called once"))
        }
    }

    fn bearer_token(token: &str) -> AccessToken {
        AccessToken::Bearer(BearerAccessToken::new(
            SecretString::new(token),
            crate::core::platform::SystemTime::now(),
            None,
        ))
    }

    fn json_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        h
    }

    fn client() -> UserInfoClient<NoDPoP> {
        UserInfoClient {
            userinfo_endpoint: "https://op.example.com/userinfo"
                .into_endpoint_url()
                .unwrap(),
            mtls_userinfo_endpoint: None,
            dpop: NoDPoP,
            jwt_validator: None,
            _phantom: PhantomData,
        }
    }

    #[tokio::test]
    async fn successful_response() {
        let body = serde_json::json!({
            "sub": "248289761001",
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe",
            "email": "janedoe@example.com",
            "email_verified": true,
            "picture": "http://example.com/janedoe/me.jpg"
        });

        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let result = client()
            .get(&http, &bearer_token("tok"), "248289761001")
            .await
            .unwrap();

        assert_eq!(result.sub, "248289761001");
        assert_eq!(result.name.as_deref(), Some("Jane Doe"));
        assert_eq!(result.given_name.as_deref(), Some("Jane"));
        assert_eq!(result.family_name.as_deref(), Some("Doe"));
        assert_eq!(result.email.as_deref(), Some("janedoe@example.com"));
        assert_eq!(result.email_verified, Some(true));
        assert_eq!(
            result.picture.as_deref(),
            Some("http://example.com/janedoe/me.jpg")
        );
    }

    #[tokio::test]
    async fn sub_mismatch_returns_error() {
        let body = serde_json::json!({ "sub": "wrong-subject" });

        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "expected-subject")
            .await
            .unwrap_err();

        assert!(matches!(err, UserInfoError::SubMismatch { .. }));
        assert!(
            err.to_string()
                .contains("expected expected-subject, got wrong-subject")
        );
    }

    #[tokio::test]
    async fn non_success_status_returns_bad_status() {
        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::FORBIDDEN,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"access denied"),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "sub")
            .await
            .unwrap_err();

        assert!(
            matches!(&err, UserInfoError::BadStatus { status, body, .. }
                if *status == StatusCode::FORBIDDEN && body == b"access denied"),
            "expected BadStatus with FORBIDDEN, got {err:?}"
        );
    }

    #[tokio::test]
    async fn invalid_json_returns_deserialize_error() {
        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from_static(b"not json"),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "sub")
            .await
            .unwrap_err();

        assert!(matches!(err, UserInfoError::Deserialize { .. }));
    }

    #[tokio::test]
    async fn missing_sub_returns_deserialize_error() {
        let body = serde_json::json!({ "name": "Jane Doe" });

        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "sub")
            .await
            .unwrap_err();

        assert!(matches!(err, UserInfoError::Deserialize { .. }));
    }

    #[tokio::test]
    async fn unknown_claims_are_ignored() {
        let body = serde_json::json!({
            "sub": "user1",
            "custom_claim": "custom_value",
            "org_id": 42
        });

        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        // Default Extra = () ignores extra claims.
        let result = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap();

        assert_eq!(result.sub, "user1");
        assert!(result.name.is_none());
    }

    #[tokio::test]
    async fn typed_extra_claims() {
        #[derive(Debug, Clone, Deserialize)]
        struct MyClaims {
            org_id: u64,
            role: String,
        }

        let body = serde_json::json!({
            "sub": "user1",
            "org_id": 42,
            "role": "admin"
        });

        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let client: UserInfoClient<NoDPoP, MyClaims> = UserInfoClient {
            userinfo_endpoint: "https://op.example.com/userinfo"
                .into_endpoint_url()
                .unwrap(),
            mtls_userinfo_endpoint: None,
            dpop: NoDPoP,
            jwt_validator: None,
            _phantom: PhantomData,
        };

        let result = client
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap();

        assert_eq!(result.sub, "user1");
        assert_eq!(result.extra.org_id, 42);
        assert_eq!(result.extra.role, "admin");
    }

    #[tokio::test]
    async fn address_claim_deserialized() {
        let body = serde_json::json!({
            "sub": "user1",
            "address": {
                "formatted": "123 Main St\nAnytown, CA 90210",
                "street_address": "123 Main St",
                "locality": "Anytown",
                "region": "CA",
                "postal_code": "90210",
                "country": "US"
            }
        });

        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let result = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap();

        let addr = result.address.unwrap();
        assert_eq!(addr.locality.as_deref(), Some("Anytown"));
        assert_eq!(addr.region.as_deref(), Some("CA"));
        assert_eq!(addr.postal_code.as_deref(), Some("90210"));
        assert_eq!(addr.country.as_deref(), Some("US"));
    }

    #[tokio::test]
    async fn jwt_content_type_returns_not_supported() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/jwt"),
        );

        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig"),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(matches!(err, UserInfoError::JwtResponseNotSupported));
        assert!(err.to_string().contains("application/jwt"));
    }

    #[tokio::test]
    async fn jwt_content_type_with_charset_returns_not_supported() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/jwt; charset=utf-8"),
        );

        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig"),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(matches!(err, UserInfoError::JwtResponseNotSupported));
    }

    #[tokio::test]
    async fn unexpected_content_type_returns_error() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        );

        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"<html>not json</html>"),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(matches!(err, UserInfoError::UnexpectedContentType { .. }));
        assert!(err.to_string().contains("text/html"));
    }

    #[tokio::test]
    async fn json_content_type_with_charset_succeeds() {
        let body = serde_json::json!({ "sub": "user1" });

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );

        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let result = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap();

        assert_eq!(result.sub, "user1");
    }

    #[tokio::test]
    async fn all_optional_claims_absent() {
        let body = serde_json::json!({ "sub": "minimal" });

        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let result = client()
            .get(&http, &bearer_token("tok"), "minimal")
            .await
            .unwrap();

        assert_eq!(result.sub, "minimal");
        assert!(result.name.is_none());
        assert!(result.email.is_none());
        assert!(result.address.is_none());
        assert!(result.updated_at.is_none());
    }

    #[tokio::test]
    async fn missing_content_type_returns_error() {
        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"{\"sub\":\"user1\"}"),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(matches!(err, UserInfoError::MissingContentType));
    }

    // --- JWT response tests ---

    /// Mock JWS verifier that accepts any signature.
    #[derive(Debug)]
    struct AcceptAllVerifier;

    impl JwsVerifier for AcceptAllVerifier {
        type Error = crate::core::BoxedError;

        fn key_match(&self, _key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
            Some(KeyMatchStrength::ByAlgorithm)
        }

        async fn verify(
            &self,
            _input: &[u8],
            _signature: &[u8],
            _key: &KeyMatch<'_>,
        ) -> Result<(), VerifyError<Self::Error>> {
            Ok(())
        }
    }

    /// Build a compact JWS from header and claims JSON values.
    ///
    /// Uses a dummy signature — pair with [`AcceptAllVerifier`] in tests.
    fn build_test_jwt(header: &serde_json::Value, claims: &serde_json::Value) -> String {
        use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
        let h = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
        let c = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let s = BASE64_URL_SAFE_NO_PAD.encode(b"fake-signature");
        format!("{h}.{c}.{s}")
    }

    fn jwt_client() -> UserInfoClient<NoDPoP> {
        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(AcceptAllVerifier))
            .iss(ClaimCheck::required_value("https://op.example.com"))
            .aud(ClaimCheck::required_value("my-client"))
            .build();
        UserInfoClient {
            userinfo_endpoint: "https://op.example.com/userinfo"
                .into_endpoint_url()
                .unwrap(),
            mtls_userinfo_endpoint: None,
            dpop: NoDPoP,
            jwt_validator: Some(validator),
            _phantom: PhantomData,
        }
    }

    fn jwt_response(jwt: &str) -> MockResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/jwt"),
        );
        MockResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from(jwt.to_owned()),
        }
    }

    #[tokio::test]
    async fn jwt_response_validated() {
        let jwt = build_test_jwt(
            &serde_json::json!({"alg": "RS256"}),
            &serde_json::json!({
                "sub": "user1",
                "iss": "https://op.example.com",
                "aud": "my-client",
                "name": "Jane Doe",
                "email": "jane@example.com"
            }),
        );

        let http = MockHttpClient::new(jwt_response(&jwt));
        let result = jwt_client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap();

        assert_eq!(result.sub, "user1");
        assert_eq!(result.name.as_deref(), Some("Jane Doe"));
        assert_eq!(result.email.as_deref(), Some("jane@example.com"));
    }

    #[tokio::test]
    async fn jwt_response_without_validator_returns_not_supported() {
        let jwt = build_test_jwt(
            &serde_json::json!({"alg": "RS256"}),
            &serde_json::json!({"sub": "user1"}),
        );

        let http = MockHttpClient::new(jwt_response(&jwt));

        // `client()` has no jwt_validator configured.
        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(matches!(err, UserInfoError::JwtResponseNotSupported));
    }

    #[tokio::test]
    async fn jwt_response_invalid_utf8() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/jwt"),
        );

        let http = MockHttpClient::new(MockResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"\xff\xfe"),
        });

        let err = jwt_client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(matches!(err, UserInfoError::MalformedJwtResponseBody));
    }

    #[tokio::test]
    async fn jwt_response_sub_mismatch() {
        let jwt = build_test_jwt(
            &serde_json::json!({"alg": "RS256"}),
            &serde_json::json!({
                "sub": "wrong-user",
                "iss": "https://op.example.com",
                "aud": "my-client"
            }),
        );

        let http = MockHttpClient::new(jwt_response(&jwt));
        let err = jwt_client()
            .get(&http, &bearer_token("tok"), "expected-user")
            .await
            .unwrap_err();

        assert!(matches!(err, UserInfoError::SubMismatch { .. }));
    }
}
