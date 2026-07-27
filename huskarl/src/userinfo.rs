//! `OpenID` Connect `UserInfo` endpoint (OIDC Core §5.3).

use std::{collections::HashMap, str::Utf8Error, sync::Arc};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header::InvalidHeaderValue};
use serde::{Deserialize, Serialize};
use snafu::prelude::*;

#[cfg(test)]
use crate::core::RetryAdvice;
use crate::{
    authorizer::{challenge, dpop_resend_advised, extract_dpop_nonce},
    core::{
        EndpointUrl, Error, OAuthError,
        crypto::verifier::{JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform},
        dpop::{NoDPoP, ResourceServerDPoP},
        http::{FailedResponse, HttpClient, Idempotency, TruncatedBody},
        jwt::{
            JwsParseError, parse_compact_jws,
            validator::{ClaimCheck, JwtValidationError, JwtValidator},
        },
        server_metadata::{AuthorizationServerMetadata, missing_field},
    },
    grant::core::OAuth2ExchangeGrant,
    token::{AccessToken, id_token::StandardOidcProfileClaims},
};

/// `OpenID` Connect `UserInfo` client.
///
/// Standard claims are returned as typed fields on [`UserInfo`]; any
/// additional provider-specific claims are stored in [`UserInfo::extra`]. The
/// client validates the response subject against the ID token subject supplied
/// to [`get`](Self::get).
pub struct UserInfoClient {
    /// The URL of the `UserInfo` endpoint.
    userinfo_endpoint: EndpointUrl,

    /// The mTLS alias for the `UserInfo` endpoint (RFC 8705 §5).
    mtls_userinfo_endpoint: Option<EndpointUrl>,

    /// The `DPoP` proof implementation for resource server requests.
    dpop: Arc<dyn ResourceServerDPoP>,

    /// Optional JWT validator for `application/jwt` `UserInfo` responses (OIDC Core §5.3.2).
    jwt_validator: Option<JwtValidator>,

    /// Reject an unsigned `application/json` response (OIDC Registration §2,
    /// `userinfo_signed_response_alg`).
    require_signed_response: bool,
}

/// State of [`UserInfoClientBuilder`] returned by
/// [`UserInfoClient::builder_from_grant`]: `userinfo_endpoint`,
/// `mtls_userinfo_endpoint`, `dpop`, `jws_verifier`, `issuer`, and `client_id`
/// set.
// Name mirrors the `{Struct}{Method}State` alias `#[from_metadata]` generates,
// so the hand-written and generated constructors read alike.
pub type UserInfoClientBuilderFromGrantState = user_info_client_builder::SetClientId<
    user_info_client_builder::SetIssuer<
        user_info_client_builder::SetJwsVerifier<
            user_info_client_builder::SetDpop<
                user_info_client_builder::SetMtlsUserinfoEndpoint<
                    user_info_client_builder::SetUserinfoEndpoint,
                >,
            >,
        >,
    >,
>;

impl core::fmt::Debug for UserInfoClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserInfoClient")
            .field("userinfo_endpoint", &self.userinfo_endpoint)
            .field("mtls_userinfo_endpoint", &self.mtls_userinfo_endpoint)
            .field("require_signed_response", &self.require_signed_response)
            .finish_non_exhaustive()
    }
}

#[huskarl_macros::from_metadata(
    metadata = crate::core::server_metadata::AuthorizationServerMetadata
)]
#[bon::bon]
impl UserInfoClient {
    /// Creates a new [`UserInfoClient`].
    ///
    /// Callers use [`Self::builder()`], or [`Self::builder_from_metadata()`]
    /// to pre-populate the endpoint fields from server metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when a configured verifier has no `issuer` or
    /// `client_id`, when `require_signed_response` is enabled without a
    /// verifier, or when the verifier cannot be built from `jwks_uri`.
    #[builder(on(String, into))]
    pub async fn new(
        /// The URL of the `UserInfo` endpoint.
        #[from_metadata(path = "userinfo_endpoint?")]
        userinfo_endpoint: EndpointUrl,
        /// The mTLS alias for the `UserInfo` endpoint (RFC 8705 §5).
        #[from_metadata(path = "mtls_endpoint_aliases?.userinfo_endpoint?")]
        mtls_userinfo_endpoint: Option<EndpointUrl>,
        /// The `DPoP` proof implementation for resource server requests.
        ///
        /// Defaults to [`NoDPoP`] for plain bearer token flows.
        #[builder(
            with = |dpop: impl ResourceServerDPoP + 'static| Arc::new(dpop) as Arc<dyn ResourceServerDPoP>,
            default = Arc::new(NoDPoP),
        )]
        dpop: Arc<dyn ResourceServerDPoP>,
        /// JWKS URI for `application/jwt` `UserInfo` response validation.
        ///
        /// Must be provided together with `jws_verifier_factory` to enable JWT response
        /// validation.
        #[from_metadata(path = "jwks_uri?")]
        jwks_uri: Option<EndpointUrl>,
        /// JWS verifier factory for JWT response validation.
        ///
        /// When provided (along with `jwks_uri`), a [`JwtValidator`] is built that validates
        /// signed `UserInfo` responses. If the provider returns a JWT response without a
        /// validator configured, [`UserInfoError::JwtResponseNotSupported`] is returned.
        ///
        /// Ignored when `jws_verifier` is set.
        jws_verifier_factory: Option<Arc<dyn JwsVerifierFactory>>,
        /// An already-resolved JWS verifier for JWT response validation.
        ///
        /// Takes precedence over `jws_verifier_factory`, and needs no `jwks_uri`.
        #[builder(with = |verifier: impl JwsVerifier + 'static| Arc::new(verifier) as Arc<dyn JwsVerifier>)]
        jws_verifier: Option<Arc<dyn JwsVerifier>>,
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
        /// Required whenever a verifier is configured.
        #[from_metadata(path = "issuer")]
        issuer: Option<String>,
        /// The client ID, used for JWT `aud` claim validation (OIDC Core §5.3.2).
        ///
        /// Required whenever a verifier is configured.
        client_id: Option<String>,
        /// Reject a plain `application/json` response with
        /// [`UserInfoError::UnsignedResponse`], for a client registered with
        /// `userinfo_signed_response_alg` (OIDC Registration §2).
        ///
        /// Defaults to `false`, accepting either content type. Requires a
        /// verifier.
        #[builder(default)]
        require_signed_response: bool,
    ) -> Result<Self, Error> {
        #[cfg(feature = "default-jws-verifier-platform")]
        let jws_verifier_platform = Some(jws_verifier_platform);

        // The factory branch needs a `jwks_uri` to read keys from.
        let verifier = if let Some(verifier) = jws_verifier {
            Some(verifier)
        } else if let Some(jws_verifier_platform) = jws_verifier_platform
            && let Some(factory) = jws_verifier_factory
            && jwks_uri.is_some()
        {
            Some(
                factory
                    .build(jwks_uri.as_ref(), jws_verifier_platform)
                    .await?,
            )
        } else {
            None
        };

        let jwt_validator = if let Some(verifier) = verifier {
            let issuer = issuer.context(MissingIssuerSnafu)?;
            let client_id = client_id.context(MissingClientIdSnafu)?;

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

        // No verifier means no response of either content type is acceptable;
        // fail at build time rather than at the first request.
        ensure!(
            !require_signed_response || jwt_validator.is_some(),
            RequireSignedWithoutValidatorSnafu
        );

        Ok(Self {
            userinfo_endpoint,
            mtls_userinfo_endpoint,
            dpop,
            jwt_validator,
            require_signed_response,
        })
    }
}

impl UserInfoClient {
    /// Returns a [`UserInfoClientBuilder`] pre-populated from a grant and
    /// authorization server metadata.
    ///
    /// Sets `userinfo_endpoint` and `mtls_userinfo_endpoint` from the metadata,
    /// and `dpop`, `jws_verifier`, `issuer`, and `client_id` from the grant.
    /// Remaining fields — notably `require_signed_response`, which no grant
    /// records — are left to the caller.
    ///
    /// # Errors
    ///
    /// Returns an error if `metadata` has no `userinfo_endpoint`.
    ///
    /// ```rust
    /// use huskarl::userinfo::UserInfoClient;
    /// # use huskarl::{
    /// #     core::{server_metadata::AuthorizationServerMetadata, Error},
    /// #     grant::authorization_code::AuthorizationCodeGrant,
    /// # };
    /// # async fn example(
    /// #     grant: AuthorizationCodeGrant,
    /// #     metadata: AuthorizationServerMetadata,
    /// # ) -> Result<(), Error> {
    /// let client = UserInfoClient::builder_from_grant(&grant, &metadata)?
    ///     .require_signed_response(true)
    ///     .build()
    ///     .await?;
    /// # let _ = client;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder_from_grant(
        grant: &impl OAuth2ExchangeGrant,
        metadata: &AuthorizationServerMetadata,
    ) -> Result<UserInfoClientBuilder<UserInfoClientBuilderFromGrantState>, Error> {
        let userinfo_endpoint = metadata
            .userinfo_endpoint
            .clone()
            .ok_or_else(|| missing_field("userinfo_endpoint"))?;

        Ok(Self::builder()
            .userinfo_endpoint(userinfo_endpoint)
            .maybe_mtls_userinfo_endpoint(
                metadata
                    .mtls_endpoint_aliases
                    .as_ref()
                    .and_then(|a| a.userinfo_endpoint.clone()),
            )
            .dpop(grant.dpop().to_resource_server_dpop())
            .maybe_jws_verifier(grant.jws_verifier())
            .maybe_issuer(grant.issuer())
            .maybe_client_id(grant.client_id()))
    }
    /// Call the `UserInfo` endpoint with the given access token.
    ///
    /// Pass the ID token's `sub` claim as `expected_sub`. The response is
    /// rejected unless its `sub` matches exactly, as required by OIDC Core
    /// §5.3.2.
    ///
    /// # Errors
    ///
    /// Returns an error if the request or `DPoP` proof fails; the endpoint
    /// returns a non-success status; the content type is missing or unsupported;
    /// JSON decoding, JWT parsing, signature validation, or claim validation
    /// fails; a signed response is required but plain JSON is returned; or
    /// `sub` differs from `expected_sub`.
    ///
    /// A `Bearer` or `DPoP` `WWW-Authenticate` challenge on a failed response is
    /// exposed through [`Error::verdict`](crate::core::Error::verdict).
    pub async fn get(
        &self,
        http_client: &impl HttpClient,
        access_token: &AccessToken,
        expected_sub: &str,
    ) -> Result<UserInfo, Error> {
        let endpoint = if http_client.uses_mtls() {
            self.mtls_userinfo_endpoint
                .as_ref()
                .unwrap_or(&self.userinfo_endpoint)
        } else {
            &self.userinfo_endpoint
        };

        let mut header_value = access_token
            .expose_header_value()
            .context(BadAuthorizationHeaderSnafu)?;
        header_value.set_sensitive(true);

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
                    .context(GeneratingProofSnafu)?
            {
                let mut proof_value =
                    HeaderValue::from_str(proof.expose_secret()).context(DPoPHeaderSnafu)?;
                proof_value.set_sensitive(true);
                headers.insert("DPoP", proof_value);
            }

            let (mut parts, ()) = http::Request::new(()).into_parts();
            parts.headers = headers;
            parts.uri = endpoint.as_uri().clone();
            let request = http::Request::from_parts(parts, Bytes::new());

            let response = http_client
                .execute(request, Idempotency::Idempotent)
                .await
                .context(RequestFailedSnafu)?;

            let status = response.status;
            let response_headers = response.headers;
            let body = response.body;

            // Servers may rotate the nonce on any response (RFC 9449 §8.1);
            // a use_dpop_nonce challenge earns one re-send (RFC 9449 §7.2).
            if let Some(nonce) = extract_dpop_nonce(&response_headers) {
                self.dpop.update_nonce(endpoint.as_uri(), nonce);
            }
            if !retried && dpop_resend_advised(status, &response_headers) {
                retried = true;
                continue;
            }

            if !status.is_success() {
                return Err(Error::from(UserInfoError::BadStatus {
                    status,
                    headers: response_headers,
                    body: TruncatedBody::from_bytes(&body),
                }));
            }

            // OIDC Core §5.3.2: content-type MUST be "application/json" for plain
            // JSON responses, or "application/jwt" for signed/encrypted responses.
            let ct_header = response_headers
                .get(http::header::CONTENT_TYPE)
                .ok_or_else(|| Error::from(UserInfoError::MissingContentType))?;
            let ct_str = ct_header.to_str().ok().ok_or_else(|| {
                Error::from(UserInfoError::UnexpectedContentType {
                    content_type: String::from_utf8_lossy(ct_header.as_bytes()).into_owned(),
                })
            })?;

            let media_type = ct_str.split(';').next().unwrap_or(ct_str).trim();
            let is_jwt_response = media_type.eq_ignore_ascii_case("application/jwt");

            if !is_jwt_response && !media_type.eq_ignore_ascii_case("application/json") {
                return Err(Error::from(UserInfoError::UnexpectedContentType {
                    content_type: media_type.to_owned(),
                }));
            }

            // Falling back to the unverified path on the server's say-so is a
            // signature-stripping downgrade.
            if self.require_signed_response && !is_jwt_response {
                return Err(Error::from(UserInfoError::UnsignedResponse));
            }

            let user_info: UserInfo = if is_jwt_response {
                self.decode_jwt_response(&body).await?
            } else {
                serde_json::from_slice(&body).context(DeserializeSnafu)?
            };

            if user_info.sub != expected_sub {
                return Err(Error::from(UserInfoError::SubMismatch {
                    expected: expected_sub.to_owned(),
                    actual: user_info.sub.clone(),
                }));
            }

            return Ok(user_info);
        }
    }

    /// Decode and validate a JWT-encoded `UserInfo` response body.
    async fn decode_jwt_response(&self, body: &[u8]) -> Result<UserInfo, Error> {
        let jwt_validator = self
            .jwt_validator
            .as_ref()
            .ok_or_else(|| Error::from(UserInfoError::JwtResponseNotSupported))?;

        let jwt_str = std::str::from_utf8(body).context(MalformedJwtResponseBodySnafu)?;

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
        if let Some(sub) = &validated.sub {
            claims_map.insert("sub".to_owned(), serde_json::Value::String(sub.clone()));
        }

        Ok(
            serde_json::from_value(serde_json::Value::Object(claims_map))
                .context(DeserializeSnafu)?,
        )
    }
}

/// Claims returned by an OIDC `UserInfo` response (OIDC Core §5.1).
///
/// Standard profile claims live in [`profile`](Self::profile) — the same
/// [`StandardOidcProfileClaims`] set that may be asserted in an ID token.
/// Claims beyond the standard set are stored in [`extra`](Self::extra). To use
/// an extension claim as a typed value, deserialize it on demand, for example:
/// `serde_json::from_value(user_info.extra.remove("groups")?)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UserInfo {
    /// Subject identifier.
    pub sub: String,

    /// Standard OIDC profile claims (OIDC Core §5.1), flattened into the
    /// response's claim set.
    #[serde(flatten)]
    pub profile: StandardOidcProfileClaims,

    /// Extra claims beyond the standard OIDC `UserInfo` set.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// The cause of a [`UserInfoClient`] build failure.
#[derive(Debug, Snafu, huskarl_macros::Classify)]
#[non_exhaustive]
pub(crate) enum UserInfoBuildError {
    /// `issuer` is required when JWT validation is configured.
    #[snafu(display("issuer is required when JWT validation is configured for UserInfo"))]
    #[classify(no)]
    MissingIssuer,
    /// `client_id` is required when JWT validation is configured.
    #[snafu(display("client_id is required when JWT validation is configured for UserInfo"))]
    #[classify(no)]
    MissingClientId,
    /// `require_signed_response` was set without JWT validation configured.
    #[snafu(display(
        "require_signed_response is set but no JWT validator is configured for UserInfo; \
         supply 'jwks_uri' and 'jws_verifier_factory', or unset the requirement — no \
         response of either content type could be accepted"
    ))]
    #[classify(no)]
    RequireSignedWithoutValidator,
}

/// The cause of a `UserInfo` request failure.
#[derive(Debug, Snafu, huskarl_macros::Classify)]
#[non_exhaustive]
pub(crate) enum UserInfoError {
    /// Could not build the Authorization header from the access token.
    #[snafu(display("failed to build Authorization header for UserInfo request"))]
    #[classify(no)]
    BadAuthorizationHeader {
        /// The underlying error.
        source: InvalidHeaderValue,
    },
    /// `DPoP` proof could not be set as an HTTP header.
    #[snafu(display("failed to set DPoP proof as HTTP header"))]
    #[classify(no)]
    DPoPHeader {
        /// The underlying error.
        source: InvalidHeaderValue,
    },
    /// The `UserInfo` endpoint returned `application/jwt` but no JWT validator was configured.
    ///
    /// Provide `jwks_uri` and `jws_verifier_factory` when building the client to enable
    /// JWT response validation.
    #[snafu(display(
        "UserInfo endpoint returned application/jwt but no JWT validator was configured"
    ))]
    #[classify(no)]
    JwtResponseNotSupported,
    /// The `UserInfo` JWT response could not be parsed as a compact JWS.
    #[snafu(display("failed to parse UserInfo JWT response"))]
    #[classify(no)]
    JwtParse {
        /// The underlying parse error.
        source: JwsParseError,
    },
    /// JWT signature or claims validation failed on a `UserInfo` JWT response.
    #[snafu(display("UserInfo JWT response validation failed"))]
    #[classify(with = UserInfoError::jwt_validation_origin)]
    JwtValidation {
        /// The underlying JWT validation error.
        source: JwtValidationError,
    },
    /// The `UserInfo` JWT response body is not valid UTF-8.
    #[snafu(display("UserInfo JWT response body is not valid UTF-8"))]
    #[classify(no)]
    MalformedJwtResponseBody { source: Utf8Error },
    /// The `UserInfo` response is missing the `Content-Type` header.
    ///
    /// Per OIDC Core §5.3.2, the content-type MUST be `application/json` or
    /// `application/jwt`.
    #[snafu(display("UserInfo response is missing the Content-Type header"))]
    #[classify(no)]
    MissingContentType,
    /// The `UserInfo` endpoint returned `application/json` but the client was
    /// built with `require_signed_response`.
    #[snafu(display(
        "UserInfo endpoint returned an unsigned application/json response but \
         require_signed_response is set"
    ))]
    #[classify(no)]
    UnsignedResponse,
    /// The `UserInfo` endpoint returned an unexpected Content-Type.
    ///
    /// Per OIDC Core §5.3.2, the content-type MUST be `application/json` for
    /// plain JSON responses or `application/jwt` for signed/encrypted responses.
    #[snafu(display("UserInfo endpoint returned unexpected Content-Type: {content_type}"))]
    #[classify(no)]
    UnexpectedContentType {
        /// The Content-Type value received.
        content_type: String,
    },
    /// The response body could not be deserialized as JSON.
    #[snafu(display("failed to deserialize UserInfo response"))]
    #[classify(no)]
    Deserialize {
        /// The underlying error.
        source: serde_json::Error,
    },
    /// The `sub` claim in the `UserInfo` response does not match the ID Token (OIDC Core §5.3.2).
    #[snafu(display("UserInfo sub mismatch: expected {expected}, got {actual}"))]
    #[classify(no)]
    SubMismatch {
        /// The expected `sub` from the ID Token.
        expected: String,
        /// The `sub` returned by the `UserInfo` endpoint.
        actual: String,
    },
    /// The `DPoP` proof for the request could not be generated.
    #[snafu(display("generating DPoP proof for UserInfo request"))]
    GeneratingProof {
        /// The underlying error.
        source: Error,
    },
    /// The HTTP request itself failed.
    #[snafu(display("UserInfo request failed"))]
    RequestFailed {
        /// The underlying error.
        source: Error,
    },
    /// The server returned a non-success HTTP status code.
    #[snafu(display("UserInfo endpoint returned HTTP {status}: {body}"))]
    #[classify(with = UserInfoError::read_off_the_response)]
    BadStatus {
        /// The HTTP status code.
        status: StatusCode,
        /// The response headers, used to inspect `WWW-Authenticate` challenges.
        headers: HeaderMap,
        /// The response body, rendered as a bounded prefix.
        body: TruncatedBody,
    },
}

impl UserInfoError {
    fn jwt_validation_origin(
        source: &JwtValidationError,
    ) -> crate::core::error::propagation::Origin<'_> {
        crate::core::error::propagation::Cause::origin(source)
    }

    /// Classifies the response using its HTTP status and authentication challenge.
    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "Classify handlers receive references to every variant field"
    )]
    fn read_off_the_response(
        status: &StatusCode,
        headers: &HeaderMap,
        _body: &TruncatedBody,
    ) -> crate::core::error::propagation::Origin<'static> {
        use crate::core::error::propagation::Origin;

        let Some(failed) = FailedResponse::new(*status, headers) else {
            // `BadStatus` should only be constructed for non-success responses.
            return Origin::Establishes(crate::core::RetryAdvice::No.into());
        };
        let verdict = challenge::parse_challenges(headers)
            .into_iter()
            .filter(|challenge| challenge.is_scheme("Bearer") || challenge.is_scheme("DPoP"))
            .find_map(|challenge| {
                challenge.error().map(|code| {
                    OAuthError::new(code)
                        .with_description(challenge.param("error_description").map(str::to_owned))
                        .with_uri(challenge.param("error_uri").map(str::to_owned))
                })
            });
        Origin::Establishes(failed.classification(verdict))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{
            EndpointUrl, OAuthErrorCode,
            crypto::{
                KeyMatchStrength,
                verifier::{JwsVerifier, KeyMatch, VerifyError},
            },
            dpop::NoDPoP,
            http::HttpResponse,
            platform::MaybeSendBoxFuture,
            secrets::SecretString,
        },
        token::BearerAccessToken,
    };

    /// Mock HTTP client that serves preconfigured responses in order.
    struct MockHttpClient {
        responses: std::sync::Mutex<std::collections::VecDeque<HttpResponse>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl MockHttpClient {
        fn new(response: HttpResponse) -> Self {
            Self::sequence(vec![response])
        }

        fn sequence(responses: Vec<HttpResponse>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses.into()),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl HttpClient for MockHttpClient {
        fn execute(
            &self,
            _request: http::Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let response = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("MockHttpClient ran out of responses");
            Box::pin(async move { Ok(response) })
        }
    }

    // Extracts the typed cause without depending on display text.
    fn userinfo_source(err: &Error) -> &UserInfoError {
        err.cause()
            .downcast_ref::<UserInfoError>()
            .expect("carries a UserInfoError")
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

    fn client() -> UserInfoClient {
        UserInfoClient {
            userinfo_endpoint: "https://op.example.com/userinfo"
                .parse::<EndpointUrl>()
                .unwrap(),
            mtls_userinfo_endpoint: None,
            dpop: Arc::new(NoDPoP),
            jwt_validator: None,
            require_signed_response: false,
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

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let result = client()
            .get(&http, &bearer_token("tok"), "248289761001")
            .await
            .unwrap();

        assert_eq!(result.sub, "248289761001");
        assert_eq!(result.profile.name.as_deref(), Some("Jane Doe"));
        assert_eq!(result.profile.given_name.as_deref(), Some("Jane"));
        assert_eq!(result.profile.family_name.as_deref(), Some("Doe"));
        assert_eq!(result.profile.email.as_deref(), Some("janedoe@example.com"));
        assert_eq!(result.profile.email_verified, Some(true));
        assert_eq!(
            result.profile.picture.as_deref(),
            Some("http://example.com/janedoe/me.jpg")
        );
    }

    #[tokio::test]
    async fn sub_mismatch_returns_error() {
        let body = serde_json::json!({ "sub": "wrong-subject" });

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "expected-subject")
            .await
            .unwrap_err();

        let source = userinfo_source(&err);
        assert!(matches!(source, UserInfoError::SubMismatch { .. }));
        assert!(
            source
                .to_string()
                .contains("expected expected-subject, got wrong-subject")
        );
    }

    #[tokio::test]
    async fn non_success_status_returns_bad_status() {
        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::FORBIDDEN,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"access denied"),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "sub")
            .await
            .unwrap_err();

        assert!(
            matches!(userinfo_source(&err), UserInfoError::BadStatus { status, body, .. }
                if *status == StatusCode::FORBIDDEN && body.to_string() == "access denied"),
            "expected BadStatus with FORBIDDEN, got {err:?}"
        );
    }

    #[tokio::test]
    async fn invalid_json_returns_deserialize_error() {
        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from_static(b"not json"),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "sub")
            .await
            .unwrap_err();

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::Deserialize { .. }
        ));
    }

    #[tokio::test]
    async fn missing_sub_returns_deserialize_error() {
        let body = serde_json::json!({ "name": "Jane Doe" });

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "sub")
            .await
            .unwrap_err();

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::Deserialize { .. }
        ));
    }

    #[tokio::test]
    async fn unknown_claims_land_in_extra() {
        let body = serde_json::json!({
            "sub": "user1",
            "custom_claim": "custom_value",
            "org_id": 42
        });

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let result = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap();

        assert_eq!(result.sub, "user1");
        assert!(result.profile.name.is_none());
        assert_eq!(result.extra["custom_claim"], "custom_value");
        assert_eq!(result.extra["org_id"], 42);
    }

    #[tokio::test]
    async fn typed_extra_claims_on_demand() {
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

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let result = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap();

        // Callers wanting typed access deserialize out of the extras map.
        let claims: MyClaims =
            serde_json::from_value(serde_json::to_value(&result.extra).unwrap()).unwrap();

        assert_eq!(result.sub, "user1");
        assert_eq!(claims.org_id, 42);
        assert_eq!(claims.role, "admin");
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

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let result = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap();

        let addr = result.profile.address.unwrap();
        assert_eq!(addr.locality.as_deref(), Some("Anytown"));
        assert_eq!(addr.region.as_deref(), Some("CA"));
        assert_eq!(addr.postal_code.as_deref(), Some("90210"));
        assert_eq!(addr.country.as_deref(), Some("US"));
    }

    fn nonce_challenge_response() -> HttpResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"DPoP error="use_dpop_nonce""#),
        );
        headers.insert("DPoP-Nonce", HeaderValue::from_static("fresh-nonce"));
        HttpResponse {
            status: StatusCode::UNAUTHORIZED,
            headers,
            body: Bytes::new(),
        }
    }

    #[tokio::test]
    async fn nonce_challenge_retries_once() {
        let body = serde_json::json!({"sub": "user1"});
        let http = MockHttpClient::sequence(vec![
            nonce_challenge_response(),
            HttpResponse {
                status: StatusCode::OK,
                headers: json_headers(),
                body: Bytes::from(serde_json::to_vec(&body).unwrap()),
            },
        ]);

        let result = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap();

        assert_eq!(result.sub, "user1");
        assert_eq!(http.calls(), 2);
    }

    #[tokio::test]
    async fn second_nonce_challenge_returns_the_error() {
        let http =
            MockHttpClient::sequence(vec![nonce_challenge_response(), nonce_challenge_response()]);

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::BadStatus { status, .. } if *status == StatusCode::UNAUTHORIZED
        ));
        assert_eq!(http.calls(), 2);
    }

    // An `invalid_token` challenge is a verdict on the access token.
    #[tokio::test]
    async fn invalid_token_challenge_is_a_dead_credential() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "www-authenticate",
            HeaderValue::from_static(
                r#"Bearer error="invalid_token", error_description="expired""#,
            ),
        );
        let http = MockHttpClient::sequence(vec![HttpResponse {
            status: StatusCode::UNAUTHORIZED,
            headers,
            body: Bytes::new(),
        }]);

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(
            err.verdict()
                .is_some_and(|v| v.code() == &OAuthErrorCode::InvalidToken)
        );
    }

    #[tokio::test]
    async fn oauth_verdict_ignores_non_oauth_authentication_schemes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static(
                r#"Basic realm="legacy", error="invalid_grant", Bearer error="invalid_token""#,
            ),
        );
        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::UNAUTHORIZED,
            headers,
            body: Bytes::new(),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();
        assert_eq!(
            err.verdict().map(OAuthError::code),
            Some(&OAuthErrorCode::InvalidToken)
        );
    }

    #[tokio::test]
    async fn oauth_verdict_preserves_challenge_diagnostics() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static(
                r#"DPoP error="invalid_token", error_description="proof expired", error_uri="https://rs.example.com/errors/proof""#,
            ),
        );
        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::UNAUTHORIZED,
            headers,
            body: Bytes::new(),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();
        let verdict = err.verdict().expect("DPoP challenge carries a verdict");
        assert_eq!(verdict.description(), Some("proof expired"));
        assert_eq!(verdict.uri(), Some("https://rs.example.com/errors/proof"));
    }

    // A bare 401 does not establish why authentication failed.
    #[tokio::test]
    async fn a_bare_401_stays_protocol() {
        let http = MockHttpClient::sequence(vec![HttpResponse {
            status: StatusCode::UNAUTHORIZED,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }]);

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(err.verdict().is_none());
        assert_eq!(err.retry_advice(), crate::core::RetryAdvice::No);
    }

    // A transient response preserves its retry interval.
    #[tokio::test]
    async fn a_5xx_is_a_retryable_server_condition() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::RETRY_AFTER, HeaderValue::from_static("10"));
        let http = MockHttpClient::sequence(vec![HttpResponse {
            status: StatusCode::SERVICE_UNAVAILABLE,
            headers,
            body: Bytes::new(),
        }]);

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert_eq!(
            err.retry_advice(),
            RetryAdvice::retry_after(crate::core::platform::Duration::from_secs(10))
        );
    }

    #[tokio::test]
    async fn nonce_header_without_challenge_does_not_retry() {
        // A plain 401 rotating the nonce (RFC 9449 §8.1) rejected the token
        // itself; a fresh nonce cannot fix it, so no re-send.
        let mut headers = HeaderMap::new();
        headers.insert("DPoP-Nonce", HeaderValue::from_static("rotated"));
        let http = MockHttpClient::sequence(vec![HttpResponse {
            status: StatusCode::UNAUTHORIZED,
            headers,
            body: Bytes::new(),
        }]);

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::BadStatus { .. }
        ));
        assert_eq!(http.calls(), 1);
    }

    #[tokio::test]
    async fn jwt_content_type_returns_not_supported() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/jwt"),
        );

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig"),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        let source = userinfo_source(&err);
        assert!(matches!(source, UserInfoError::JwtResponseNotSupported));
        assert!(source.to_string().contains("application/jwt"));
    }

    #[tokio::test]
    async fn jwt_content_type_with_charset_returns_not_supported() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/jwt; charset=utf-8"),
        );

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig"),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::JwtResponseNotSupported
        ));
    }

    #[tokio::test]
    async fn unexpected_content_type_returns_error() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        );

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"<html>not json</html>"),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        let source = userinfo_source(&err);
        assert!(matches!(
            source,
            UserInfoError::UnexpectedContentType { .. }
        ));
        assert!(source.to_string().contains("text/html"));
    }

    #[tokio::test]
    async fn json_content_type_with_charset_succeeds() {
        let body = serde_json::json!({ "sub": "user1" });

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );

        let http = MockHttpClient::new(HttpResponse {
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

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        });

        let result = client()
            .get(&http, &bearer_token("tok"), "minimal")
            .await
            .unwrap();

        assert_eq!(result.sub, "minimal");
        assert!(result.profile.name.is_none());
        assert!(result.profile.email.is_none());
        assert!(result.profile.address.is_none());
        assert!(result.profile.updated_at.is_none());
    }

    #[tokio::test]
    async fn missing_content_type_returns_error() {
        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"{\"sub\":\"user1\"}"),
        });

        let err = client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::MissingContentType
        ));
    }

    // --- JWT response tests ---

    /// Mock JWS verifier that accepts any signature.
    #[derive(Debug)]
    struct AcceptAllVerifier;

    impl JwsVerifier for AcceptAllVerifier {
        fn key_match(&self, _key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
            Some(KeyMatchStrength::ByAlgorithm)
        }

        fn verify<'a>(
            &'a self,
            _input: &'a [u8],
            _signature: &'a [u8],
            _key_match: &'a KeyMatch<'a>,
        ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
            Box::pin(async { Ok(()) })
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

    fn jwt_client() -> UserInfoClient {
        let validator = JwtValidator::builder()
            .verifier(AcceptAllVerifier)
            .iss(ClaimCheck::required_value("https://op.example.com"))
            .aud(ClaimCheck::required_value("my-client"))
            .build();
        UserInfoClient {
            userinfo_endpoint: "https://op.example.com/userinfo"
                .parse::<EndpointUrl>()
                .unwrap(),
            mtls_userinfo_endpoint: None,
            dpop: Arc::new(NoDPoP),
            jwt_validator: Some(validator),
            require_signed_response: false,
        }
    }

    fn jwt_response(jwt: &str) -> HttpResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/jwt"),
        );
        HttpResponse {
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
        assert_eq!(result.profile.name.as_deref(), Some("Jane Doe"));
        assert_eq!(result.profile.email.as_deref(), Some("jane@example.com"));
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

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::JwtResponseNotSupported
        ));
    }

    #[tokio::test]
    async fn jwt_response_invalid_utf8() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/jwt"),
        );

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"\xff\xfe"),
        });

        let err = jwt_client()
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::MalformedJwtResponseBody { source: _ }
        ));
    }

    // --- require_signed_response ---

    /// A client requiring signed responses rejects plain JSON rather than
    /// taking its claims unverified.
    #[tokio::test]
    async fn require_signed_response_rejects_json() {
        let mut client = jwt_client();
        client.require_signed_response = true;

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from_static(b"{\"sub\":\"user1\",\"email\":\"jane@example.com\"}"),
        });

        let err = client
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .expect_err("an unsigned response must not satisfy a signed-response client");

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::UnsignedResponse
        ));
    }

    /// The rejection happens before deserialization, so a well-formed unsigned
    /// body that would otherwise pass every later check still fails.
    #[tokio::test]
    async fn require_signed_response_rejects_json_before_sub_check() {
        let mut client = jwt_client();
        client.require_signed_response = true;

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from_static(b"not json at all"),
        });

        let err = client
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(
            matches!(userinfo_source(&err), UserInfoError::UnsignedResponse),
            "content type decides before the body is parsed, got {err:?}"
        );
    }

    /// The requirement does not disturb the signed path.
    #[tokio::test]
    async fn require_signed_response_accepts_jwt() {
        let jwt = build_test_jwt(
            &serde_json::json!({"alg": "RS256"}),
            &serde_json::json!({
                "sub": "user1",
                "iss": "https://op.example.com",
                "aud": "my-client"
            }),
        );

        let mut client = jwt_client();
        client.require_signed_response = true;

        let http = MockHttpClient::new(jwt_response(&jwt));
        let result = client
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap();

        assert_eq!(result.sub, "user1");
    }

    /// A non-JSON, non-JWT content type still reports the more specific error.
    #[tokio::test]
    async fn require_signed_response_keeps_content_type_error() {
        let mut client = jwt_client();
        client.require_signed_response = true;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        );
        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"<html/>"),
        });

        let err = client
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::UnexpectedContentType { .. }
        ));
    }

    /// Requiring signed responses with nothing to verify them would reject
    /// every response, so the builder refuses it.
    #[tokio::test]
    async fn require_signed_response_without_validator_is_a_build_error() {
        let err = UserInfoClient::builder()
            .userinfo_endpoint("https://op.example.com/userinfo".parse().unwrap())
            .require_signed_response(true)
            .build()
            .await
            .expect_err("no validator means no acceptable response");

        assert!(
            err.cause()
                .downcast_ref::<UserInfoBuildError>()
                .is_some_and(|e| matches!(e, UserInfoBuildError::RequireSignedWithoutValidator)),
            "got {err:?}"
        );
    }

    /// Factory that always fails, to prove `jws_verifier` short-circuits it.
    struct ExplodingFactory;

    impl JwsVerifierFactory for ExplodingFactory {
        fn build(
            &self,
            _jwks_uri: Option<&EndpointUrl>,
            _platform: Arc<dyn JwsVerifierPlatform>,
        ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, Error>> {
            Box::pin(async { Err(Error::new(RetryAdvice::No, "factory must not be called")) })
        }
    }

    /// A supplied `jws_verifier` needs no `jwks_uri` and takes precedence over
    /// a factory.
    #[tokio::test]
    async fn jws_verifier_takes_precedence_over_factory() {
        let jwt = build_test_jwt(
            &serde_json::json!({"alg": "RS256"}),
            &serde_json::json!({
                "sub": "user1",
                "iss": "https://op.example.com",
                "aud": "my-client"
            }),
        );

        let client = UserInfoClient::builder()
            .userinfo_endpoint("https://op.example.com/userinfo".parse().unwrap())
            .jws_verifier(AcceptAllVerifier)
            .jws_verifier_factory(Arc::new(ExplodingFactory))
            .issuer("https://op.example.com")
            .client_id("my-client")
            .require_signed_response(true)
            .build()
            .await
            .expect("the supplied verifier is used, so the factory never runs");

        let http = MockHttpClient::new(jwt_response(&jwt));
        let result = client
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap();

        assert_eq!(result.sub, "user1");
    }

    // --- builder_from_grant validator derivation ---

    /// Factory yielding [`AcceptAllVerifier`], standing in for a JWKS-backed one.
    struct AcceptAllFactory;

    impl JwsVerifierFactory for AcceptAllFactory {
        fn build(
            &self,
            _jwks_uri: Option<&EndpointUrl>,
            _platform: Arc<dyn JwsVerifierPlatform>,
        ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, Error>> {
            Box::pin(async { Ok(Arc::new(AcceptAllVerifier) as _) })
        }
    }

    /// Builds an authorization code grant, optionally carrying a JWS verifier.
    ///
    /// The HTTP client is never exercised — these tests build a `UserInfo`
    /// client from the grant rather than running a token exchange.
    async fn code_grant(
        with_verifier: bool,
    ) -> crate::grant::authorization_code::AuthorizationCodeGrant {
        crate::grant::authorization_code::AuthorizationCodeGrant::builder()
            .client_id("my-client")
            .issuer("https://op.example.com")
            .http_client(MockHttpClient::sequence(vec![]))
            .client_auth(crate::core::client_auth::NoAuth)
            .token_endpoint("https://op.example.com/token".parse().unwrap())
            .authorization_endpoint("https://op.example.com/authorize".parse().unwrap())
            .redirect_uri("http://127.0.0.1/cb")
            .maybe_jws_verifier_factory(with_verifier.then_some(AcceptAllFactory))
            .build()
            .await
            .unwrap()
    }

    fn userinfo_metadata() -> AuthorizationServerMetadata {
        serde_json::from_value(serde_json::json!({
            "issuer": "https://op.example.com",
            "authorization_endpoint": "https://op.example.com/authorize",
            "token_endpoint": "https://op.example.com/token",
            "userinfo_endpoint": "https://op.example.com/userinfo",
            "response_types_supported": ["code"],
        }))
        .unwrap()
    }

    /// A grant's verifier reaches the built client, so a signed `UserInfo`
    /// response validates instead of hard-erroring.
    #[tokio::test]
    async fn builder_from_grant_derives_jwt_validator() {
        let jwt = build_test_jwt(
            &serde_json::json!({"alg": "RS256"}),
            &serde_json::json!({
                "sub": "user1",
                "iss": "https://op.example.com",
                "aud": "my-client",
                "email": "jane@example.com"
            }),
        );

        let grant = code_grant(true).await;
        let client = UserInfoClient::builder_from_grant(&grant, &userinfo_metadata())
            .expect("metadata carries a userinfo_endpoint")
            .build()
            .await
            .unwrap();

        let http = MockHttpClient::new(jwt_response(&jwt));
        let result = client
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap();

        assert_eq!(result.sub, "user1");
        assert_eq!(result.profile.email.as_deref(), Some("jane@example.com"));
    }

    /// The derived validator checks `aud` and `iss`, not just the signature —
    /// otherwise it would accept any JWS the server's JWKS covers.
    #[rstest::rstest]
    #[case::wrong_audience("https://op.example.com", "other-client")]
    #[case::wrong_issuer("https://evil.example.com", "my-client")]
    #[tokio::test]
    async fn builder_from_grant_validator_checks_claims(#[case] iss: &str, #[case] aud: &str) {
        let jwt = build_test_jwt(
            &serde_json::json!({"alg": "RS256"}),
            &serde_json::json!({"sub": "user1", "iss": iss, "aud": aud}),
        );

        let grant = code_grant(true).await;
        let client = UserInfoClient::builder_from_grant(&grant, &userinfo_metadata())
            .unwrap()
            .build()
            .await
            .unwrap();

        let http = MockHttpClient::new(jwt_response(&jwt));
        let err = client
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .expect_err("a mismatched iss or aud must be rejected");

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::JwtValidation { .. }
        ));
    }

    /// A grant with no verifier cannot produce one: the JWT path stays closed
    /// and reports the missing configuration rather than skipping validation.
    #[tokio::test]
    async fn builder_from_grant_without_verifier_rejects_jwt_response() {
        let jwt = build_test_jwt(
            &serde_json::json!({"alg": "RS256"}),
            &serde_json::json!({"sub": "user1", "iss": "https://op.example.com", "aud": "my-client"}),
        );

        let grant = code_grant(false).await;
        let client = UserInfoClient::builder_from_grant(&grant, &userinfo_metadata())
            .unwrap()
            .build()
            .await
            .unwrap();

        let http = MockHttpClient::new(jwt_response(&jwt));
        let err = client
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .expect_err("no verifier means no validation is possible");

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::JwtResponseNotSupported
        ));
    }

    /// `require_signed_response` carries through `builder_from_grant`.
    #[tokio::test]
    async fn builder_from_grant_honors_require_signed_response() {
        let grant = code_grant(true).await;
        let client = UserInfoClient::builder_from_grant(&grant, &userinfo_metadata())
            .unwrap()
            .require_signed_response(true)
            .build()
            .await
            .unwrap();

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from_static(b"{\"sub\":\"user1\"}"),
        });

        let err = client
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap_err();

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::UnsignedResponse
        ));
    }

    /// Requiring signed responses from a grant that has no verifier is the
    /// same misconfiguration the builder rejects.
    #[tokio::test]
    async fn builder_from_grant_require_signed_without_verifier_errors() {
        let grant = code_grant(false).await;
        let _err = UserInfoClient::builder_from_grant(&grant, &userinfo_metadata())
            .unwrap()
            .require_signed_response(true)
            .build()
            .await
            .expect_err("no derivable validator means no acceptable response");
    }

    /// Absent `userinfo_endpoint` errors, and the message names the field.
    #[tokio::test]
    async fn builder_from_grant_without_userinfo_endpoint_names_the_field() {
        let metadata: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://op.example.com",
            "authorization_endpoint": "https://op.example.com/authorize",
            "token_endpoint": "https://op.example.com/token",
            "response_types_supported": ["code"],
        }))
        .unwrap();

        let grant = code_grant(true).await;
        // `.err()`, not `unwrap_err()`: bon builders aren't `Debug`.
        let err = UserInfoClient::builder_from_grant(&grant, &metadata)
            .err()
            .expect("metadata carries no userinfo_endpoint");

        // The detail is a chain layer now, so the alternate form carries it.
        assert_eq!(
            format!("{err:#}"),
            "authorization server metadata has no 'userinfo_endpoint'"
        );
    }

    /// Plain JSON still works through `builder_from_grant` when a validator is derived.
    #[tokio::test]
    async fn builder_from_grant_still_accepts_json() {
        let grant = code_grant(true).await;
        let client = UserInfoClient::builder_from_grant(&grant, &userinfo_metadata())
            .unwrap()
            .build()
            .await
            .unwrap();

        let http = MockHttpClient::new(HttpResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from_static(b"{\"sub\":\"user1\"}"),
        });

        let result = client
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap();

        assert_eq!(result.sub, "user1");
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

        assert!(matches!(
            userinfo_source(&err),
            UserInfoError::SubMismatch { .. }
        ));
    }
}

#[cfg(test)]
mod classification {
    use super::*;

    #[test]
    fn a_jwt_infrastructure_failure_preserves_its_classification() {
        let source = Error::new(crate::core::RetryAdvice::RETRY, "the JTI store");
        let err = Error::from(UserInfoError::JwtValidation {
            source: JwtValidationError::JtiCheck { source },
        });

        assert_eq!(err.retry_advice(), crate::core::RetryAdvice::RETRY);
    }

    // Resource-server challenges use the shared typed verdict representation.
    #[test]
    fn a_challenge_becomes_the_verdict() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "www-authenticate",
            HeaderValue::from_static(r#"Bearer error="insufficient_scope""#),
        );
        let err = Error::from(UserInfoError::BadStatus {
            status: StatusCode::FORBIDDEN,
            headers,
            body: TruncatedBody::new(""),
        });
        assert!(
            err.verdict()
                .is_some_and(|v| v.code() == &crate::core::OAuthErrorCode::InsufficientScope)
        );
    }
}
