//! `OpenID` Connect `UserInfo` endpoint (OIDC Core §5.3).

use std::{collections::HashMap, str::Utf8Error, sync::Arc};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header::InvalidHeaderValue};
use serde::{Deserialize, Serialize};
use snafu::prelude::*;

use crate::{
    authorizer::{challenge, dpop_resend_advised, extract_dpop_nonce},
    core::{
        EndpointUrl, Error, OAuthError,
        crypto::verifier::{JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform},
        dpop::{NoDPoP, ResourceServerDPoP},
        http::{FailedResponse, HttpClient, Idempotency, TruncatedBody},
        jwk::JwksSource,
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

impl<S: user_info_client_builder::State> UserInfoClientBuilder<S> {
    /// Uses the authorization server's JWKS URI to verify signatures with a
    /// default [`JwksSource`] backed by this HTTP client.
    ///
    /// This sets the same field as `jws_verifier_factory`; choose one of the two.
    /// For custom refresh or startup settings, pass a configured [`JwksSource`]
    /// to `jws_verifier_factory` instead.
    pub fn jwks_source(
        self,
        http_client: impl HttpClient + 'static,
    ) -> UserInfoClientBuilder<user_info_client_builder::SetJwsVerifierFactory<S>>
    where
        S::JwsVerifierFactory: user_info_client_builder::IsUnset,
    {
        self.jws_verifier_factory(JwksSource::builder().http_client(http_client).build())
    }

    /// _**Optional** ([Some](Self::jws_verifier_factory()) / [Option](Self::maybe_jws_verifier_factory()) setters)._
    /// JWS verifier factory for JWT response validation.
    ///
    /// When provided, a [`JwtValidator`] is built that validates
    /// signed `UserInfo` responses. If the provider returns a JWT response without a
    /// validator configured, the response is rejected.
    ///
    /// Ignored when `jws_verifier` is set.
    pub fn maybe_jws_verifier_factory(
        self,
        factory: Option<Arc<dyn JwsVerifierFactory>>,
    ) -> UserInfoClientBuilder<user_info_client_builder::SetJwsVerifierFactory<S>>
    where
        S::JwsVerifierFactory: user_info_client_builder::IsUnset,
    {
        self.maybe_jws_verifier_factory_internal(factory)
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
    /// Returns an error when a factory is used without a verifier platform,
    /// when a configured verifier has no `issuer` or
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
        /// Required by the default JWKS source. Custom factories may supply
        /// their own keys and omit this URI.
        #[from_metadata(path = "jwks_uri?")]
        jwks_uri: Option<EndpointUrl>,
        /// JWS verifier factory for JWT response validation.
        ///
        /// When provided, a [`JwtValidator`] is built that validates
        /// signed `UserInfo` responses. If the provider returns a JWT response without a
        /// validator configured, the response is rejected.
        ///
        /// Ignored when `jws_verifier` is set.
        #[builder(
            with = |factory: impl JwsVerifierFactory + 'static| Arc::new(factory) as Arc<dyn JwsVerifierFactory>,
            setters(option_fn(name = "maybe_jws_verifier_factory_internal", vis = "")),
        )]
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

        let verifier = if let Some(verifier) = jws_verifier {
            Some(verifier)
        } else if let Some(factory) = jws_verifier_factory {
            let jws_verifier_platform =
                jws_verifier_platform.context(MissingJwsVerifierPlatformSnafu)?;
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
    /// A factory was supplied without a verifier platform.
    #[snafu(display(
        "jws_verifier_factory was set but no JWS verifier platform is configured; \
         enable the 'default-jws-verifier-platform' feature or call \
         '.jws_verifier_platform(...)' on the builder"
    ))]
    #[classify(no)]
    MissingJwsVerifierPlatform,
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
         supply 'jws_verifier' or 'jws_verifier_factory', or unset the requirement — no \
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
    /// Configure `jwks_source` with a `jwks_uri`, a custom `jws_verifier_factory`,
    /// or an already-resolved `jws_verifier` to enable JWT response validation.
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
mod tests;
