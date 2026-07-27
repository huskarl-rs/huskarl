//! Low-level RFC 7662 token introspection call.

use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderValue, Method, Request, StatusCode};
use serde::{Deserialize, Deserializer, Serialize};
use snafu::{ResultExt as _, Snafu, ensure};

use crate::{
    core::{
        EndpointUrl, Error, OAuthError, RetryAdvice,
        client_auth::{AuthenticationContext, ClientAuthentication},
        crypto::verifier::{JwsVerifierFactory, JwsVerifierPlatform},
        http::{FailedResponse, HttpClient, HttpResponse, Idempotency, TruncatedBody},
        jwt::{
            ConfirmationClaim,
            validator::{ClaimCheck, JwtValidationError, JwtValidator},
        },
        oauth_form,
        platform::{Duration, SystemTime},
        secrets::SecretString,
    },
    error::{Challenge, ServerStatus, ToRfc6750Error},
    validator::ValidatedRequest,
};

/// Performs a raw RFC 7662 token introspection call.
///
/// Unlike [`crate::validator::introspection::IntrospectionValidator`], this type does not extract tokens from request
/// headers or perform sender-constraint binding checks. It only calls the introspection endpoint
/// and returns the result.
///
/// Use [`TokenIntrospection::builder`] to construct an instance.
pub struct TokenIntrospection {
    client_id: String,
    issuer: Option<String>,
    introspection_endpoint: EndpointUrl,
    token_endpoint: Option<EndpointUrl>,
    client_auth: Arc<dyn ClientAuthentication>,
    request_jwt_response: bool,
    jwt_validator: Option<JwtValidator>,
}

#[bon::bon]
impl TokenIntrospection {
    /// Creates a new [`TokenIntrospection`].
    #[builder(on(String, into))]
    pub async fn new(
        /// The client ID of this resource server, used for authenticating to the introspection
        /// endpoint.
        client_id: String,
        /// The issuer URL of the authorization server.
        ///
        /// Used for client authentication methods that require an audience (e.g.
        /// `private_key_jwt`) and for RFC 9701 JWT response issuer (`iss`) validation.
        issuer: Option<String>,
        /// The URL of the token introspection endpoint.
        introspection_endpoint: EndpointUrl,
        /// The authorization server's token endpoint, as published in metadata.
        ///
        /// Used only as the audience for client assertions configured with
        /// `Audience::TokenEndpoint`; introspection requests go to the
        /// introspection endpoint, so this differs from the target endpoint.
        /// Leave unset to make that audience policy fail closed.
        token_endpoint: Option<EndpointUrl>,
        /// The client authentication strategy.
        #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
        client_auth: Arc<dyn ClientAuthentication>,
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
        /// Clock-skew leeway for the RFC 9701 response JWT's temporal checks.
        /// Defaults to
        /// [`DEFAULT_CLOCK_LEEWAY`](crate::validator::DEFAULT_CLOCK_LEEWAY).
        #[builder(default = crate::validator::DEFAULT_CLOCK_LEEWAY)]
        clock_leeway: crate::core::platform::Duration,
    ) -> Result<Self, Error> {
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
            let iss_check = issuer.as_ref().map_or(ClaimCheck::NoCheck, |i| {
                ClaimCheck::required_value(i.clone())
            });

            Some(
                JwtValidator::builder()
                    .verifier(verifier)
                    .typ(ClaimCheck::required_value("token-introspection+jwt"))
                    .require_exp(true)
                    .aud(aud_check)
                    .iss(iss_check)
                    .clock_leeway(clock_leeway)
                    .build(),
            )
        } else {
            None
        };

        Ok(Self {
            client_id,
            issuer,
            introspection_endpoint,
            token_endpoint,
            client_auth,
            request_jwt_response,
            jwt_validator,
        })
    }
}

/// The RFC 7662 introspection request body parameters (client-authentication
/// parameters are appended separately).
#[derive(Serialize)]
struct IntrospectionRequest<'a> {
    token: &'a str,
    token_type_hint: &'a str,
}

impl TokenIntrospection {
    /// Calls the introspection endpoint and returns a [`ValidatedRequest`] if the token is active.
    ///
    /// # Errors
    ///
    /// Returns an [`IntrospectionCallError`] if client authentication fails, the
    /// HTTP request fails, the endpoint returns a non-success status, the
    /// response (or its JWT form) cannot be parsed, or the token is inactive
    /// ([`IntrospectionCallError::TokenInactive`]).
    pub async fn introspect<C: HttpClient, Claims: for<'de> Deserialize<'de> + Clone + 'static>(
        &self,
        http_client: &C,
        access_token: &SecretString,
    ) -> Result<ValidatedRequest<Claims>, IntrospectionCallError> {
        let auth_params = self
            .client_auth
            .authentication_context(
                AuthenticationContext::builder()
                    .client_id(&self.client_id)
                    .target_endpoint(&self.introspection_endpoint)
                    .maybe_issuer(self.issuer.as_deref())
                    .maybe_token_endpoint(self.token_endpoint.as_ref())
                    .build(),
            )
            .await
            .context(AuthenticatingSnafu)?;

        let (body, auth_headers) = {
            let mut body = oauth_form::to_string(&IntrospectionRequest {
                token: access_token.expose_secret(),
                token_type_hint: "access_token",
            })
            .context(SerializeRequestSnafu)?;
            // Client-auth form parameters (e.g. `client_id`/`client_secret`); their
            // `FormValue` serialization handles sensitive vs non-sensitive values.
            if let Some(form_params) = &auth_params.form_params {
                body.push('&');
                oauth_form::push_to_string(&mut body, form_params)
                    .context(SerializeRequestSnafu)?;
            }
            (Bytes::from(body), auth_params.headers)
        };

        let (mut parts, ()) = Request::new(()).into_parts();
        parts.method = Method::POST;
        parts.uri = self.introspection_endpoint.as_uri().clone();
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

        // RFC 7662 introspection is a read-only query — safe to re-send.
        let response = http_client
            .execute(request, Idempotency::Idempotent)
            .await
            .context(SendingSnafu)?;

        let (introspection, introspection_jwt) = self.parse_response::<Claims>(response).await?;

        ensure!(introspection.active, TokenInactiveSnafu);

        Ok(ValidatedRequest {
            exp: parse_optional_timestamp("exp", introspection.exp)?,
            iat: parse_optional_timestamp("iat", introspection.iat)?,
            iss: introspection.iss,
            sub: introspection.sub,
            aud: introspection.aud,
            jti: introspection.jti,
            cnf: introspection.cnf,
            claims: introspection.claims,
            introspection_jwt,
        })
    }

    /// Parses an introspection endpoint response into the structured response,
    /// together with the raw JWT body when the authorization server returned an
    /// RFC 9701 JWT response.
    async fn parse_response<Claims: for<'de> Deserialize<'de> + Clone + 'static>(
        &self,
        response: HttpResponse,
    ) -> Result<(IntrospectionResponse<Claims>, Option<String>), IntrospectionCallError> {
        let status = response.status;
        let is_jwt_response = response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| {
                let ct = ct.trim().to_ascii_lowercase();
                ct.starts_with("application/token-introspection+jwt")
                    || ct.starts_with("token-introspection+jwt")
            });
        let body = response.body;

        if let Some(failed) = FailedResponse::new(status, &response.headers) {
            // RFC 7662 §2.3: an introspection error response follows RFC 6749
            // §5.2, so the shared classifier reads it the same way the token
            // endpoint does — 5xx/429 as retryable, honouring `Retry-After`, and
            // a well-formed error body on a 4xx as a verdict naming what the AS
            // decided about *our* credentials.
            let verdict = serde_json::from_slice::<IntrospectionErrorBody>(&body)
                .ok()
                .map(|error| {
                    OAuthError::new(error.error).with_description(error.error_description)
                });
            return Err(IntrospectionCallError::Refused {
                source: failed.into_error(
                    verdict,
                    BadIntrospectionStatus {
                        status,
                        body: TruncatedBody::from_bytes(&body),
                    },
                ),
            });
        }

        if is_jwt_response {
            let jwt_validator = self
                .jwt_validator
                .as_ref()
                .ok_or_else(|| UnexpectedJwtResponseSnafu.build())?;

            let jwt_str = std::str::from_utf8(&body)
                .context(MalformedJwtResponseBodySnafu)?
                .trim();

            let validated = jwt_validator
                .validate::<TokenIntrospectionJwtClaims<Claims>>(jwt_str)
                .await
                .context(JwtResponseSnafu)?;

            Ok((
                validated.claims.token_introspection,
                Some(jwt_str.to_owned()),
            ))
        } else {
            let response: IntrospectionResponse<Claims> =
                serde_json::from_slice(&body).context(ParseJsonResponseSnafu)?;
            Ok((response, None))
        }
    }
}

/// Converts an optional `i64` timestamp to `Option<SystemTime>`.
fn parse_optional_timestamp(
    field: &'static str,
    value: Option<i64>,
) -> Result<Option<SystemTime>, IntrospectionCallError> {
    value
        .map(|ts| {
            u64::try_from(ts)
                .ok()
                .and_then(|ts| SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(ts)))
                .ok_or_else(|| InvalidTimestampSnafu { field, value: ts }.build())
        })
        .transpose()
}

/// RFC 7662 §2.2 introspection response.
///
/// The `Claims` type parameter captures any non-standard fields the authorization
/// server includes beyond the standard set; they surface on the validated request.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct IntrospectionResponse<Claims = ()> {
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
    /// Additional claims beyond the standard introspection response fields.
    ///
    /// RFC 9396 `authorization_details` (a §9.2 top-level member) is not a
    /// registered field here; it flows into `claims`, so a caller that wants it
    /// typed includes an `authorization_details` field in their `Claims` type.
    #[serde(flatten)]
    pub claims: Claims,
}

/// RFC 9701 §4 outer JWT claims wrapping an introspection response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TokenIntrospectionJwtClaims<Claims: Clone> {
    /// The RFC 7662 introspection response embedded as a claim.
    pub token_introspection: IntrospectionResponse<Claims>,
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

#[cfg(test)]
mod timestamp_tests {
    use super::*;

    #[test]
    fn absent_timestamp_is_none() {
        assert!(parse_optional_timestamp("exp", None).unwrap().is_none());
    }

    #[test]
    fn ordinary_timestamp_round_trips() {
        let parsed = parse_optional_timestamp("iat", Some(1_700_000_000))
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1_700_000_000
        );
    }

    #[test]
    fn negative_timestamp_is_rejected() {
        assert!(matches!(
            parse_optional_timestamp("exp", Some(-1)),
            Err(IntrospectionCallError::InvalidTimestamp {
                field: "exp",
                value: -1
            })
        ));
    }

    #[test]
    fn extreme_timestamp_never_panics() {
        let _ = parse_optional_timestamp("exp", Some(i64::MAX));
    }
}

/// The cause recorded for a non-success introspection response.
#[derive(Debug, Snafu)]
#[snafu(display("introspection endpoint returned HTTP {status}: {body}"))]
pub(crate) struct BadIntrospectionStatus {
    status: StatusCode,
    /// A bounded body prefix, preventing echoed tokens from filling logs.
    body: TruncatedBody,
}

/// An RFC 6749 §5.2 error body, which RFC 7662 §2.3 says introspection errors
/// follow.
#[derive(Debug, Deserialize)]
struct IntrospectionErrorBody {
    error: String,
    error_description: Option<String>,
}

/// Error returned by [`TokenIntrospection::introspect`].
///
/// When used by an introspection validator, [`ToRfc6750Error::challenge`]
/// classifies `TokenInactive` as `invalid_token`. All other variants are
/// server-side failures and therefore produce a 5xx response without a
/// `WWW-Authenticate` challenge. Retryable failures use HTTP 503 and preserve
/// any known `Retry-After` interval.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum IntrospectionCallError {
    /// This resource server could not construct its credentials for the
    /// introspection endpoint.
    ///
    /// Produces HTTP 500 unless the source classifies the failure as retryable,
    /// in which case it produces HTTP 503.
    #[snafu(display("assembling credentials for the introspection endpoint"))]
    Authenticating {
        /// The classified failure.
        source: Error,
    },
    /// The introspection request failed before a usable response was received.
    ///
    /// Produces HTTP 502 unless the source classifies the failure as retryable,
    /// in which case it produces HTTP 503.
    #[snafu(display("sending the introspection request"))]
    Sending {
        /// The classified failure.
        source: Error,
    },
    /// The introspection endpoint answered with a non-success status.
    ///
    /// A well-formed OAuth error response is treated as this resource server's
    /// request or credential failure and produces HTTP 500. An unexplained
    /// non-success response produces HTTP 502. A retryable source produces HTTP
    /// 503 instead and preserves its retry interval.
    #[snafu(display("the introspection endpoint refused the request"))]
    Refused {
        /// The classified failure.
        source: Error,
    },
    /// Failed to parse the JSON introspection response.
    #[snafu(display("failed to parse introspection JSON response"))]
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
    #[snafu(display("token is not active"))]
    TokenInactive,
    /// The JWT introspection response body is not valid UTF-8.
    #[snafu(display("JWT introspection response body is not valid UTF-8"))]
    MalformedJwtResponseBody {
        /// The underlying error, which names the offending byte offset.
        source: std::str::Utf8Error,
    },
    /// The introspection response contains a timestamp that cannot be represented as a Unix timestamp.
    #[snafu(display("introspection response field '{field}' has invalid timestamp: {value}"))]
    InvalidTimestamp {
        /// The name of the field with the invalid timestamp.
        field: &'static str,
        /// The invalid timestamp value.
        value: i64,
    },
    /// Failed to serialize the introspection request body.
    #[snafu(display("failed to serialize introspection request body"))]
    SerializeRequest {
        /// The underlying serialization error.
        source: oauth_form::FormError,
    },
}

/// Maps an introspection failure to a server response classification.
///
/// Retryable failures produce 503 and preserve any known delay. Other failures
/// use `settled`, which reflects where the call failed.
fn call_response(source: &Error, settled: ServerStatus) -> crate::error::TokenValidationError {
    // Retryable failures override the settled status and retain their delay.
    if let RetryAdvice::Retry { after } = source.retry_advice() {
        return crate::error::TokenValidationError::Server {
            status: ServerStatus::SERVICE_UNAVAILABLE,
            retry_after: after,
        };
    }
    crate::error::TokenValidationError::server(settled)
}

impl ToRfc6750Error for IntrospectionCallError {
    fn challenge(&self) -> Challenge {
        let error = {
            use crate::error::{TokenErrorCode, TokenValidationError};
            match self {
                Self::TokenInactive => TokenValidationError::Client(TokenErrorCode::InvalidToken),
                // Our credentials, our request.
                Self::Authenticating { source } => {
                    call_response(source, ServerStatus::INTERNAL_SERVER_ERROR)
                }
                // No answer came back at all.
                Self::Sending { source } => call_response(source, ServerStatus::BAD_GATEWAY),
                // An answer came back and refused us. A verdict means the AS judged
                // our credentials — ours to fix, never fixed by retrying; anything
                // else is a response we cannot use, which is theirs.
                Self::Refused { source } => call_response(
                    source,
                    // A verdict means the AS judged our credentials, which is
                    // this deployment's problem; anything else is a response we
                    // could not use, which is the AS's.
                    if source.verdict().is_some() {
                        ServerStatus::INTERNAL_SERVER_ERROR
                    } else {
                        ServerStatus::BAD_GATEWAY
                    },
                ),
                // We got an answer and could not use it: the AS is misbehaving.
                Self::ParseJsonResponse { .. }
                | Self::JwtResponse { .. }
                | Self::MalformedJwtResponseBody { .. }
                | Self::InvalidTimestamp { .. } => {
                    TokenValidationError::server(ServerStatus::BAD_GATEWAY)
                }
                // We were not built to handle what it sent, or we built the request
                // wrong. Neither is the AS's fault.
                Self::UnexpectedJwtResponse | Self::SerializeRequest { .. } => {
                    TokenValidationError::server(ServerStatus::INTERNAL_SERVER_ERROR)
                }
            }
        };
        let challenge = Challenge::new(error);
        match self {
            Self::TokenInactive => challenge.with_description("The access token is revoked"),
            _ => challenge,
        }
    }
    fn attempted_scheme(&self) -> Option<crate::TokenType> {
        None
    }
}

#[cfg(test)]
mod call_classification {
    use http::{HeaderMap, StatusCode};

    use super::*;
    use crate::error::TokenValidationError;

    fn status_of(err: &IntrospectionCallError) -> StatusCode {
        match err.challenge().error {
            TokenValidationError::Server { status, .. } => status.get(),
            TokenValidationError::Client(code) => {
                panic!("expected a server-side failure, got {code:?}")
            }
        }
    }

    /// Builds the error the real path builds, so these assert the wiring and
    /// not just `call_status` in isolation.
    fn from_response(
        status: StatusCode,
        headers: &HeaderMap,
        body: &str,
    ) -> IntrospectionCallError {
        let failed = FailedResponse::new(status, headers).expect("not a success");
        let verdict = serde_json::from_slice::<IntrospectionErrorBody>(body.as_bytes())
            .ok()
            .map(|e| OAuthError::new(e.error).with_description(e.error_description));
        IntrospectionCallError::Refused {
            source: failed.into_error(
                verdict,
                BadIntrospectionStatus {
                    status,
                    body: TruncatedBody::new(body),
                },
            ),
        }
    }

    /// The AS is down or throttling: retrying may genuinely work, and 503 is
    /// the only status that says so.
    #[test]
    fn an_unavailable_as_is_503() {
        let none = HeaderMap::new();
        for status in [
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::BAD_GATEWAY,
            StatusCode::GATEWAY_TIMEOUT,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            assert_eq!(
                status_of(&from_response(status, &none, "")),
                StatusCode::SERVICE_UNAVAILABLE,
                "{status}"
            );
        }
    }

    /// The regression this redesign exists for. The AS rejected *our*
    /// introspection credentials — that heals when someone rotates a secret or
    /// re-registers us, but never by being retried. Answering 503 sent every
    /// caller back into the same wall and made a misconfigured deployment look
    /// like an upstream outage.
    #[test]
    fn the_as_rejecting_our_credentials_is_500_not_503() {
        let none = HeaderMap::new();
        for (status, body) in [
            (StatusCode::UNAUTHORIZED, r#"{"error":"invalid_client"}"#),
            (StatusCode::BAD_REQUEST, r#"{"error":"invalid_request"}"#),
            (StatusCode::FORBIDDEN, r#"{"error":"unauthorized_client"}"#),
        ] {
            let err = from_response(status, &none, body);
            assert_eq!(
                status_of(&err),
                StatusCode::INTERNAL_SERVER_ERROR,
                "{status} {body}"
            );
        }
    }

    /// A non-success the AS did not explain is it misbehaving, not us.
    #[test]
    fn an_unexplained_4xx_is_502() {
        let err = from_response(
            StatusCode::NOT_FOUND,
            &HeaderMap::new(),
            "<html>nope</html>",
        );
        assert_eq!(status_of(&err), StatusCode::BAD_GATEWAY);
    }

    /// A layer that knows a fault will clear gets to say so, and 503 follows
    /// without `call_response` knowing anything about secret providers.
    ///
    /// The interval it measured comes with it. A 503 that names none leaves
    /// the client to guess, and its guess is seconds — against a cooldown
    /// something downstairs already timed at thirty.
    #[test]
    fn a_lower_layer_that_knows_it_will_clear_earns_a_503() {
        // The cause here is deliberately a bare string: nothing reads it. What
        // drives the 503 is the advice, which is the axis built to carry it.
        let cooling_down = Error::new(
            RetryAdvice::retry_after(crate::core::platform::Duration::from_secs(30)),
            "the secret provider is in cooldown",
        );
        let err = IntrospectionCallError::Authenticating {
            source: cooling_down,
        };
        assert_eq!(status_of(&err), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            err.challenge().error.retry_after(),
            Some(crate::core::platform::Duration::from_secs(30)),
            "the interval the cooldown measured must survive to the response",
        );
    }

    /// The AS's own `Retry-After` is the other source of an interval, and it
    /// travels the same route: `FailedResponse` reads the header, the advice
    /// carries it, and this hands it to the response.
    #[test]
    fn an_upstream_retry_after_reaches_our_own_response() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", http::HeaderValue::from_static("120"));
        let err = from_response(StatusCode::SERVICE_UNAVAILABLE, &headers, "");

        assert_eq!(status_of(&err), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            err.challenge().error.retry_after(),
            Some(crate::core::platform::Duration::from_mins(2))
        );
    }

    /// The other half: a failure nobody timed names no interval. `None` here
    /// has to mean "nothing knew", or a client cannot trust the ones that do.
    #[test]
    fn a_failure_nothing_timed_names_no_interval() {
        for err in [
            from_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &HeaderMap::new(),
                "<html>down</html>",
            ),
            from_response(
                StatusCode::UNAUTHORIZED,
                &HeaderMap::new(),
                r#"{"error":"invalid_client"}"#,
            ),
            IntrospectionCallError::MalformedJwtResponseBody {
                source: String::from_utf8(vec![0xff]).unwrap_err().utf8_error(),
            },
            IntrospectionCallError::TokenInactive,
        ] {
            assert_eq!(err.challenge().error.retry_after(), None, "{err:?}");
        }
    }

    /// An answer we could not use is the AS's doing; a request we built wrong,
    /// or a response we were not configured to handle, is ours.
    #[test]
    fn unusable_answers_are_502_and_our_own_faults_are_500() {
        for err in [
            IntrospectionCallError::MalformedJwtResponseBody {
                source: String::from_utf8(vec![0xff]).unwrap_err().utf8_error(),
            },
            IntrospectionCallError::InvalidTimestamp {
                field: "exp",
                value: -1,
            },
        ] {
            assert_eq!(status_of(&err), StatusCode::BAD_GATEWAY, "{err:?}");
        }
        assert_eq!(
            status_of(&IntrospectionCallError::UnexpectedJwtResponse),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// An inactive token is the one thing here that is the *client's* problem,
    /// and it stays a 401 `invalid_token` rather than any of the above.
    #[test]
    fn an_inactive_token_is_still_the_clients_problem() {
        let challenge = IntrospectionCallError::TokenInactive.challenge();
        assert!(matches!(
            challenge.error,
            TokenValidationError::Client(crate::error::TokenErrorCode::InvalidToken)
        ));
        assert_eq!(
            challenge.description.as_deref(),
            Some("The access token is revoked"),
        );
    }

    /// An AS that echoes the introspection request back in its error body must
    /// not put the access token into an operator's logs in full.
    #[test]
    fn an_echoed_request_body_is_bounded() {
        // A marker past the 256-byte bound: if it shows up, the tail of the
        // request — which is where the token would be — reached the log.
        let echoed = format!("token={}TAIL_OF_TOKEN", "s3cret".repeat(200));
        let err = from_response(StatusCode::BAD_REQUEST, &HeaderMap::new(), &echoed);
        // Rendered the way an operator would see it: the whole source chain.
        let rendered = std::iter::successors(Some(&err as &dyn std::error::Error), |e| e.source())
            .map(|e| format!("{e}: {e:?}"))
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(
            !rendered.contains("TAIL_OF_TOKEN"),
            "the tail of an echoed request reached the source chain: {rendered}"
        );
        assert!(rendered.contains("bytes total"), "got {rendered}");
    }
}
