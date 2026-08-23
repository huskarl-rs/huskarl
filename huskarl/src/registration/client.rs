//! The [`ClientRegistration`] client (RFC 7591 §3.1).

use bon::Builder;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde::Deserialize;
use snafu::ResultExt as _;

use super::{
    error::{
        AuthHeaderSnafu, DeserializeSnafu, RegistrationError, RequestFailedSnafu, SerializeSnafu,
    },
    metadata::ClientMetadata,
    response::ClientInformationResponse,
};
use crate::core::{
    EndpointUrl, Error,
    http::{FailedResponse, HttpClient, Idempotency, TruncatedBody},
    secrets::SecretString,
};

/// Registers a client with an authorization server's registration endpoint
/// (RFC 7591).
///
/// Call [`register`](Self::register) with the desired [`ClientMetadata`].
/// Construct it with [`builder`](Self::builder), or with `builder_from_metadata`
/// to fill the endpoint from
/// [`AuthorizationServerMetadata`](crate::core::server_metadata::AuthorizationServerMetadata)
/// (which errors when the server advertises no registration endpoint).
///
/// If the server requires an initial access token (RFC 7591 §3.1), supply it via
/// the builder; it is sent as a bearer token on the registration request.
#[huskarl_macros::from_metadata(metadata = crate::core::server_metadata::AuthorizationServerMetadata)]
#[derive(Clone, Builder)]
pub struct ClientRegistration {
    /// The URL of the client registration endpoint.
    #[from_metadata(path = "registration_endpoint?")]
    registration_endpoint: EndpointUrl,

    /// The mTLS alias for the registration endpoint (RFC 8705 §5).
    #[from_metadata(path = "mtls_endpoint_aliases?.registration_endpoint?")]
    mtls_registration_endpoint: Option<EndpointUrl>,

    /// An optional initial access token authorizing use of the registration
    /// endpoint (RFC 7591 §3.1), sent as a bearer token.
    #[builder(into)]
    initial_access_token: Option<SecretString>,
}

impl core::fmt::Debug for ClientRegistration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientRegistration")
            .field("registration_endpoint", &self.registration_endpoint)
            .field(
                "mtls_registration_endpoint",
                &self.mtls_registration_endpoint,
            )
            .field(
                "has_initial_access_token",
                &self.initial_access_token.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl ClientRegistration {
    /// Register a client at the authorization server's registration endpoint.
    ///
    /// Sends a POST request with the client metadata as a JSON body. Per
    /// RFC 7591 §3.2.1 the server responds `201 Created` with a JSON
    /// [`ClientInformationResponse`].
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the client metadata is invalid,
    /// or the response is malformed. Server rejections expose their RFC 7591
    /// error through [`Error::verdict`](crate::core::Error::verdict).
    pub async fn register(
        &self,
        http_client: &impl HttpClient,
        metadata: &ClientMetadata,
    ) -> Result<ClientInformationResponse, Error> {
        // RFC 7591 §2: jwks and jwks_uri MUST NOT both be present.
        if metadata.jwks.is_some() && metadata.jwks_uri.is_some() {
            return Err(Error::from(RegistrationError::JwksConflict));
        }

        let endpoint = if http_client.uses_mtls() {
            self.mtls_registration_endpoint
                .as_ref()
                .unwrap_or(&self.registration_endpoint)
        } else {
            &self.registration_endpoint
        };

        let body = serde_json::to_vec(metadata).context(SerializeSnafu)?;

        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.method = Method::POST;
        parts.uri = endpoint.as_uri().clone();
        parts.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Some(token) = &self.initial_access_token {
            let mut value = HeaderValue::from_str(&format!("Bearer {}", token.expose_secret()))
                .context(AuthHeaderSnafu)?;
            value.set_sensitive(true);
            parts.headers.insert(header::AUTHORIZATION, value);
        }
        let request = http::Request::from_parts(parts, Bytes::from(body));

        // A registration POST creates server-side state; a blind re-send could
        // register a duplicate client, so the request is not idempotent.
        let response = http_client
            .execute(request, Idempotency::Unknown)
            .await
            .context(RequestFailedSnafu)?;

        if response.status.is_success() {
            ensure_json_content_type(&response.headers)?;
            Ok(serde_json::from_slice(&response.body).context(DeserializeSnafu)?)
        } else {
            Err(map_error_response(
                response.status,
                &response.headers,
                &response.body,
            ))
        }
    }
}

/// Validates that a successful response is `application/json` (RFC 7591 §3.2.1).
fn ensure_json_content_type(headers: &HeaderMap) -> Result<(), Error> {
    let ct_value = headers
        .get(header::CONTENT_TYPE)
        .ok_or_else(|| Error::from(RegistrationError::MissingContentType))?;
    let ct_str = ct_value.to_str().map_err(|_| {
        Error::from(RegistrationError::UnexpectedContentType {
            content_type: String::from_utf8_lossy(ct_value.as_bytes()).into_owned(),
        })
    })?;
    let media_type = ct_str.split(';').next().unwrap_or(ct_str).trim();
    if media_type.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(Error::from(RegistrationError::UnexpectedContentType {
            content_type: media_type.to_owned(),
        }))
    }
}

/// The JSON error body returned for a registration failure (RFC 7591 §3.2.2).
#[derive(Deserialize)]
struct ErrorBody {
    error: String,
    error_description: Option<String>,
}

/// Maps a non-success registration response to an [`Error`].
///
/// A 5xx or 429 remains a transient failure regardless of its body. Other
/// well-formed RFC 7591 error responses become server verdicts.
#[track_caller]
fn map_error_response(status: StatusCode, headers: &http::HeaderMap, body: &[u8]) -> Error {
    let Some(failed) = FailedResponse::new(status, headers) else {
        return Error::from(RegistrationError::BadStatus {
            status,
            body: TruncatedBody::from_bytes(body),
        });
    };

    // Do not treat error-shaped gateway responses as registration verdicts.
    if failed.is_transient() {
        return failed.into_error(
            None,
            RegistrationError::BadStatus {
                status,
                body: TruncatedBody::from_bytes(body),
            },
        );
    }

    let Ok(ErrorBody {
        error,
        error_description: description,
    }) = serde_json::from_slice::<ErrorBody>(body)
    else {
        return failed.into_error(
            None,
            RegistrationError::BadStatus {
                status,
                body: TruncatedBody::from_bytes(body),
            },
        );
    };

    // Preserve registered and extension codes through the same variant.
    let cause = RegistrationError::OAuthError {
        verdict: crate::core::OAuthError::new(error).with_description(description),
    };
    // Use the variant's value so direct conversion and HTTP mapping agree.
    let verdict = cause.verdict();
    failed.into_error(verdict, cause)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use http::Uri;
    use rstest::rstest;

    use super::*;
    use crate::core::{
        http::HttpResponse, platform::MaybeSendBoxFuture,
        server_metadata::AuthorizationServerMetadata,
    };

    #[derive(Default)]
    struct Captured {
        method: Option<Method>,
        uri: Option<Uri>,
        headers: Option<HeaderMap>,
        body: Option<Bytes>,
    }

    /// An [`HttpClient`] that records the request it receives and replies with a
    /// fixed response.
    struct RecordingClient {
        uses_mtls: bool,
        response: Mutex<Option<HttpResponse>>,
        captured: Mutex<Captured>,
    }

    impl RecordingClient {
        fn new(response: HttpResponse) -> Self {
            Self {
                uses_mtls: false,
                response: Mutex::new(Some(response)),
                captured: Mutex::new(Captured::default()),
            }
        }

        fn with_mtls(mut self, uses_mtls: bool) -> Self {
            self.uses_mtls = uses_mtls;
            self
        }

        fn uri(&self) -> String {
            self.captured
                .lock()
                .unwrap()
                .uri
                .clone()
                .unwrap()
                .to_string()
        }

        fn body_string(&self) -> String {
            let bytes = self.captured.lock().unwrap().body.clone().unwrap();
            String::from_utf8(bytes.to_vec()).unwrap()
        }

        fn header(&self, name: &str) -> Option<String> {
            self.captured
                .lock()
                .unwrap()
                .headers
                .as_ref()
                .unwrap()
                .get(name)
                .map(|v| v.to_str().unwrap().to_owned())
        }
    }

    impl HttpClient for RecordingClient {
        fn execute(
            &self,
            request: http::Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            {
                let mut cap = self.captured.lock().unwrap();
                cap.method = Some(request.method().clone());
                cap.uri = Some(request.uri().clone());
                cap.headers = Some(request.headers().clone());
                cap.body = Some(request.body().clone());
            }
            let response = self.response.lock().unwrap().take().unwrap();
            Box::pin(async move { Ok(response) })
        }

        fn uses_mtls(&self) -> bool {
            self.uses_mtls
        }
    }

    fn url(s: &str) -> EndpointUrl {
        s.parse().unwrap()
    }

    fn json_response(status: StatusCode, body: &serde_json::Value) -> HttpResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        HttpResponse {
            status,
            headers,
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        }
    }

    fn registration(mtls_alias: Option<&str>) -> ClientRegistration {
        ClientRegistration::builder()
            .registration_endpoint(url("https://as.example/register"))
            .maybe_mtls_registration_endpoint(mtls_alias.map(url))
            .build()
    }

    fn desired_metadata() -> ClientMetadata {
        ClientMetadata::builder()
            .client_name("My App")
            .redirect_uris(bon::vec!["https://app.example/cb"])
            .grant_types(bon::vec!["authorization_code"])
            .build()
    }

    #[tokio::test]
    async fn register_posts_json_metadata_to_the_endpoint() {
        let client = RecordingClient::new(json_response(
            StatusCode::CREATED,
            &serde_json::json!({
                "client_id": "issued-client",
                "client_secret": "issued-secret",
                "client_secret_expires_at": 0,
                "client_name": "My App",
            }),
        ));

        let info = registration(None)
            .register(&client, &desired_metadata())
            .await
            .expect("201 with a client information response");

        assert_eq!(
            client.captured.lock().unwrap().method.as_ref().unwrap(),
            Method::POST
        );
        assert_eq!(client.uri(), "https://as.example/register");
        assert_eq!(
            client.header("content-type").as_deref(),
            Some("application/json")
        );
        let body = client.body_string();
        assert!(body.contains("\"client_name\":\"My App\""), "body: {body}");
        assert!(body.contains("authorization_code"), "body: {body}");

        assert_eq!(info.client_id, "issued-client");
        assert_eq!(
            info.client_secret.as_ref().unwrap().expose_secret(),
            "issued-secret"
        );
        assert_eq!(info.metadata.client_name.as_deref(), Some("My App"));
    }

    #[tokio::test]
    async fn builder_from_metadata_uses_registration_endpoint() {
        let metadata = AuthorizationServerMetadata::builder()
            .issuer("https://as.example")
            .token_endpoint(url("https://as.example/token"))
            .response_types_supported(vec!["code".to_string()])
            .registration_endpoint(url("https://as.example/register"))
            .build();

        let client = RecordingClient::new(json_response(
            StatusCode::CREATED,
            &serde_json::json!({ "client_id": "abc" }),
        ));

        ClientRegistration::builder_from_metadata(&metadata)
            .expect("metadata advertises a registration endpoint")
            .build()
            .register(&client, &desired_metadata())
            .await
            .unwrap();

        assert_eq!(client.uri(), "https://as.example/register");
    }

    /// The effective endpoint is the mTLS alias only when the client uses mTLS
    /// *and* an alias is configured.
    #[rstest]
    #[case::mtls_prefers_alias(
        true,
        Some("https://mtls.as.example/register"),
        "https://mtls.as.example/register"
    )]
    #[case::mtls_without_alias_falls_back(true, None, "https://as.example/register")]
    #[case::plain_client_ignores_alias(
        false,
        Some("https://mtls.as.example/register"),
        "https://as.example/register"
    )]
    #[tokio::test]
    async fn register_selects_endpoint_by_mtls_and_alias(
        #[case] uses_mtls: bool,
        #[case] alias: Option<&str>,
        #[case] expected_uri: &str,
    ) {
        let client = RecordingClient::new(json_response(
            StatusCode::CREATED,
            &serde_json::json!({ "client_id": "abc" }),
        ))
        .with_mtls(uses_mtls);

        registration(alias)
            .register(&client, &desired_metadata())
            .await
            .unwrap();

        assert_eq!(client.uri(), expected_uri);
    }

    #[tokio::test]
    async fn initial_access_token_is_sent_as_bearer() {
        let client = RecordingClient::new(json_response(
            StatusCode::CREATED,
            &serde_json::json!({ "client_id": "abc" }),
        ));

        ClientRegistration::builder()
            .registration_endpoint(url("https://as.example/register"))
            .initial_access_token("init-token")
            .build()
            .register(&client, &desired_metadata())
            .await
            .unwrap();

        assert_eq!(
            client.header("authorization").as_deref(),
            Some("Bearer init-token")
        );
    }

    #[tokio::test]
    async fn jwks_and_jwks_uri_conflict_is_rejected_locally() {
        let client = RecordingClient::new(json_response(
            StatusCode::CREATED,
            &serde_json::json!({ "client_id": "abc" }),
        ));

        let metadata = ClientMetadata::builder()
            .jwks_uri("https://app.example/jwks.json")
            .jwks(crate::core::jwk::PublicJwks::new(vec![]))
            .build();

        let _err = registration(None)
            .register(&client, &metadata)
            .await
            .unwrap_err();
    }

    /// The four RFC 7591 §3.2.2 codes each name something in the metadata the
    /// caller can change, so they promise "adjust and retry".
    #[rstest]
    #[case::redirect_uri("invalid_redirect_uri")]
    #[case::client_metadata("invalid_client_metadata")]
    #[case::software_statement("invalid_software_statement")]
    #[case::unapproved("unapproved_software_statement")]
    #[tokio::test]
    async fn rfc7591_error_codes_map_to_request_rejected(#[case] code: &str) {
        let client = RecordingClient::new(json_response(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({
                "error": code,
                "error_description": "nope",
            }),
        ));

        let err = registration(None)
            .register(&client, &desired_metadata())
            .await
            .unwrap_err();

        // The typed code is what says "fix the metadata and retry".
        assert!(
            err.verdict()
                .is_some_and(|o| o.code().parameters_at_fault())
        );
        assert_eq!(err.verdict().map(|v| v.code().as_str()), Some(code));
        // The gloss travels with its code — both are read off the variant, so
        // this also pins the round trip through `RegistrationError::verdict`.
        assert_eq!(
            err.verdict().and_then(crate::core::OAuthError::description),
            Some("nope")
        );
    }

    /// A code outside that set is still a rejection — but not one we can say
    /// how to fix, so the caller is told `Fail` rather than "adjust the
    /// metadata". Nothing in this module decides that: it falls out of the
    /// code not being `parameters_at_fault`, which is also what makes the
    /// token endpoint answer the same way.
    #[tokio::test]
    async fn an_unrecognised_registration_code_is_a_rejection_we_cannot_act_on() {
        let client = RecordingClient::new(json_response(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({ "error": "something_else" }),
        ));

        let err = registration(None)
            .register(&client, &desired_metadata())
            .await
            .unwrap_err();

        assert_eq!(
            crate::cache::Recovery::implied_by(&err),
            crate::cache::Recovery::Fail
        );
        // The raw code still reaches the caller for its own triage.
        assert_eq!(
            err.verdict().map(|v| v.code().as_str()),
            Some("something_else")
        );
    }

    #[tokio::test]
    async fn non_json_error_body_is_a_protocol_error() {
        let mut response = HttpResponse {
            status: StatusCode::BAD_REQUEST,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"<html>boom</html>"),
        };
        response
            .headers
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
        let client = RecordingClient::new(response);

        let err = registration(None)
            .register(&client, &desired_metadata())
            .await
            .unwrap_err();
        assert_eq!(err.verdict().map(|v| v.code().as_str()), None);
    }

    /// Regression: a 5xx is a retryable server condition even when its body
    /// parses as an RFC 7591 error shape — a transient outage must not be
    /// classified as "adjust the metadata and retry".
    #[rstest]
    #[case::gateway_json(serde_json::json!({"error": "server_error"}).to_string())]
    #[case::temporarily_unavailable(
        serde_json::json!({"error": "temporarily_unavailable"}).to_string()
    )]
    #[case::html("<html>boom</html>".to_string())]
    #[tokio::test]
    async fn server_5xx_is_retryable_and_unavailable(#[case] body: String) {
        let client = RecordingClient::new(HttpResponse {
            status: StatusCode::SERVICE_UNAVAILABLE,
            headers: HeaderMap::new(),
            body: Bytes::from(body),
        });

        let err = registration(None)
            .register(&client, &desired_metadata())
            .await
            .unwrap_err();
        assert_eq!(err.retry_advice(), crate::core::RetryAdvice::RETRY);
        // A 503 is the server's condition, never its verdict on the metadata.
        assert!(err.verdict().is_none());
    }

    /// A throttled registration endpoint keeps the interval it named.
    #[tokio::test]
    async fn registration_429_keeps_retry_after() {
        let client = RecordingClient::new(HttpResponse {
            status: StatusCode::TOO_MANY_REQUESTS,
            headers: {
                let mut h = HeaderMap::new();
                h.insert(header::RETRY_AFTER, HeaderValue::from_static("45"));
                h
            },
            body: Bytes::from_static(b""),
        });

        let err = registration(None)
            .register(&client, &desired_metadata())
            .await
            .unwrap_err();
        assert_eq!(
            err.retry_advice(),
            crate::core::RetryAdvice::retry_after(crate::core::platform::Duration::from_secs(45))
        );
    }

    #[tokio::test]
    async fn unexpected_success_content_type_is_a_protocol_error() {
        let client = RecordingClient::new(HttpResponse {
            status: StatusCode::CREATED,
            headers: {
                let mut h = HeaderMap::new();
                h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                h
            },
            body: Bytes::from_static(b"{\"client_id\":\"abc\"}"),
        });

        let _err = registration(None)
            .register(&client, &desired_metadata())
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn malformed_success_body_is_a_protocol_error() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let client = RecordingClient::new(HttpResponse {
            status: StatusCode::CREATED,
            headers,
            body: Bytes::from_static(b"not json"),
        });

        let _err = registration(None)
            .register(&client, &desired_metadata())
            .await
            .unwrap_err();
    }
}
