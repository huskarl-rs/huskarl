use serde::{Deserialize, Serialize};

use crate::{
    core::{
        EndpointUrl, Error, client_auth::AuthenticationParams, dpop::AuthorizationServerDPoP,
        http::HttpClient,
    },
    grant::{authorization_code::types::AuthorizationPayload, core::form::OAuth2FormRequest},
};

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(super) enum ParBody<'a> {
    Expanded(Box<AuthorizationPayload<'a>>),
    Jar { request: &'a str },
}

#[derive(Debug, Serialize)]
pub(super) struct AuthorizationPushPayload<'a> {
    pub client_id: &'a str,
    pub request_uri: &'a str,
}

#[derive(Debug, Deserialize)]
pub(super) struct AuthorizationPushResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

pub(super) async fn make_par_call(
    http_client: &dyn HttpClient,
    par_url: &EndpointUrl,
    auth_params: AuthenticationParams<'_>,
    payload: &ParBody<'_>,
    dpop: &dyn AuthorizationServerDPoP,
    dpop_jkt: Option<&str>,
) -> Result<AuthorizationPushResponse, Error> {
    OAuth2FormRequest::builder()
        .form(payload)
        .auth_params(auth_params)
        .uri(par_url.as_uri())
        .dpop(dpop)
        .maybe_dpop_jkt(dpop_jkt)
        .build()
        .execute(http_client)
        .await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use bytes::Bytes;
    use http::{Request, StatusCode, Uri};

    use super::*;
    use crate::core::{
        client_auth::{ClientAuthentication, NoAuth},
        dpop::NoDPoP,
        http::{HttpResponse, Idempotency},
        platform::MaybeSendBoxFuture,
    };

    #[derive(Default)]
    struct Captured {
        uri: Option<Uri>,
        body: Option<Bytes>,
    }

    /// Records the request and replies with a fixed status and body.
    struct RecordingClient {
        status: StatusCode,
        body: &'static str,
        captured: Mutex<Captured>,
    }

    impl RecordingClient {
        fn new(status: StatusCode, body: &'static str) -> Self {
            Self {
                status,
                body,
                captured: Mutex::new(Captured::default()),
            }
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

        fn body(&self) -> String {
            let bytes = self.captured.lock().unwrap().body.clone().unwrap();
            String::from_utf8(bytes.to_vec()).unwrap()
        }
    }

    impl HttpClient for RecordingClient {
        fn execute(
            &self,
            request: Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            {
                let mut cap = self.captured.lock().unwrap();
                cap.uri = Some(request.uri().clone());
                cap.body = Some(request.body().clone());
            }
            let status = self.status;
            let body = Bytes::from_static(self.body.as_bytes());
            Box::pin(async move {
                Ok(HttpResponse {
                    status,
                    headers: http::HeaderMap::new(),
                    body,
                })
            })
        }
    }

    fn url(s: &str) -> EndpointUrl {
        s.parse().unwrap()
    }

    /// A minimal payload — only the non-optional fields are set.
    fn payload() -> AuthorizationPayload<'static> {
        AuthorizationPayload {
            response_type: "code",
            redirect_uri: "https://app.example/cb",
            scope: None,
            state: "state-xyz",
            code_challenge: None,
            code_challenge_method: None,
            dpop_jkt: None,
            nonce: "nonce-1",
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            resource: None,
        }
    }

    #[tokio::test]
    async fn make_par_call_posts_to_endpoint_and_parses_response() {
        let client = RecordingClient::new(
            StatusCode::CREATED,
            r#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}"#,
        );
        let par_url = url("https://as.example/par");
        let auth = NoAuth
            .authentication_params("client-1", None, None, &par_url, None)
            .await
            .unwrap();

        let body = ParBody::Jar {
            request: "header.payload.signature",
        };
        let response = make_par_call(&client, &par_url, auth, &body, &NoDPoP, None)
            .await
            .unwrap();

        assert_eq!(
            response.request_uri,
            "urn:ietf:params:oauth:request_uri:abc"
        );
        assert_eq!(response.expires_in, 90);

        assert_eq!(client.uri(), "https://as.example/par");
        assert!(
            client.body().contains("request=header.payload.signature"),
            "body: {}",
            client.body()
        );
    }

    #[tokio::test]
    async fn make_par_call_propagates_an_error_response() {
        let client =
            RecordingClient::new(StatusCode::BAD_REQUEST, r#"{"error":"invalid_request"}"#);
        let par_url = url("https://as.example/par");
        let auth = NoAuth
            .authentication_params("client-1", None, None, &par_url, None)
            .await
            .unwrap();

        let result = make_par_call(
            &client,
            &par_url,
            auth,
            &ParBody::Jar { request: "jwt" },
            &NoDPoP,
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn par_body_jar_serializes_as_request_param() {
        let body = ParBody::Jar {
            request: "the-jar-jwt",
        };
        assert_eq!(
            crate::core::oauth_form::to_string(&body).unwrap(),
            "request=the-jar-jwt"
        );
    }

    #[test]
    fn par_body_expanded_serializes_the_authorization_payload() {
        let body = ParBody::Expanded(Box::new(payload()));
        let encoded = crate::core::oauth_form::to_string(&body).unwrap();

        assert!(encoded.contains("response_type=code"), "encoded: {encoded}");
        assert!(encoded.contains("state=state-xyz"), "encoded: {encoded}");
        assert!(encoded.contains("nonce=nonce-1"), "encoded: {encoded}");
        // The untagged enum must emit the payload fields, not a `request=` param.
        assert!(!encoded.contains("request="), "encoded: {encoded}");
    }

    #[test]
    fn push_payload_serializes_client_id_and_request_uri() {
        let push = AuthorizationPushPayload {
            client_id: "client-1",
            request_uri: "urn:ietf:params:oauth:request_uri:abc",
        };
        let encoded = crate::core::oauth_form::to_string(&push).unwrap();
        assert!(encoded.contains("client_id=client-1"), "encoded: {encoded}");
        assert!(encoded.contains("request_uri=urn"), "encoded: {encoded}");
    }

    #[test]
    fn push_response_deserializes_from_json() {
        let response: AuthorizationPushResponse =
            serde_json::from_str(r#"{"request_uri":"urn:x","expires_in":120}"#).unwrap();
        assert_eq!(response.request_uri, "urn:x");
        assert_eq!(response.expires_in, 120);
    }
}
