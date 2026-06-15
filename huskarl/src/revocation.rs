//! Token revocation (RFC 7009).
//!
//! Provides the ability to revoke access tokens and refresh tokens at an
//! authorization server's revocation endpoint.

use std::{borrow::Cow, sync::Arc};

use bon::Builder;
use serde::Serialize;

use crate::{
    core::{EndpointUrl, Error, client_auth::ClientAuthentication, dpop::NoDPoP, http::HttpClient},
    grant::core::form::OAuth2FormRequest,
    token::{AccessToken, RefreshToken},
};

/// A token that can be revoked.
pub trait RevocableToken {
    /// Returns the token value.
    fn token_value(&self) -> &str;

    /// Returns the token type hint as defined in RFC 7009 §2.1.
    fn token_type_hint(&self) -> &'static str;
}

impl RevocableToken for AccessToken {
    fn token_value(&self) -> &str {
        self.token().expose_secret()
    }

    fn token_type_hint(&self) -> &'static str {
        "access_token"
    }
}

impl RevocableToken for RefreshToken {
    fn token_value(&self) -> &str {
        self.token().expose_secret()
    }

    fn token_type_hint(&self) -> &'static str {
        "refresh_token"
    }
}

/// Implementation of token revocation.
#[huskarl_macros::from_metadata(metadata = crate::core::server_metadata::AuthorizationServerMetadata)]
#[derive(Clone, Builder)]
pub struct TokenRevocation {
    // -- User-supplied fields --
    /// The client ID.
    #[builder(into)]
    client_id: Cow<'static, str>,

    /// The client authentication method.
    #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
    client_auth: Arc<dyn ClientAuthentication>,

    // -- Metadata fields --
    /// The issuer for tokens created by the authorization server.
    #[builder(into)]
    #[from_metadata(path = "issuer")]
    issuer: Option<String>,

    /// The authorization server's token endpoint, as published in metadata.
    ///
    /// Used only as the audience for client assertions configured with
    /// [`Audience::TokenEndpoint`](crate::core::client_auth::Audience::TokenEndpoint);
    /// revocation requests go to the revocation endpoint, so this differs from
    /// the target endpoint. `None` leaves `Audience::TokenEndpoint` to fail
    /// closed.
    #[from_metadata(path = "token_endpoint")]
    token_endpoint: Option<EndpointUrl>,

    /// The URL of the revocation endpoint.
    #[from_metadata(path = "revocation_endpoint?")]
    revocation_endpoint: EndpointUrl,

    /// The mTLS alias for the revocation endpoint (RFC 8705 §5).
    #[from_metadata(path = "mtls_endpoint_aliases?.revocation_endpoint?")]
    mtls_revocation_endpoint: Option<EndpointUrl>,

    /// Supported endpoint auth methods (RFC 8414).
    #[from_metadata(path = "revocation_endpoint_auth_methods_supported")]
    revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl core::fmt::Debug for TokenRevocation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TokenRevocation")
            .field("client_id", &self.client_id)
            .field("issuer", &self.issuer)
            .field("token_endpoint", &self.token_endpoint)
            .field("revocation_endpoint", &self.revocation_endpoint)
            .field("mtls_revocation_endpoint", &self.mtls_revocation_endpoint)
            .finish_non_exhaustive()
    }
}

impl TokenRevocation {
    /// Revoke a token at the authorization server's revocation endpoint.
    ///
    /// Sends a POST request to the revocation endpoint with the token and
    /// a token type hint. Per RFC 7009, the server returns 200 OK
    /// with an empty body on success.
    ///
    /// # Errors
    ///
    /// Returns an error of kind
    /// [`ErrorKind::Auth`](crate::core::ErrorKind::Auth) if client
    /// authentication fails; other kinds propagate from the HTTP request or
    /// server response.
    pub async fn revoke(
        &self,
        http_client: &impl HttpClient,
        token: &impl RevocableToken,
    ) -> Result<(), Error> {
        let effective_endpoint = if http_client.uses_mtls() {
            self.mtls_revocation_endpoint
                .as_ref()
                .unwrap_or(&self.revocation_endpoint)
        } else {
            &self.revocation_endpoint
        };

        let auth_params = self
            .client_auth
            .authentication_params(
                &self.client_id,
                self.issuer.as_deref(),
                self.token_endpoint.as_ref(),
                effective_endpoint,
                self.revocation_endpoint_auth_methods_supported.as_deref(),
            )
            .await?;

        let form = RevocationForm {
            token: token.token_value(),
            token_type_hint: token.token_type_hint(),
        };

        OAuth2FormRequest::builder()
            .auth_params(auth_params)
            .form(&form)
            .uri(effective_endpoint.as_uri())
            .dpop(&NoDPoP)
            .build()
            .execute_empty_response(http_client)
            .await
    }
}

#[derive(Debug, Serialize)]
struct RevocationForm<'a> {
    token: &'a str,
    token_type_hint: &'static str,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use bytes::Bytes;
    use http::{Request, StatusCode, Uri};
    use rstest::rstest;

    use super::*;
    use crate::{
        core::{
            client_auth::NoAuth,
            http::{HttpClient, HttpResponse, Idempotency},
            platform::{MaybeSendBoxFuture, SystemTime},
            secrets::SecretString,
        },
        token::{AccessToken, BearerAccessToken},
    };

    #[derive(Default)]
    struct Captured {
        uri: Option<Uri>,
        body: Option<Bytes>,
    }

    /// An [`HttpClient`] that records the request it receives and answers with a
    /// fixed status and an empty body.
    struct RecordingClient {
        status: StatusCode,
        uses_mtls: bool,
        captured: Mutex<Captured>,
    }

    impl RecordingClient {
        fn new(status: StatusCode, uses_mtls: bool) -> Self {
            Self {
                status,
                uses_mtls,
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
            Box::pin(async move {
                Ok(HttpResponse {
                    status,
                    headers: http::HeaderMap::new(),
                    body: Bytes::new(),
                })
            })
        }

        fn uses_mtls(&self) -> bool {
            self.uses_mtls
        }
    }

    fn url(s: &str) -> EndpointUrl {
        s.parse().unwrap()
    }

    fn revocation(mtls_alias: Option<&str>) -> TokenRevocation {
        TokenRevocation::builder()
            .client_id("revoke-client")
            .client_auth(NoAuth)
            .revocation_endpoint(url("https://as.example/revoke"))
            .maybe_mtls_revocation_endpoint(mtls_alias.map(url))
            .build()
    }

    fn access_token() -> AccessToken {
        AccessToken::Bearer(BearerAccessToken::new(
            SecretString::new("the-access-token"),
            SystemTime::now(),
            None,
        ))
    }

    fn refresh_token() -> RefreshToken {
        RefreshToken::new(SecretString::new("the-refresh-token"), None)
    }

    #[test]
    fn revocable_token_impls_report_value_and_hint() {
        assert_eq!(access_token().token_value(), "the-access-token");
        assert_eq!(access_token().token_type_hint(), "access_token");
        assert_eq!(refresh_token().token_value(), "the-refresh-token");
        assert_eq!(refresh_token().token_type_hint(), "refresh_token");
    }

    #[tokio::test]
    async fn revoke_access_token_posts_rfc7009_form_to_revocation_endpoint() {
        let client = RecordingClient::new(StatusCode::OK, false);
        revocation(None)
            .revoke(&client, &access_token())
            .await
            .expect("200 with empty body is success");

        assert_eq!(client.uri(), "https://as.example/revoke");
        let body = client.body();
        assert!(body.contains("token=the-access-token"), "body: {body}");
        assert!(
            body.contains("token_type_hint=access_token"),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn revoke_refresh_token_sends_refresh_hint() {
        let client = RecordingClient::new(StatusCode::OK, false);
        revocation(None)
            .revoke(&client, &refresh_token())
            .await
            .unwrap();

        let body = client.body();
        assert!(body.contains("token=the-refresh-token"), "body: {body}");
        assert!(
            body.contains("token_type_hint=refresh_token"),
            "body: {body}"
        );
    }

    /// The effective endpoint is the mTLS alias only when the client uses mTLS
    /// *and* an alias is configured; otherwise it is the primary endpoint.
    #[rstest]
    #[case::mtls_prefers_alias(
        true,
        Some("https://mtls.as.example/revoke"),
        "https://mtls.as.example/revoke"
    )]
    #[case::mtls_without_alias_falls_back(true, None, "https://as.example/revoke")]
    #[case::plain_client_ignores_alias(
        false,
        Some("https://mtls.as.example/revoke"),
        "https://as.example/revoke"
    )]
    #[tokio::test]
    async fn revoke_selects_endpoint_by_mtls_and_alias(
        #[case] uses_mtls: bool,
        #[case] alias: Option<&str>,
        #[case] expected_uri: &str,
    ) {
        let client = RecordingClient::new(StatusCode::OK, uses_mtls);
        revocation(alias)
            .revoke(&client, &access_token())
            .await
            .unwrap();
        assert_eq!(client.uri(), expected_uri);
    }

    #[tokio::test]
    async fn revoke_propagates_a_server_error_status() {
        let client = RecordingClient::new(StatusCode::BAD_REQUEST, false);
        let result = revocation(None).revoke(&client, &access_token()).await;
        assert!(
            result.is_err(),
            "a non-2xx response must surface as an error"
        );
    }
}
