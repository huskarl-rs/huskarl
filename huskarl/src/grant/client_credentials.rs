//! Client credentials grant (RFC 6749 §4.4).
//!
//! Used when the client is acting on its own behalf, not on behalf of a user.
//! Client credentials requires client authentication — its credentials *are* the
//! grant.
//!
//! See the [client credentials how-to
//! guide](crate::_docs::guide::client_credentials) for step-by-step setup.

use std::sync::Arc;

use bon::Builder;
use serde::Serialize;

use crate::{
    cache::GrantParametersSource,
    core::{
        EndpointUrl, Error,
        client_auth::ClientAuthentication,
        dpop::{AuthorizationServerDPoP, NoDPoP},
        http::HttpClient,
        platform::MaybeSendBoxFuture,
    },
    grant::{
        core::{OAuth2ExchangeGrant, join_space},
        refresh::RefreshGrant,
    },
};

/// An OAuth 2.0 client credentials grant.
///
/// This grant is used for machine-to-machine authentication where no user
/// interaction is required. The client authenticates directly with the
/// authorization server using its own credentials.
///
/// See the [module documentation][crate::grant::client_credentials] for a usage guide.
#[huskarl_macros::from_metadata(metadata = crate::core::server_metadata::AuthorizationServerMetadata)]
#[derive(Builder)]
#[builder(on(String, into), builder_type(doc {
    /// Configures a [`ClientCredentialsGrant`].
    ///
    /// Required and optional inputs are marked on their setter methods. Prefer
    /// [`ClientCredentialsGrant::builder_from_metadata`] when discovery
    /// metadata is available; it fills endpoint, issuer, and authentication
    /// capability inputs before returning this builder.
}))]
pub struct ClientCredentialsGrant {
    /// The OAuth 2.0 client identifier registered with the authorization
    /// server.
    client_id: String,

    /// The transport used for token requests.
    #[builder(with = |client: impl HttpClient + 'static| Arc::new(client) as Arc<dyn HttpClient>)]
    http_client: Arc<dyn HttpClient>,

    /// How the client authenticates to the token endpoint.
    ///
    /// Client authentication is required for this grant because the client's
    /// credentials are the grant (RFC 6749 §4.4).
    #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
    client_auth: Arc<dyn ClientAuthentication>,

    /// The `DPoP` signer. Defaults to [`NoDPoP`] (no token sender-constraining).
    #[builder(
        with = |dpop: impl AuthorizationServerDPoP + 'static| Arc::new(dpop) as Arc<dyn AuthorizationServerDPoP>,
        default = Arc::new(NoDPoP),
    )]
    dpop: Arc<dyn AuthorizationServerDPoP>,

    /// The authorization server's issuer identifier, when known.
    ///
    /// Client-authentication methods may use it as the audience of a signed
    /// assertion. The metadata builder supplies it automatically.
    #[from_metadata(path = "issuer")]
    issuer: Option<String>,

    /// The canonical token endpoint URL, before mTLS alias resolution.
    #[from_metadata(path = "token_endpoint")]
    token_endpoint: EndpointUrl,

    /// The mTLS alias for the token endpoint (RFC 8705 §5).
    #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
    mtls_token_endpoint: Option<EndpointUrl>,

    /// The endpoint used for token requests: the mTLS alias when the HTTP
    /// client uses mTLS, the primary token endpoint otherwise.
    #[builder(skip = crate::grant::core::resolve_mtls_alias(http_client.as_ref(), &token_endpoint, mtls_token_endpoint.as_ref()))]
    effective_token_endpoint: EndpointUrl,

    /// Authentication methods advertised for the token endpoint.
    ///
    /// [`ClientSecret`](crate::core::client_auth::ClientSecret) uses this list
    /// to choose HTTP Basic or form authentication. `None` leaves that choice
    /// unconstrained by metadata.
    #[from_metadata(path = "token_endpoint_auth_methods_supported")]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl core::fmt::Debug for ClientCredentialsGrant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientCredentialsGrant")
            .field("client_id", &self.client_id)
            .field("issuer", &self.issuer)
            .field("token_endpoint", &self.token_endpoint)
            .field("mtls_token_endpoint", &self.mtls_token_endpoint)
            .finish_non_exhaustive()
    }
}

impl OAuth2ExchangeGrant for ClientCredentialsGrant {
    type Parameters = ClientCredentialsGrantParameters;
    type Form<'a> = ClientCredentialsGrantForm;

    fn client_id(&self) -> Option<&str> {
        Some(&self.client_id)
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn client_auth(&self) -> Option<&dyn ClientAuthentication> {
        Some(self.client_auth.as_ref())
    }

    fn token_endpoint(&self) -> &EndpointUrl {
        &self.token_endpoint
    }

    fn effective_token_endpoint(&self) -> &EndpointUrl {
        &self.effective_token_endpoint
    }

    fn dpop(&self) -> &dyn AuthorizationServerDPoP {
        self.dpop.as_ref()
    }

    fn http_client(&self) -> &dyn HttpClient {
        self.http_client.as_ref()
    }

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.token_endpoint_auth_methods_supported.as_deref()
    }

    fn to_refresh_grant(&self) -> RefreshGrant {
        RefreshGrant::builder()
            .client_id(self.client_id.clone())
            .maybe_issuer(self.issuer.clone())
            .http_client(self.http_client.clone())
            .client_auth(self.client_auth.clone())
            .dpop(self.dpop.clone())
            .token_endpoint(self.token_endpoint.clone())
            .maybe_mtls_token_endpoint(self.mtls_token_endpoint.clone())
            .maybe_token_endpoint_auth_methods_supported(
                self.token_endpoint_auth_methods_supported.clone(),
            )
            .build()
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        ClientCredentialsGrantForm {
            grant_type: "client_credentials",
            scope: join_space(params.scope.as_deref()),
            resource: params.resource,
            authorization_details: params.authorization_details,
        }
    }
}

/// Parameters when requesting a token using the client credentials grant.
#[derive(Debug, Clone, Builder)]
#[builder(on(String, into))]
pub struct ClientCredentialsGrantParameters {
    /// The requested scope(s) for the access token.
    scope: Option<Vec<String>>,
    /// The target resource(s) for the access token.
    resource: Option<Vec<String>>,
    /// RFC 9396 `authorization_details` requested for the issued access token.
    authorization_details: Option<Vec<crate::core::AuthorizationDetail>>,
}

impl Default for ClientCredentialsGrantParameters {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl ClientCredentialsGrantParameters {
    /// Create an empty set of parameters for requesting a token.
    ///
    /// This is enough for most use cases; the builder exists as an extensible
    /// API where arbitrary extra fields may be added in future.
    #[must_use]
    pub fn new() -> Self {
        Self::builder().build()
    }
}

/// Client credentials parameters are reusable: scopes and resources may be
/// re-submitted freely, so the cache clones them for each exchange. Pass a
/// value directly to the cache builder; for parameters that vary per request,
/// use [`from_fn`](crate::cache::from_fn) instead.
impl GrantParametersSource<Self> for ClientCredentialsGrantParameters {
    fn acquire(&self) -> MaybeSendBoxFuture<'_, Result<Option<Self>, Error>> {
        let params = self.clone();
        Box::pin(async move { Ok(Some(params)) })
    }

    fn discard_after_rejection(&self) -> bool {
        true
    }
}

/// Client credentials grant body.
#[derive(Debug, Serialize, Builder)]
pub struct ClientCredentialsGrantForm {
    /// Fixed OAuth 2.0 grant type: `client_credentials`.
    grant_type: &'static str,
    /// Requested scopes encoded as one space-separated value.
    scope: Option<String>,
    /// Resource indicators encoded as repeated `resource` fields (RFC 8707).
    resource: Option<Vec<String>>,
    /// RFC 9396 `authorization_details` requested for the issued access token.
    authorization_details: Option<Vec<crate::core::AuthorizationDetail>>,
}

#[cfg(test)]
#[cfg(not(target_family = "wasm"))]
mod tests {
    use std::sync::LazyLock;

    use httpmock::MockServer;
    use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
    use huskarl_reqwest::ReqwestClient;
    use serde_json::json;

    use crate::{
        core::{client_auth::NoAuth, dpop::DPoP},
        grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
        token::AccessToken,
    };

    static MOCK_SERVER: LazyLock<MockServer> = LazyLock::new(MockServer::start);

    fn http_client() -> ReqwestClient {
        reqwest::Client::new().into()
    }

    #[test]
    fn test_resource_serializes_as_repeated_keys() {
        let form = super::ClientCredentialsGrantForm::builder()
            .grant_type("client_credentials")
            .resource(vec![
                "https://api.example.com".into(),
                "https://other.example.com".into(),
            ])
            .build();
        let encoded = crate::core::oauth_form::to_string(&form).unwrap();
        assert!(
            encoded.contains("resource=https%3A%2F%2Fapi.example.com"),
            "first resource not found in: {encoded}"
        );
        assert!(
            encoded.contains("resource=https%3A%2F%2Fother.example.com"),
            "second resource not found in: {encoded}"
        );
        // Ensure they are separate keys, not comma-joined
        assert!(
            !encoded.contains(','),
            "resource values should not be comma-joined: {encoded}"
        );
    }

    #[tokio::test]
    async fn test_exchange() {
        use httpmock::prelude::*;

        use crate::prelude::*;

        let grant = ClientCredentialsGrant::builder()
            .token_endpoint(MOCK_SERVER.url("/no_dpop/token").parse().unwrap())
            .client_id("client")
            .http_client(http_client())
            .client_auth(NoAuth)
            .build();

        let mock = MOCK_SERVER
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/no_dpop/token")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header_missing("DPoP")
                    .form_urlencoded_tuple("grant_type", "client_credentials")
                    .form_urlencoded_tuple("client_id", "client");
                then.status(200)
                    .header("Content-Type", "application/json")
                    .json_body(json!({
                        "access_token": "access_token",
                        "token_type": "Bearer",
                    }));
            })
            .await;

        let response = grant
            .exchange(ClientCredentialsGrantParameters::builder().build())
            .await;

        mock.assert();
        let response = response.unwrap();

        assert!(matches!(response.access_token(), AccessToken::Bearer(_)));
        assert_eq!(
            response.access_token().token().expose_secret(),
            "access_token"
        );
    }

    #[tokio::test]
    async fn test_exchange_with_dpop() {
        use httpmock::prelude::*;

        use crate::prelude::*;

        let grant = ClientCredentialsGrant::builder()
            .token_endpoint(MOCK_SERVER.url("/with_dpop/token").parse().unwrap())
            .client_id("client")
            .http_client(http_client())
            .client_auth(NoAuth)
            .dpop(
                DPoP::builder()
                    .signer(PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap())
                    .build(),
            )
            .build();

        let mock = MOCK_SERVER
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/with_dpop/token")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header_exists("DPoP")
                    .form_urlencoded_tuple("grant_type", "client_credentials")
                    .form_urlencoded_tuple("client_id", "client");
                then.status(200)
                    .header("Content-Type", "application/json")
                    .json_body(json!({
                        "access_token": "access_token",
                        "token_type": "DPoP",
                    }));
            })
            .await;

        let response = grant
            .exchange(ClientCredentialsGrantParameters::builder().build())
            .await;

        mock.assert();
        let response = response.unwrap();

        assert!(matches!(response.access_token(), AccessToken::DPoP(_)));
        assert_eq!(
            response.access_token().token().expose_secret(),
            "access_token"
        );
    }
}
