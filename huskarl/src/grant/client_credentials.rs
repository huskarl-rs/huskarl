//! Client credentials grant (RFC 6749 §4.4).
//!
//! Used when the client is acting on its own behalf, not on behalf of a user.
//!
//! # Usage
//!
//! ## 1. Set up your HTTP client
//!
//! A HTTP client needs to be configured. Using the `huskarl_reqwest` crate:
//!
//! ```rust
//! use huskarl_reqwest::ReqwestClient;
//!
//! # async fn setup_client() -> Result<(), Box<dyn std::error::Error>> {
//! let client: ReqwestClient = ReqwestClient::builder().build().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 2. Set up client authentication (mandatory for client credentials).
//!
//! This example shows the use of a client secret as credentials, but any `ClientAuthentication`
//! implementation can be used.
//!
//! ```rust
//! use huskarl::core::{
//!     client_auth::ClientSecret,
//!     secrets::{EnvVarSecret, encodings::StringEncoding},
//! };
//!
//! # async fn setup_client_auth() -> Result<(), Box<dyn std::error::Error>> {
//! let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//! let client_auth: ClientSecret = ClientSecret::new(env_secret);
//! # Ok(())
//! # }
//! ```
//!
//! ## 3a. Set up the grant with authorization server metadata
//!
//! ```rust
//! use huskarl::{
//!     core::{client_auth::ClientSecret, server_metadata::AuthorizationServerMetadata},
//!     grant::client_credentials::ClientCredentialsGrant,
//! };
//! # use huskarl::core::http::HttpClient;
//! # use huskarl::core::secrets::EnvVarSecret;
//! # use huskarl::core::secrets::encodings::StringEncoding;
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = huskarl_reqwest::ReqwestClient::builder()
//! #     .build()
//! #     .await?;
//! #
//! # let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//! # let client_auth: ClientSecret = ClientSecret::new(env_secret);
//!
//! let metadata = AuthorizationServerMetadata::fetch()
//!     .http_client(&client)
//!     .issuer("https://my-issuer")
//!     .call()
//!     .await?;
//!
//! let grant: ClientCredentialsGrant = ClientCredentialsGrant::builder_from_metadata(&metadata)
//!     .client_id("client_id")
//!     .http_client(client)
//!     .client_auth(client_auth)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## 3b. Alternative: Set up the grant without metadata
//!
//! ```rust
//! use huskarl::{
//!     core::client_auth::ClientSecret, grant::client_credentials::ClientCredentialsGrant,
//! };
//! # use huskarl::core::http::HttpClient;
//! # use huskarl::core::secrets::EnvVarSecret;
//! # use huskarl::core::secrets::encodings::StringEncoding;
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = huskarl_reqwest::ReqwestClient::builder()
//! #     .build()
//! #     .await?;
//! #
//! # let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//! # let client_auth: ClientSecret = ClientSecret::new(env_secret);
//!
//! let grant: ClientCredentialsGrant = ClientCredentialsGrant::builder()
//!     .token_endpoint("https://my-server/token")?
//!     .client_id("client_id")
//!     .http_client(client)
//!     .client_auth(client_auth)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## 4. Get an access token.
//!
//! ```rust
//! use huskarl::prelude::*; // Imports OAuth2ExchangeGrant which defines the exchange call.
//! use huskarl::grant::client_credentials::ClientCredentialsGrantParameters;
//! use huskarl::token::AccessToken;
//! # use huskarl::grant::client_credentials::ClientCredentialsGrant;
//! use huskarl::core::client_auth::ClientSecret;
//! # use huskarl::core::http::HttpClient;
//! # use huskarl::core::secrets::EnvVarSecret;
//! # use huskarl::core::secrets::encodings::StringEncoding;
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = huskarl_reqwest::ReqwestClient::builder()
//! #     .build()
//! #     .await?;
//! #
//! # let client_auth: ClientSecret = ClientSecret::new(EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?);
//! #
//! # let grant: ClientCredentialsGrant = ClientCredentialsGrant::builder()
//! #     .token_endpoint("https://my-server/token")?
//! #     .client_id("client_id")
//! #     .http_client(client)
//! #     .client_auth(client_auth)
//! #     .build();
//!
//! let params = ClientCredentialsGrantParameters::builder().scopes(vec!["read", "write"]).build();
//! let response = grant.exchange(params).await?;
//! let token: &AccessToken = response.access_token();
//!
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use bon::Builder;
use serde::Serialize;

use crate::{
    core::{
        EndpointUrl,
        client_auth::ClientAuthentication,
        dpop::{AuthorizationServerDPoP, NoDPoP},
        http::HttpClient,
    },
    grant::{
        core::{OAuth2ExchangeGrant, mk_scopes},
        refresh::RefreshGrant,
    },
};

/// An `OAuth2` client credentials grant.
///
/// This grant is used for machine-to-machine authentication where no user
/// interaction is required. The client authenticates directly with the
/// authorization server using its own credentials.
///
/// See the [module documentation][crate::grant::client_credentials] for a usage guide.
#[huskarl_macros::from_metadata(metadata = crate::core::server_metadata::AuthorizationServerMetadata)]
#[huskarl_macros::try_builder]
#[derive(Builder)]
#[builder(state_mod(name = "builder"), on(String, into))]
pub struct ClientCredentialsGrant {
    /// The client ID.
    client_id: String,

    /// The HTTP client used for token requests.
    #[builder(with = |client: impl HttpClient + 'static| Arc::new(client) as Arc<dyn HttpClient>)]
    http_client: Arc<dyn HttpClient>,

    /// The client authentication method.
    #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
    client_auth: Arc<dyn ClientAuthentication>,

    /// The `DPoP` signer. Defaults to [`NoDPoP`] (no token sender-constraining).
    #[builder(
        with = |dpop: impl AuthorizationServerDPoP + 'static| Arc::new(dpop) as Arc<dyn AuthorizationServerDPoP>,
        default = Arc::new(NoDPoP),
    )]
    dpop: Arc<dyn AuthorizationServerDPoP>,

    /// The issuer for tokens created by the authorization server.
    #[from_metadata(path = "issuer")]
    issuer: Option<String>,

    /// The URL of the token endpoint.
    #[from_metadata(path = "token_endpoint")]
    #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
    token_endpoint: EndpointUrl,

    /// The mTLS alias for the token endpoint (RFC 8705 §5).
    #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
    #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
    mtls_token_endpoint: Option<EndpointUrl>,

    /// The endpoint used for token requests: the mTLS alias when the HTTP
    /// client uses mTLS, the primary token endpoint otherwise.
    #[builder(skip = crate::grant::core::resolve_mtls_alias(http_client.as_ref(), &token_endpoint, mtls_token_endpoint.as_ref()))]
    effective_token_endpoint: EndpointUrl,

    /// Supported endpoint auth methods; used to auto-select basic or
    /// form auth for client secrets.
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

    /// Scopes and resources may be re-submitted freely.
    fn reusable_parameters(&self) -> bool {
        true
    }

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn client_auth(&self) -> &dyn ClientAuthentication {
        self.client_auth.as_ref()
    }

    // Deliberately returns the build-time-resolved endpoint, not the raw
    // `token_endpoint` builder input.
    #[allow(clippy::misnamed_getters)]
    fn token_endpoint(&self) -> &EndpointUrl {
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
            .token_endpoint(self.effective_token_endpoint.clone())
            .expect("an EndpointUrl converts to itself infallibly")
            .maybe_token_endpoint_auth_methods_supported(
                self.token_endpoint_auth_methods_supported.clone(),
            )
            .build()
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        ClientCredentialsGrantForm {
            grant_type: "client_credentials",
            scope: params.scope,
            resource: params.resource,
        }
    }
}

/// Parameters when requesting a token using the client credentials grant.
#[derive(Debug, Clone, Builder)]
pub struct ClientCredentialsGrantParameters {
    /// The requested scope(s) for the access token.
    #[builder(required, default, name = "scopes", with = |scopes: impl IntoIterator<Item = impl Into<String>>| mk_scopes(scopes))]
    scope: Option<String>,
    /// The target resource(s) for the access token.
    resource: Option<Vec<String>>,
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

/// Client credentials grant body.
#[derive(Debug, Serialize)]
pub struct ClientCredentialsGrantForm {
    grant_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<Vec<String>>,
}

#[cfg(all(test, not(target_family = "wasm")))]
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
        let form = super::ClientCredentialsGrantForm {
            grant_type: "client_credentials",
            scope: None,
            resource: Some(vec![
                "https://api.example.com".to_string(),
                "https://other.example.com".to_string(),
            ]),
        };
        let encoded = serde_html_form::to_string(&form).unwrap();
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
            .token_endpoint(MOCK_SERVER.url("/no_dpop/token"))
            .unwrap()
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
            .token_endpoint(MOCK_SERVER.url("/with_dpop/token"))
            .unwrap()
            .client_id("client")
            .http_client(http_client())
            .client_auth(NoAuth)
            .dpop(
                DPoP::builder()
                    .signer(PrivateKey::generate(GenerateAlgorithm::Es256, None))
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

        assert!(matches!(response.access_token(), AccessToken::Dpop(_)));
        assert_eq!(
            response.access_token().token().expose_secret(),
            "access_token"
        );
    }
}
