//! Client credentials grant (RFC 6749 §4.4).
//!
//! Used when the client is acting on its own behalf, not on behalf of a user.

use bon::Builder;
use serde::Serialize;

use crate::{
    core::server_metadata::AuthorizationServerMetadata,
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
#[huskarl_macros::grant]
#[derive(Debug, Builder)]
#[builder(state_mod(name = "builder"), on(String, into))]
pub struct ClientCredentialsGrant {}

impl<
    Auth: crate::core::client_auth::ClientAuthentication + 'static,
    D: crate::core::dpop::AuthorizationServerDPoP + 'static,
> ClientCredentialsGrant<Auth, D>
{
    /// Configure the grant from authorization server metadata.
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> ClientCredentialsGrantBuilder<Auth, D, SetCommonMetadata> {
        ClientCredentialsGrant::builder().with_common_metadata(metadata)
    }
}

#[huskarl_macros::grant_impl]
impl<
    Auth: crate::core::client_auth::ClientAuthentication + Clone + 'static,
    D: crate::core::dpop::AuthorizationServerDPoP + 'static,
> OAuth2ExchangeGrant for ClientCredentialsGrant<Auth, D>
{
    type Parameters = ClientCredentialsGrantParameters;
    type ClientAuth = Auth;
    type DPoP = D;
    type Form<'a> = ClientCredentialsGrantForm;

    fn to_refresh_grant(&self) -> RefreshGrant<Auth, D> {
        RefreshGrant::builder()
            .client_id(self.client_id.clone())
            .maybe_issuer(self.issuer.clone())
            .client_auth(self.client_auth.clone())
            .dpop(self.dpop.clone())
            .token_endpoint(self.token_endpoint.clone())
            .unwrap_or_else(|e| match e {})
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
    use crate::token::AccessToken;
    use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
    use huskarl_reqwest::ReqwestClient;
    use serde_json::json;

    use crate::{
        core::{
            client_auth::NoAuth,
            dpop::{DPoP, NoDPoP},
        },
        grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
    };

    static MOCK_SERVER: LazyLock<MockServer> = LazyLock::new(MockServer::start);
    static HTTP_CLIENT: LazyLock<ReqwestClient> = LazyLock::new(|| reqwest::Client::new().into());

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
        use crate::prelude::*;
        use httpmock::prelude::*;

        let grant = ClientCredentialsGrant::builder()
            .token_endpoint(MOCK_SERVER.url("/no_dpop/token"))
            .unwrap()
            .client_id("client")
            .client_auth(NoAuth)
            .dpop(NoDPoP)
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
            .exchange(
                LazyLock::force(&HTTP_CLIENT),
                ClientCredentialsGrantParameters::builder().build(),
            )
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
        use crate::prelude::*;
        use httpmock::prelude::*;

        let grant = ClientCredentialsGrant::builder()
            .token_endpoint(MOCK_SERVER.url("/with_dpop/token"))
            .unwrap()
            .client_id("client")
            .client_auth(NoAuth)
            .dpop(
                DPoP::builder()
                    .signer(PrivateKey::generate(GenerateAlgorithm::Es256))
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
            .exchange(
                LazyLock::force(&HTTP_CLIENT),
                ClientCredentialsGrantParameters::builder().build(),
            )
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
