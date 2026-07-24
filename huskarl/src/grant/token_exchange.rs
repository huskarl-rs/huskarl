//! Token exchange grant (RFC 8693).
//!
//! Used to issue a new security token by exchanging an existing token, supporting
//! impersonation and delegation without requiring user re-authentication. The
//! existing token is the grant's authorization, so client authentication is
//! optional.
//!
//! See the [token exchange how-to guide](crate::_docs::guide::token_exchange) for
//! step-by-step setup.

use std::sync::Arc;

use bon::Builder;
use serde::Serialize;

use crate::{
    cache::GrantParametersSource,
    core::{
        EndpointUrl, Error,
        client_auth::ClientAuthentication,
        crypto::signer::AsymmetricJwsSignerSelector,
        dpop::{AuthorizationServerDPoP, NoDPoP},
        http::HttpClient,
        platform::MaybeSendBoxFuture,
        secrets::SecretString,
    },
    grant::{
        core::{OAuth2ExchangeGrant, join_space},
        refresh::RefreshGrant,
    },
};

/// An `OAuth2` token exchange grant.
///
/// This grant is used to issue a new security token by exchanging an existing
/// token, without requiring user re-authentication. It supports impersonation
/// and delegation use cases by allowing the exchange of one token type for another.
///
/// See the [module documentation][crate::grant::token_exchange] for a usage guide.
#[huskarl_macros::from_metadata(metadata = crate::core::server_metadata::AuthorizationServerMetadata)]
#[derive(Clone, Builder)]
#[builder(on(String, into))]
pub struct TokenExchangeGrant {
    /// The client ID. Optional: omit it for an unidentified client (RFC 8693 §2
    /// leaves client identification to the authorization server's discretion).
    client_id: Option<String>,

    /// The HTTP client used for token requests.
    #[builder(with = |client: impl HttpClient + 'static| Arc::new(client) as Arc<dyn HttpClient>)]
    http_client: Arc<dyn HttpClient>,

    /// The client authentication method. Optional — the subject token is the
    /// grant. Omit it to send no client credentials, supply
    /// [`NoAuth`](crate::core::client_auth::NoAuth) to send the `client_id`
    /// without credentials, or any other [`ClientAuthentication`] to
    /// authenticate.
    #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
    client_auth: Option<Arc<dyn ClientAuthentication>>,

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
    token_endpoint: EndpointUrl,

    /// The mTLS alias for the token endpoint (RFC 8705 §5).
    #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
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

impl TokenExchangeGrant {
    /// Binds a per-session `DPoP` key, returning a grant that signs with it.
    ///
    /// Derived grants share the grant's server-scoped `DPoP` nonce, so one
    /// grant per authorization server serves every session.
    ///
    /// # Errors
    ///
    /// Returns an error unless the configured `DPoP` is
    /// [`SessionKeyedDPoP`](crate::core::dpop::SessionKeyedDPoP).
    pub fn with_session_dpop_key(
        &self,
        key: impl AsymmetricJwsSignerSelector + 'static,
    ) -> Result<Self, Error> {
        Ok(Self {
            dpop: self.dpop.with_session_key(Arc::new(key))?,
            ..self.clone()
        })
    }
}

impl core::fmt::Debug for TokenExchangeGrant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TokenExchangeGrant")
            .field("client_id", &self.client_id)
            .field("issuer", &self.issuer)
            .field("token_endpoint", &self.token_endpoint)
            .field("mtls_token_endpoint", &self.mtls_token_endpoint)
            .finish_non_exhaustive()
    }
}

impl OAuth2ExchangeGrant for TokenExchangeGrant {
    type Parameters = TokenExchangeGrantParameters;
    type Form<'a> = TokenExchangeGrantForm;

    fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn client_auth(&self) -> Option<&dyn ClientAuthentication> {
        self.client_auth.as_deref()
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
            .maybe_client_id(self.client_id.clone())
            .maybe_issuer(self.issuer.clone())
            .http_client(self.http_client.clone())
            .maybe_client_auth(self.client_auth.clone())
            .dpop(self.dpop.clone())
            .token_endpoint(self.token_endpoint.clone())
            .maybe_mtls_token_endpoint(self.mtls_token_endpoint.clone())
            .maybe_token_endpoint_auth_methods_supported(
                self.token_endpoint_auth_methods_supported.clone(),
            )
            .build()
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        TokenExchangeGrantForm {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
            resource: params.resource,
            authorization_details: params.authorization_details,
            audience: params.audience,
            scope: join_space(params.scope.as_deref()),
            requested_token_type: params.requested_token_type,
            subject_token: params.subject.token,
            subject_token_type: params.subject.token_type,
            actor_token: params.actor.as_ref().map(|t| t.token.clone()),
            actor_token_type: params.actor.as_ref().map(|t| t.token_type.clone()),
        }
    }
}

/// Parameters when requesting a token using the token exchange grant.
#[derive(Debug, Clone, Builder)]
#[builder(on(String, into), on(SecurityToken, into))]
pub struct TokenExchangeGrantParameters {
    /// The security token to exchange (the subject of the exchange).
    subject: SecurityToken,
    /// The URI of a resource server where the requested token will be used.
    resource: Option<Vec<String>>,
    /// RFC 9396 `authorization_details` requested for the issued access token.
    authorization_details: Option<Vec<crate::core::AuthorizationDetail>>,
    /// The logical name of the target service or resource where the requested token will be used.
    audience: Option<String>,
    /// The requested scope(s) for the issued security token.
    scope: Option<Vec<String>>,
    /// The type of the requested security token (e.g. `urn:ietf:params:oauth:token-type:access_token`).
    requested_token_type: Option<String>,
    /// An optional security token representing the party acting on behalf of the subject.
    actor: Option<SecurityToken>,
}

/// Token exchange parameters are reusable: subject and actor tokens may be
/// exchanged repeatedly while they remain valid, so the cache clones them for
/// each exchange. Pass a value directly to the cache builder; for tokens that
/// must be refetched per request, use [`from_fn`](crate::cache::from_fn).
impl GrantParametersSource<Self> for TokenExchangeGrantParameters {
    fn acquire(&self) -> MaybeSendBoxFuture<'_, Result<Option<Self>, Error>> {
        let params = self.clone();
        Box::pin(async move { Ok(Some(params)) })
    }

    fn discard_after_rejection(&self) -> bool {
        true
    }
}

/// A security token used as the subject or actor in a token exchange.
#[derive(Debug, Clone, Builder)]
pub struct SecurityToken {
    /// The raw token.
    ///
    /// Accepts anything that converts into a
    /// [`SecretString`] — a `&str`, `String`,
    /// or the `SecretString` you already hold (e.g. from a
    /// [`TokenResponse`](crate::grant::core::TokenResponse)). Held redacted;
    /// serialized only when the request is sent.
    #[builder(into)]
    token: SecretString,
    /// The type of the token.
    token_type: SecurityTokenType,
}

/// The type of a [`SecurityToken`] in an RFC 8693 token exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum SecurityTokenType {
    /// `urn:ietf:params:oauth:token-type:access_token`
    #[serde(rename = "urn:ietf:params:oauth:token-type:access_token")]
    AccessToken,
    /// `urn:ietf:params:oauth:token-type:refresh_token`
    #[serde(rename = "urn:ietf:params:oauth:token-type:refresh_token")]
    RefreshToken,
    /// `urn:ietf:params:oauth:token-type:id_token`
    #[serde(rename = "urn:ietf:params:oauth:token-type:id_token")]
    IdToken,
    /// `urn:ietf:params:oauth:token-type:saml1`
    #[serde(rename = "urn:ietf:params:oauth:token-type:saml1")]
    Saml1,
    /// `urn:ietf:params:oauth:token-type:saml2`
    #[serde(rename = "urn:ietf:params:oauth:token-type:saml2")]
    Saml2,
    /// `urn:ietf:params:oauth:token-type:jwt`
    #[serde(rename = "urn:ietf:params:oauth:token-type:jwt")]
    Jwt,
    /// An extension token type not covered by the standard variants.
    #[serde(untagged)]
    Other(String),
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::Request;
    use serde_json::json;

    use super::*;
    use crate::core::{
        Error,
        http::{HttpClient, HttpResponse, Idempotency},
        platform::MaybeSendBoxFuture,
    };

    /// An [`HttpClient`] that must never be called — `build_form` does no I/O.
    struct UnusedClient;

    impl HttpClient for UnusedClient {
        fn execute(
            &self,
            _request: Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            Box::pin(async { unreachable!("build_form performs no HTTP request") })
        }
    }

    /// An [`HttpClient`] presenting an RFC 8705 mTLS client certificate, so that
    /// endpoint resolution takes the alias branch.
    struct MtlsClient;

    impl HttpClient for MtlsClient {
        fn execute(
            &self,
            _request: Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            Box::pin(async { unreachable!("endpoint resolution performs no HTTP request") })
        }

        fn uses_mtls(&self) -> bool {
            true
        }
    }

    fn grant() -> TokenExchangeGrant {
        TokenExchangeGrant::builder()
            .token_endpoint("https://as.example/token".parse::<EndpointUrl>().unwrap())
            .client_id("exchange-client")
            .http_client(UnusedClient)
            .build()
    }

    // RFC 8705 §5: the published token endpoint and the mTLS alias serve
    // different roles — the former is the `Audience::TokenEndpoint` assertion
    // `aud`, the latter is where the request is actually sent. A derived refresh
    // grant must inherit both, not the resolved alias flattened into each.
    #[test]
    fn to_refresh_grant_keeps_published_and_alias_endpoints_distinct() {
        let published: EndpointUrl = "https://as.example/token".parse().unwrap();
        let alias: EndpointUrl = "https://mtls.as.example/token".parse().unwrap();

        let grant = TokenExchangeGrant::builder()
            .token_endpoint(published.clone())
            .mtls_token_endpoint(alias.clone())
            .client_id("exchange-client")
            .http_client(MtlsClient)
            .build();

        assert_eq!(grant.token_endpoint(), &published);
        assert_eq!(grant.effective_token_endpoint(), &alias);

        let refresh = grant.to_refresh_grant();
        assert_eq!(
            refresh.token_endpoint(),
            &published,
            "the assertion audience must stay the published endpoint"
        );
        assert_eq!(
            refresh.effective_token_endpoint(),
            &alias,
            "requests must still go to the mTLS alias"
        );
    }

    // Without mTLS the alias is inert, and both endpoints stay the published one.
    #[test]
    fn to_refresh_grant_without_mtls_uses_the_published_endpoint_throughout() {
        let published: EndpointUrl = "https://as.example/token".parse().unwrap();
        let refresh = grant().to_refresh_grant();

        assert_eq!(refresh.token_endpoint(), &published);
        assert_eq!(refresh.effective_token_endpoint(), &published);
    }

    fn subject() -> SecurityToken {
        SecurityToken::builder()
            .token("subject-tok")
            .token_type(SecurityTokenType::AccessToken)
            .build()
    }

    #[test]
    fn build_form_maps_all_parameters_onto_the_wire() {
        let params = TokenExchangeGrantParameters::builder()
            .subject(subject())
            .actor(
                SecurityToken::builder()
                    .token("actor-tok")
                    .token_type(SecurityTokenType::Jwt)
                    .build(),
            )
            .audience("https://api.example")
            .scope(bon::vec!["read", "write"])
            .requested_token_type("urn:ietf:params:oauth:token-type:access_token")
            .authorization_details(vec![
                crate::core::AuthorizationDetail::builder("payment_initiation")
                    .with("actions", serde_json::json!(["initiate"]))
                    .build(),
            ])
            .build();

        let encoded = crate::core::oauth_form::to_string(&grant().build_form(params)).unwrap();

        for expected in [
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
            "subject_token=subject-tok",
            "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
            "actor_token=actor-tok",
            "actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt",
            "audience=https%3A%2F%2Fapi.example",
            "scope=read+write",
            "requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
            // RFC 9396 §6: one parameter carrying URL-encoded JSON (`%5B%7B` = `[{`).
            "authorization_details=%5B%7B",
        ] {
            assert!(
                encoded.contains(expected),
                "missing {expected} in: {encoded}"
            );
        }
    }

    #[test]
    fn build_form_omits_absent_optional_fields() {
        // Only the subject is supplied; every other field is optional.
        let params = TokenExchangeGrantParameters::builder()
            .subject(subject())
            .scope(vec![])
            .build();

        let encoded = crate::core::oauth_form::to_string(&grant().build_form(params)).unwrap();

        // The subject and the constant grant type are always present.
        assert!(encoded.contains("grant_type="));
        assert!(encoded.contains("subject_token=subject-tok"));
        // Absent optionals are skipped entirely (no empty `key=`).
        for absent in [
            "resource",
            "audience",
            "scope",
            "requested_token_type",
            "actor_token",
            "actor_token_type",
        ] {
            assert!(
                !encoded.contains(absent),
                "{absent} should be omitted, but found it in: {encoded}"
            );
        }
    }

    #[test]
    fn resource_serializes_as_repeated_keys() {
        let params = TokenExchangeGrantParameters::builder()
            .subject(subject())
            .resource(vec![
                "https://api.example.com".to_string(),
                "https://other.example.com".to_string(),
            ])
            .scope(vec![])
            .build();

        let encoded = crate::core::oauth_form::to_string(&grant().build_form(params)).unwrap();

        assert!(encoded.contains("resource=https%3A%2F%2Fapi.example.com"));
        assert!(encoded.contains("resource=https%3A%2F%2Fother.example.com"));
        assert!(
            !encoded.contains(','),
            "resource must not be comma-joined: {encoded}"
        );
    }

    #[test]
    fn security_token_type_serializes_to_rfc8693_urns() {
        for (ty, urn) in [
            (
                SecurityTokenType::AccessToken,
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                SecurityTokenType::RefreshToken,
                "urn:ietf:params:oauth:token-type:refresh_token",
            ),
            (
                SecurityTokenType::IdToken,
                "urn:ietf:params:oauth:token-type:id_token",
            ),
            (
                SecurityTokenType::Saml1,
                "urn:ietf:params:oauth:token-type:saml1",
            ),
            (
                SecurityTokenType::Saml2,
                "urn:ietf:params:oauth:token-type:saml2",
            ),
            (
                SecurityTokenType::Jwt,
                "urn:ietf:params:oauth:token-type:jwt",
            ),
        ] {
            assert_eq!(serde_json::to_value(&ty).unwrap(), json!(urn));
        }

        // The `Other` extension variant serializes untagged as its raw string.
        assert_eq!(
            serde_json::to_value(SecurityTokenType::Other(
                "urn:example:custom-token".to_string()
            ))
            .unwrap(),
            json!("urn:example:custom-token")
        );
    }
}

/// Token exchange grant body.
#[derive(Debug, Serialize)]
pub struct TokenExchangeGrantForm {
    grant_type: &'static str,
    resource: Option<Vec<String>>,
    /// RFC 9396 `authorization_details` requested for the issued access token.
    authorization_details: Option<Vec<crate::core::AuthorizationDetail>>,
    audience: Option<String>,
    scope: Option<String>,
    requested_token_type: Option<String>,
    subject_token: SecretString,
    subject_token_type: SecurityTokenType,
    actor_token: Option<SecretString>,
    actor_token_type: Option<SecurityTokenType>,
}

#[cfg(test)]
#[cfg(not(target_family = "wasm"))]
mod session_dpop_tests {
    use std::sync::LazyLock;

    use httpmock::MockServer;
    use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
    use huskarl_reqwest::ReqwestClient;
    use serde_json::json;

    use super::{
        SecurityToken, SecurityTokenType, TokenExchangeGrant, TokenExchangeGrantParameters,
    };
    use crate::{
        core::{client_auth::NoAuth, dpop::SessionKeyedDPoP},
        grant::core::OAuth2ExchangeGrant,
        token::AccessToken,
    };

    static MOCK_SERVER: LazyLock<MockServer> = LazyLock::new(MockServer::start);

    fn http_client() -> ReqwestClient {
        reqwest::Client::new().into()
    }

    /// One grant per authorization server; a per-session grant derived from it
    /// signs the token proof with that session's key.
    #[tokio::test]
    async fn exchange_with_session_dpop_key() {
        use httpmock::prelude::*;

        let grant = TokenExchangeGrant::builder()
            .token_endpoint(
                MOCK_SERVER
                    .url("/session_dpop/token_exchange/token")
                    .parse()
                    .unwrap(),
            )
            .client_id("client")
            .http_client(http_client())
            .client_auth(NoAuth)
            .dpop(SessionKeyedDPoP::new())
            .build()
            .with_session_dpop_key(PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap())
            .unwrap();

        let mock = MOCK_SERVER
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/session_dpop/token_exchange/token")
                    .header_exists("DPoP")
                    .form_urlencoded_tuple(
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                    );
                then.status(200)
                    .header("Content-Type", "application/json")
                    .json_body(json!({
                        "access_token": "access_token",
                        "token_type": "DPoP",
                        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    }));
            })
            .await;

        let response = grant
            .exchange(
                TokenExchangeGrantParameters::builder()
                    .subject(
                        SecurityToken::builder()
                            .token("subject-token")
                            .token_type(SecurityTokenType::AccessToken)
                            .build(),
                    )
                    .build(),
            )
            .await;

        mock.assert();
        assert!(matches!(
            response.unwrap().access_token(),
            AccessToken::DPoP(_)
        ));
    }
}
