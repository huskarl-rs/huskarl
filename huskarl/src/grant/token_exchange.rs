//! Token exchange grant (RFC 8693).
//!
//! Used to issue a new security token by exchanging an existing token, supporting
//! impersonation and delegation without requiring user re-authentication.
//!
//! # Usage
//!
//! ## 1. Set up your HTTP client
//!
//! The examples below use the `huskarl_reqwest` crate; see [Setting up an HTTP
//! client](crate::grant#setting-up-an-http-client) for the shared setup the rest
//! of this page assumes.
//!
//! ## 2. Set up client authentication (optional)
//!
//! The grant presents an existing token as its authorization, so authenticating
//! the client is optional and independent — do it only if your authorization
//! server requires it, otherwise present none at all. See [Setting up client
//! authentication](crate::grant#setting-up-client-authentication).
//!
//! ## 3a. Set up the grant with authorization server metadata
//!
//! ```rust
//! use huskarl::{
//!     core::{client_auth::ClientSecret, server_metadata::AuthorizationServerMetadata},
//!     grant::token_exchange::TokenExchangeGrant,
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
//! let grant: TokenExchangeGrant = TokenExchangeGrant::builder_from_metadata(&metadata)
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
//! use huskarl::{core::client_auth::ClientSecret, grant::token_exchange::TokenExchangeGrant};
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
//! let grant: TokenExchangeGrant = TokenExchangeGrant::builder()
//!     .token_endpoint("https://my-server/token".parse()?)
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
//! use huskarl::grant::token_exchange::{SecurityToken, SecurityTokenType, TokenExchangeGrantParameters};
//! use huskarl::token::AccessToken;
//! # use huskarl::grant::token_exchange::TokenExchangeGrant;
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
//! # let grant: TokenExchangeGrant = TokenExchangeGrant::builder()
//! #     .token_endpoint("https://my-server/token".parse()?)
//! #     .client_id("client_id")
//! #     .http_client(client)
//! #     .client_auth(client_auth)
//! #     .build();
//!
//! let subject = SecurityToken::builder().token("eyToken").token_type(SecurityTokenType::AccessToken).build();
//! let params = TokenExchangeGrantParameters::builder().subject(subject).build();
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
    cache::GrantParametersSource,
    core::{
        EndpointUrl, Error,
        client_auth::ClientAuthentication,
        dpop::{AuthorizationServerDPoP, NoDPoP},
        http::HttpClient,
        platform::MaybeSendBoxFuture,
        secrets::SecretString,
    },
    grant::{
        core::{OAuth2ExchangeGrant, mk_scopes},
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
#[derive(Builder)]
#[builder(on(String, into))]
pub struct TokenExchangeGrant {
    /// The client ID. Optional: omit it for an unidentified client (RFC 8693 §2
    /// leaves client identification to the authorization server's discretion).
    client_id: Option<String>,

    /// The HTTP client used for token requests.
    #[builder(with = |client: impl HttpClient + 'static| Arc::new(client) as Arc<dyn HttpClient>)]
    http_client: Arc<dyn HttpClient>,

    /// The client authentication method. Optional: the subject token is the
    /// grant, independent of client authentication. Omit it to authenticate the
    /// client in no way; supply [`NoAuth`](crate::core::client_auth::NoAuth) to
    /// send the `client_id` without credentials, or any other
    /// [`ClientAuthentication`] to authenticate.
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
            .token_endpoint(self.effective_token_endpoint.clone())
            .maybe_token_endpoint_auth_methods_supported(
                self.token_endpoint_auth_methods_supported.clone(),
            )
            .build()
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        TokenExchangeGrantForm {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
            resource: params.resource,
            audience: params.audience,
            scope: params.scope,
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
    /// The logical name of the target service or resource where the requested token will be used.
    audience: Option<String>,
    /// The requested scope(s) for the issued security token.
    #[builder(required, default, name = "scopes", with = |scopes: impl IntoIterator<Item = impl Into<String>>| mk_scopes(scopes))]
    scope: Option<String>,
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

    fn grant() -> TokenExchangeGrant {
        TokenExchangeGrant::builder()
            .token_endpoint("https://as.example/token".parse::<EndpointUrl>().unwrap())
            .client_id("exchange-client")
            .http_client(UnusedClient)
            .build()
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
            .scopes(["read", "write"])
            .requested_token_type("urn:ietf:params:oauth:token-type:access_token")
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
            .scopes(Vec::<String>::new())
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
            .scopes(Vec::<String>::new())
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
    audience: Option<String>,
    scope: Option<String>,
    requested_token_type: Option<String>,
    subject_token: SecretString,
    subject_token_type: SecurityTokenType,
    actor_token: Option<SecretString>,
    actor_token_type: Option<SecurityTokenType>,
}
