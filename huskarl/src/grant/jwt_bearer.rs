//! JWT bearer grant (RFC 7523 §2.1).
//!
//! Used to request an access token by presenting a JWT *assertion* that an
//! authority the authorization server trusts has signed. The assertion identifies
//! the principal the token is for; the client does not act on its own behalf (for
//! that, see [`client_credentials`](crate::grant::client_credentials)).
//!
//! This grant carries a **caller-supplied, already-signed** assertion. The
//! library does not mint the assertion — see [Creating the assertion
//! JWT](#creating-the-assertion-jwt) below for how to build and sign one.
//!
//! Note that the assertion (the *grant*) is independent of client authentication.
//! A client may still authenticate to the token endpoint separately — for example
//! with [`JwtBearer`](crate::core::client_auth::JwtBearer) (`private_key_jwt`) — in
//! addition to presenting a user assertion as the grant.
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
//! The assertion stands alone, so authenticating the client is optional — do it
//! only if your authorization server requires it. See [Setting up client
//! authentication](crate::grant#setting-up-client-authentication).
//!
//! ## 3a. Set up the grant with authorization server metadata
//!
//! ```rust
//! use huskarl::{
//!     core::{client_auth::ClientSecret, server_metadata::AuthorizationServerMetadata},
//!     grant::jwt_bearer::JwtBearerGrant,
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
//! let grant: JwtBearerGrant = JwtBearerGrant::builder_from_metadata(&metadata)
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
//! use huskarl::{core::client_auth::ClientSecret, grant::jwt_bearer::JwtBearerGrant};
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
//! let grant: JwtBearerGrant = JwtBearerGrant::builder()
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
//! The `assertion` is the signed JWT from [Creating the assertion
//! JWT](#creating-the-assertion-jwt).
//!
//! ```rust
//! use huskarl::prelude::*; // Imports OAuth2ExchangeGrant which defines the exchange call.
//! use huskarl::grant::jwt_bearer::JwtBearerGrantParameters;
//! use huskarl::token::AccessToken;
//! # use huskarl::grant::jwt_bearer::JwtBearerGrant;
//! use huskarl::core::client_auth::ClientSecret;
//! # use huskarl::core::http::HttpClient;
//! # use huskarl::core::secrets::EnvVarSecret;
//! # use huskarl::core::secrets::encodings::StringEncoding;
//! # async fn run(assertion: String) -> Result<(), Box<dyn std::error::Error>> {
//! # let client = huskarl_reqwest::ReqwestClient::builder()
//! #     .build()
//! #     .await?;
//! #
//! # let client_auth: ClientSecret = ClientSecret::new(EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?);
//! #
//! # let grant: JwtBearerGrant = JwtBearerGrant::builder()
//! #     .token_endpoint("https://my-server/token".parse()?)
//! #     .client_id("client_id")
//! #     .http_client(client)
//! #     .client_auth(client_auth)
//! #     .build();
//!
//! let params = JwtBearerGrantParameters::builder()
//!     .assertion(assertion)
//!     .scopes(vec!["read", "write"])
//!     .build();
//! let response = grant.exchange(params).await?;
//! let token: &AccessToken = response.access_token();
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Creating the assertion JWT
//!
//! RFC 7523 §3 requires the assertion to be a JWT signed by an issuer the
//! authorization server trusts. The claims identify the trusted issuer of the
//! assertion (`iss`), the principal the token is for (`sub`), and the
//! authorization server as the audience (`aud`); `exp` and `iat` bound its
//! lifetime. Build and sign one with [`Jwt`](crate::core::jwt::Jwt) and any
//! [`JwsSigner`](crate::core::crypto::signer::JwsSigner) (here, a freshly
//! generated key — in practice load a long-lived key the server trusts):
//!
//! The [`SecretString`] returned by `to_jws_compact` can be passed straight to
//! [`JwtBearerGrantParameters::builder().assertion(..)`](JwtBearerGrantParameters)
//! — the setter accepts any `Into<SecretString>` (`&str`, `String`, or
//! `SecretString`).
//!
//! ```rust
//! use std::time::Duration;
//!
//! use huskarl::core::{jwt::Jwt, secrets::SecretString};
//! use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
//!
//! # async fn make_assertion() -> Result<SecretString, Box<dyn std::error::Error>> {
//! let key = PrivateKey::generate(GenerateAlgorithm::Es256, None)?;
//!
//! let jwt = Jwt::builder()
//!     .issuer("https://issuer.example.com") // who vouches for the assertion (iss)
//!     .subject("user@example.com") // the principal the token is for (sub)
//!     .audience("https://my-issuer") // the authorization server (aud)
//!     .issued_now_expires_after(Duration::from_secs(300))
//!     .claims(())
//!     .build();
//!
//! let assertion = jwt.to_jws_compact(&key).await?;
//! Ok(assertion)
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

/// An `OAuth2` JWT bearer grant (RFC 7523).
///
/// This grant requests an access token by presenting a signed JWT assertion that
/// vouches for the principal the token is for. The assertion is supplied by the
/// caller (see the [module documentation][crate::grant::jwt_bearer] for how to
/// create one); this grant does not mint it.
///
/// See the [module documentation][crate::grant::jwt_bearer] for a usage guide.
#[huskarl_macros::from_metadata(metadata = crate::core::server_metadata::AuthorizationServerMetadata)]
#[derive(Builder)]
#[builder(on(String, into))]
pub struct JwtBearerGrant {
    /// The client ID. Optional: omit it for an unidentified client (the
    /// assertion's `iss`/`sub` identify the principal; RFC 7523 §3.1 allows a
    /// grant with no client identification).
    client_id: Option<String>,

    /// The HTTP client used for token requests.
    #[builder(with = |client: impl HttpClient + 'static| Arc::new(client) as Arc<dyn HttpClient>)]
    http_client: Arc<dyn HttpClient>,

    /// The client authentication method. Optional — the assertion is the grant
    /// (see the [module docs](self#usage)). Omit it to send no client
    /// credentials, supply [`NoAuth`](crate::core::client_auth::NoAuth) to send
    /// the `client_id` without credentials, or any other
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

impl core::fmt::Debug for JwtBearerGrant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JwtBearerGrant")
            .field("client_id", &self.client_id)
            .field("issuer", &self.issuer)
            .field("token_endpoint", &self.token_endpoint)
            .field("mtls_token_endpoint", &self.mtls_token_endpoint)
            .finish_non_exhaustive()
    }
}

impl OAuth2ExchangeGrant for JwtBearerGrant {
    type Parameters = JwtBearerGrantParameters;
    type Form<'a> = JwtBearerGrantForm;

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
        JwtBearerGrantForm {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion: params.assertion,
            scope: params.scope,
            resource: params.resource,
            authorization_details: params.authorization_details,
        }
    }
}

/// Parameters when requesting a token using the JWT bearer grant.
#[derive(Debug, Clone, Builder)]
pub struct JwtBearerGrantParameters {
    /// The signed JWT assertion (RFC 7523 §2.1).
    ///
    /// Accepts anything that converts into a
    /// [`SecretString`] — an already-signed
    /// compact JWS as a `&str` or `String`, or the `SecretString` returned by
    /// [`Jwt::to_jws_compact`](crate::core::jwt::Jwt::to_jws_compact). Held
    /// redacted; serialized only when the request is sent. See the [module
    /// documentation][crate::grant::jwt_bearer#creating-the-assertion-jwt] for how
    /// to build and sign one.
    #[builder(into)]
    assertion: SecretString,
    /// The requested scope(s) for the access token.
    #[builder(required, default, name = "scopes", with = |scopes: impl IntoIterator<Item = impl Into<String>>| mk_scopes(scopes))]
    scope: Option<String>,
    /// The target resource(s) for the access token (RFC 8707).
    resource: Option<Vec<String>>,
    /// RFC 9396 `authorization_details` requested for the issued access token.
    authorization_details: Option<Vec<crate::core::AuthorizationDetail>>,
}

/// A JWT bearer assertion may be presented repeatedly until it expires, so this
/// fixed source clones the same assertion for each exchange — fine while it is
/// valid, but once its `exp` passes the cache cannot obtain a new token. For an
/// assertion the client mints itself, use a [`from_fn`](crate::cache::from_fn)
/// source that re-signs a fresh assertion per exchange.
impl GrantParametersSource<Self> for JwtBearerGrantParameters {
    fn acquire(&self) -> MaybeSendBoxFuture<'_, Result<Option<Self>, Error>> {
        let params = self.clone();
        Box::pin(async move { Ok(Some(params)) })
    }

    // A rejected (e.g. expired) assertion will only be rejected again; stop
    // replaying it.
    fn discard_after_rejection(&self) -> bool {
        true
    }
}

/// JWT bearer grant body.
#[derive(Debug, Serialize, Builder)]
pub struct JwtBearerGrantForm {
    grant_type: &'static str,
    assertion: SecretString,
    scope: Option<String>,
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
        core::{client_auth::NoAuth, dpop::DPoP, secrets::SecretString},
        grant::jwt_bearer::{JwtBearerGrant, JwtBearerGrantParameters},
        token::AccessToken,
    };

    static MOCK_SERVER: LazyLock<MockServer> = LazyLock::new(MockServer::start);

    fn http_client() -> ReqwestClient {
        reqwest::Client::new().into()
    }

    #[test]
    fn test_assertion_setter_accepts_str_string_and_secret() {
        // &str, String, and the SecretString from `to_jws_compact` all convert in.
        for assertion in [
            JwtBearerGrantParameters::builder()
                .assertion("a.b.c")
                .build(),
            JwtBearerGrantParameters::builder()
                .assertion(String::from("a.b.c"))
                .build(),
            JwtBearerGrantParameters::builder()
                .assertion(SecretString::new("a.b.c"))
                .build(),
        ] {
            assert_eq!(assertion.assertion.expose_secret(), "a.b.c");
        }
    }

    #[test]
    fn test_form_serializes_grant_type_and_assertion() {
        let form = super::JwtBearerGrantForm::builder()
            .grant_type("urn:ietf:params:oauth:grant-type:jwt-bearer")
            .assertion(SecretString::new("header.payload.signature"))
            .build();
        let encoded = crate::core::oauth_form::to_string(&form).unwrap();
        assert!(
            encoded.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"),
            "grant_type not found in: {encoded}"
        );
        assert!(
            encoded.contains("assertion=header.payload.signature"),
            "assertion not found in: {encoded}"
        );
        // Optional fields are omitted when absent.
        assert!(
            !encoded.contains("scope="),
            "scope should be omitted: {encoded}"
        );
    }

    #[tokio::test]
    async fn test_exchange() {
        use httpmock::prelude::*;

        use crate::prelude::*;

        let grant = JwtBearerGrant::builder()
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
                    .form_urlencoded_tuple(
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    )
                    .form_urlencoded_tuple("assertion", "the.signed.assertion")
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
                JwtBearerGrantParameters::builder()
                    .assertion("the.signed.assertion")
                    .build(),
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
    async fn test_exchange_anonymous_sends_no_client_id_or_auth() {
        use httpmock::prelude::*;

        use crate::prelude::*;

        // Neither `client_auth` nor `client_id` supplied: the assertion is the
        // grant, so an unidentified, unauthenticated request is valid
        // (RFC 7523 §3.1).
        let grant = JwtBearerGrant::builder()
            .token_endpoint(MOCK_SERVER.url("/anon/token").parse().unwrap())
            .http_client(http_client())
            .build();

        let mock = MOCK_SERVER
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/anon/token")
                    .form_urlencoded_tuple(
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    )
                    .form_urlencoded_tuple("assertion", "the.signed.assertion")
                    .form_urlencoded_tuple_missing("client_id")
                    .form_urlencoded_tuple_missing("client_secret")
                    .header_missing("Authorization");
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
                JwtBearerGrantParameters::builder()
                    .assertion("the.signed.assertion")
                    .build(),
            )
            .await;

        mock.assert();
        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_exchange_with_dpop() {
        use httpmock::prelude::*;

        use crate::prelude::*;

        let grant = JwtBearerGrant::builder()
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
                    .form_urlencoded_tuple(
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    )
                    .form_urlencoded_tuple("assertion", "the.signed.assertion");
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
                JwtBearerGrantParameters::builder()
                    .assertion("the.signed.assertion")
                    .build(),
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
