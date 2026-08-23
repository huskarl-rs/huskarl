//! JWT bearer grant (RFC 7523 §2.1).
//!
//! Used to request an access token by presenting a JWT *assertion* that an
//! authority the authorization server trusts has signed. The assertion identifies
//! the principal the token is for; the client does not act on its own behalf (for
//! that, see [`client_credentials`](crate::grant::client_credentials)). The
//! assertion is caller-supplied and already signed — the library does not mint it.
//!
//! See the [JWT bearer how-to guide](crate::_docs::guide::jwt_bearer) for
//! step-by-step setup, including how to build and sign the assertion JWT.

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

/// An OAuth 2.0 JWT bearer grant (RFC 7523).
///
/// This grant requests an access token by presenting a signed JWT assertion that
/// vouches for the principal the token is for. The assertion is supplied by the
/// caller (see the [module documentation][crate::grant::jwt_bearer] for how to
/// create one); this grant does not mint it.
///
/// See the [module documentation][crate::grant::jwt_bearer] for a usage guide.
#[huskarl_macros::from_metadata(metadata = crate::core::server_metadata::AuthorizationServerMetadata)]
#[derive(Clone, Builder)]
#[builder(on(String, into), builder_type(doc {
    /// Configures a [`JwtBearerGrant`].
    ///
    /// Required and optional inputs are marked on their setter methods. Prefer
    /// [`JwtBearerGrant::builder_from_metadata`] when discovery metadata is
    /// available; it fills endpoint, issuer, and authentication capability
    /// inputs before returning this builder.
}))]
pub struct JwtBearerGrant {
    /// The client ID. Optional: omit it for an unidentified client (the
    /// assertion's `iss`/`sub` identify the principal; RFC 7523 §3.1 allows a
    /// grant with no client identification).
    client_id: Option<String>,

    /// The transport used for token requests.
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

impl JwtBearerGrant {
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
            .token_endpoint(self.token_endpoint.clone())
            .maybe_mtls_token_endpoint(self.mtls_token_endpoint.clone())
            .maybe_token_endpoint_auth_methods_supported(
                self.token_endpoint_auth_methods_supported.clone(),
            )
            .build()
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        JwtBearerGrantForm {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion: params.assertion,
            scope: join_space(params.scope.as_deref()),
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
    scope: Option<Vec<String>>,
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
    /// Fixed OAuth 2.0 grant type:
    /// `urn:ietf:params:oauth:grant-type:jwt-bearer`.
    grant_type: &'static str,
    /// Signed JWT assertion serialized into the outgoing form.
    assertion: SecretString,
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
        core::{
            client_auth::NoAuth,
            dpop::{DPoP, SessionKeyedDPoP},
            secrets::SecretString,
        },
        grant::jwt_bearer::{JwtBearerGrant, JwtBearerGrantParameters},
        token::AccessToken,
    };

    static MOCK_SERVER: LazyLock<MockServer> = LazyLock::new(MockServer::start);

    fn http_client() -> ReqwestClient {
        reqwest::Client::new().into()
    }

    /// One grant per authorization server; a per-session grant derived from it
    /// signs the token proof with that session's key.
    #[tokio::test]
    async fn test_exchange_with_session_dpop_key() {
        use httpmock::prelude::*;

        use crate::prelude::*;

        let grant = JwtBearerGrant::builder()
            .token_endpoint(
                MOCK_SERVER
                    .url("/session_dpop/jwt_bearer/token")
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
                    .path("/session_dpop/jwt_bearer/token")
                    .header_exists("DPoP")
                    .form_urlencoded_tuple(
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    );
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
        assert!(matches!(
            response.unwrap().access_token(),
            AccessToken::DPoP(_)
        ));
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

        assert!(matches!(response.access_token(), AccessToken::DPoP(_)));
        assert_eq!(
            response.access_token().token().expose_secret(),
            "access_token"
        );
    }
}
