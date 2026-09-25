use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Uri};
use huskarl::{
    authorizer::{HttpAuthorizer, dpop_resend_advised},
    cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache, NoSource},
    core::{
        AuthorizationDetail,
        client_auth::ClientAuthentication,
        dpop::AuthorizationServerDPoP,
        http::{HttpClient, Idempotency},
        server_metadata::AuthorizationServerMetadata,
    },
    grant::{
        authorization_code::{
            AuthorizationCodeGrant, CompleteOutput, Jar, ResponseMode, StartInput, StartOutput,
            bind_loopback,
        },
        core::OAuth2ExchangeGrant,
    },
};
use huskarl_reqwest::{
    ReqwestClient,
    mtls::{MtlsProvider, NoMtls},
};
use tokio::net::TcpListener;

use crate::{api::Error, browser::Browser, client_error::ClientError, config::Config};

/// Plan-scoped transport and callback state, reused across modules.
pub struct FlowContext {
    pub http_client: ReqwestClient,
    browser: Browser,
    listener: TcpListener,
    pub redirect_uri: String,
    pub issuer: String,
}

/// Per-scenario authorization parameters. Registration can supply a fresh client ID.
#[derive(Clone)]
pub struct AuthorizationOptions {
    pub client_id: String,
    pub scopes: Vec<String>,
    pub response_mode: Option<ResponseMode>,
    /// None infers OIDC from scopes; false explicitly selects plain OAuth.
    pub oidc: Option<bool>,
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
    /// Disable optional PAR when exercising direct request-object delivery.
    pub prefer_pushed_authorization_requests: bool,
}

impl Default for AuthorizationOptions {
    fn default() -> Self {
        Self {
            client_id: crate::client_id(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            response_mode: None,
            oidc: None,
            authorization_details: None,
            prefer_pushed_authorization_requests: true,
        }
    }
}

impl FlowContext {
    pub async fn new(config: &Config, issuer: String) -> Result<Self, Error> {
        Self::new_with_mtls(config, issuer, NoMtls).await
    }

    /// Configure mTLS for protocol requests, independently of browser navigation.
    pub async fn new_with_mtls(
        config: &Config,
        issuer: String,
        mtls: impl MtlsProvider + 'static,
    ) -> Result<Self, Error> {
        let insecure = config.insecure_tls;
        let timeout = config.request_timeout;
        let http_client = ReqwestClient::builder()
            .mtls(mtls)
            .configure_builder(Box::new(move |b| {
                b.danger_accept_invalid_certs(insecure).timeout(timeout)
            }))
            .build()
            .await?;
        let browser = Browser::spawn(
            reqwest::Client::builder()
                .danger_accept_invalid_certs(insecure)
                .timeout(timeout)
                .cookie_store(true)
                .build()?,
        );
        let listener = bind_loopback(0).await?;
        let redirect_uri = format!(
            "http://127.0.0.1:{}/callback",
            listener.local_addr()?.port()
        );
        Ok(Self {
            http_client,
            browser,
            listener,
            redirect_uri,
            issuer,
        })
    }

    /// Fetch and validate discovery without starting authorization or fetching keys.
    pub async fn discover(&self) -> Result<AuthorizationServerMetadata, ClientError> {
        AuthorizationServerMetadata::oidc_fetch()
            .issuer(&self.issuer)
            .http_client(&self.http_client)
            .call()
            .await
            .map_err(|e| ClientError::capture(&e))
    }

    /// Fetch discovery afresh while the module is active, then drive authorization.
    pub async fn authorize<
        Auth: ClientAuthentication + 'static,
        D: AuthorizationServerDPoP + 'static,
        J: Jar + 'static,
    >(
        &self,
        options: &AuthorizationOptions,
        client_auth: Auth,
        dpop: D,
        jar: J,
    ) -> Result<FlowOutput, ClientError> {
        let prepared = self
            .prepare_authorization(options, client_auth, dpop, jar)
            .await?;
        self.authorize_prepared(&prepared).await
    }

    /// Discover and build once so repeated flows share the grant's JWKS cache.
    pub async fn prepare_authorization<
        Auth: ClientAuthentication + 'static,
        D: AuthorizationServerDPoP + 'static,
        J: Jar + 'static,
    >(
        &self,
        options: &AuthorizationOptions,
        client_auth: Auth,
        dpop: D,
        jar: J,
    ) -> Result<PreparedAuthorization, ClientError> {
        let metadata = self.discover().await?;
        self.prepare_authorization_from_metadata(options, client_auth, dpop, jar, metadata)
            .await
    }

    /// Build using the discovery document already used for dynamic registration.
    pub async fn prepare_authorization_from_metadata<
        Auth: ClientAuthentication + 'static,
        D: AuthorizationServerDPoP + 'static,
        J: Jar + 'static,
    >(
        &self,
        options: &AuthorizationOptions,
        client_auth: Auth,
        dpop: D,
        jar: J,
        metadata: AuthorizationServerMetadata,
    ) -> Result<PreparedAuthorization, ClientError> {
        let grant: AuthorizationCodeGrant =
            AuthorizationCodeGrant::builder_from_metadata(&metadata)
                .map_err(|e| ClientError::capture(&e))?
                .client_id(&options.client_id)
                .http_client(self.http_client.clone())
                .client_auth(client_auth)
                .redirect_uri(&self.redirect_uri)
                .maybe_response_mode(options.response_mode)
                .maybe_oidc(options.oidc)
                .prefer_pushed_authorization_requests(options.prefer_pushed_authorization_requests)
                .dpop(dpop)
                .jar(jar)
                // jws_verifier_factory defaults to a JwksSource wired from http_client.
                .build()
                .await
                .map_err(|e| ClientError::capture(&e))?;

        Ok(PreparedAuthorization {
            grant,
            metadata,
            scopes: options.scopes.clone(),
            authorization_details: options.authorization_details.clone(),
        })
    }

    /// Start a fresh authorization using an existing grant and its cached verifier.
    pub async fn authorize_prepared(
        &self,
        prepared: &PreparedAuthorization,
    ) -> Result<FlowOutput, ClientError> {
        let grant = &prepared.grant;
        // Build the token source from the refresh grant (takes &self, so `grant` is
        // still usable). Its resource_server_dpop is derived from grant.dpop() here.
        // Keep an Arc handle so the source can be primed after the flow completes.
        let source = Arc::new(
            GrantTokenSource::builder()
                .grant(grant.to_refresh_grant())
                .grant_parameters(NoSource)
                .refresh_store(InMemoryRefreshTokenStore::default())
                .build(),
        );
        let authorizer = HttpAuthorizer::builder()
            .cache(InMemoryTokenCache::builder().source(source.clone()).build())
            .build();

        let StartOutput {
            authorization_url,
            pending_state,
            ..
        } = grant
            .start(
                StartInput::builder()
                    .scope(prepared.scopes.clone())
                    .maybe_authorization_details(prepared.authorization_details.clone())
                    .build(),
            )
            .await
            .map_err(|e| ClientError::capture(&e))?;

        let browser_result = self
            .browser
            .navigate(authorization_url.to_string(), self.redirect_uri.clone())
            .await;

        let complete = tokio::select! {
            biased;
            result = grant.complete_on_loopback(&self.listener, &pending_state, None) => {
                println!("    loopback completed: {}", result.as_ref().map(|_| "ok").unwrap_or_else(|_e| "err"));
                result.map_err(|e| ClientError::capture(&e))
            }
            nav = browser_result => {
                match nav.map_err(|_| "browser task stopped".to_string())? {
                    Ok(r) => {
                        Err(format!(
                            "browser navigation ended (HTTP {}) before flow completion",
                            r.status,
                        ).into())
                    }
                    Err(e) => Err(format!("browser navigation failed: {e}").into()),
                }
            }
        }?;

        // Prime the source so get_headers() immediately returns the fresh token.
        source
            .prime(complete.token_response.clone())
            .await
            .map_err(|e| ClientError::capture(&e))?;

        Ok(FlowOutput {
            complete,
            authorizer,
            metadata: prepared.metadata.clone(),
        })
    }
}
/// Makes a GET request to `uri`, re-sending once when the client advises DPoP nonce recovery.
///
/// Each call to `get_headers` generates a fresh DPoP proof (including the current nonce).
/// `process_response` records each response's `DPoP-Nonce` (and invalidates the token on an
/// `invalid_token` challenge). The client's `dpop_resend_advised` decides whether
/// a nonce challenge warrants a re-send; other failures are returned without retrying.
pub async fn call_resource_get(
    http_client: &ReqwestClient,
    authorizer: &HttpAuthorizer,
    uri: &Uri,
) -> Result<u16, ClientError> {
    let mut retried = false;
    loop {
        let headers = match authorizer.get_headers(&Method::GET, uri).await {
            Ok(h) => h,
            Err(e) => return Err(ClientError::capture(&e)),
        };

        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.headers = headers;
        parts.uri = uri.clone();
        let request = http::Request::from_parts(parts, Bytes::new());

        let response = match http_client.execute(request, Idempotency::Idempotent).await {
            Ok(r) => r,
            Err(e) => return Err(ClientError::capture(&e)),
        };

        authorizer.process_response(uri, &response.headers);

        if !retried && dpop_resend_advised(response.status, &response.headers) {
            retried = true;
            continue;
        }
        return Ok(response.status.as_u16());
    }
}

/// Validated client output, kept separate from the suite verdict.
pub struct FlowOutput {
    pub complete: CompleteOutput,
    pub authorizer: HttpAuthorizer,
    pub metadata: AuthorizationServerMetadata,
}

/// Module-scoped authorization state. Reuse it across a signing-key rotation.
pub struct PreparedAuthorization {
    grant: AuthorizationCodeGrant,
    metadata: AuthorizationServerMetadata,
    scopes: Vec<String>,
    authorization_details: Option<Vec<AuthorizationDetail>>,
}

impl PreparedAuthorization {
    /// Share the grant's DPoP and verification state with resource clients.
    pub fn grant(&self) -> &AuthorizationCodeGrant {
        &self.grant
    }
}
