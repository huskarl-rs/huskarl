pub mod api;
pub mod browser;

use std::sync::Arc;

use browser::Browser;
use bytes::Bytes;
use http::{Method, StatusCode, Uri};
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{InMemoryRefreshTokenStore, InMemoryTokenCache, TokenCache},
    core::{
        client_auth::ClientAuthentication,
        dpop::AuthorizationServerDPoP,
        http::{HttpClient, HttpResponse},
        jwk::JwksSource,
        server_metadata::AuthorizationServerMetadata,
    },
    grant::{
        authorization_code::{AuthorizationCodeGrant, Jar, StartInput, StartOutput, bind_loopback},
        core::{OAuth2ExchangeGrant, TokenResponse},
        refresh::RefreshGrant,
    },
};
use huskarl_reqwest::ReqwestClient;
use tokio::net::TcpListener;

pub const CONFORMANCE_SUITE_BASE: &str = "https://localhost.emobix.co.uk:8443";

pub fn base_url() -> String {
    std::env::var("CONFORMANCE_SUITE_BASE").unwrap_or_else(|_| CONFORMANCE_SUITE_BASE.to_string())
}

pub fn client_id() -> String {
    std::env::var("CONFORMANCE_CLIENT_ID").unwrap_or_else(|_| "client".to_string())
}

pub fn report_module_result(
    test_name: &str,
    info: &api::ModuleInfo,
    flow_ok: bool,
) -> Option<String> {
    let flow_str = if flow_ok { "ok" } else { "rejected" };
    match &info.result {
        Some(api::TestResult::Passed) => {
            println!("  PASSED (flow: {flow_str})");
            None
        }
        Some(api::TestResult::Warning) => {
            println!("  WARNING (flow: {flow_str})");
            None
        }
        Some(api::TestResult::Review) => {
            println!("  REVIEW (flow: {flow_str})");
            None
        }
        Some(api::TestResult::Skipped) => {
            println!("  SKIPPED (flow: {flow_str})");
            None
        }
        other => {
            let msg = format!("  {test_name}: result={other:?}, flow={flow_str}");
            println!("{msg}");
            Some(msg)
        }
    }
}

pub fn assert_no_failures(failures: Vec<String>) {
    if !failures.is_empty() {
        panic!(
            "{} module(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

/// The `HttpAuthorizer` type returned from the auth-code flow helpers.
pub type FlowAuthorizer<Auth, D> =
    HttpAuthorizer<InMemoryTokenCache<RefreshGrant<Auth, D>, InMemoryRefreshTokenStore>>;

/// Builds an HTTP client that accepts the conformance suite's self-signed certificate.
pub async fn build_http_client() -> ReqwestClient {
    ReqwestClient::builder()
        .mtls(huskarl_reqwest::mtls::NoMtls)
        .configure_builder(Box::new(|b| b.danger_accept_invalid_certs(true)))
        .build()
        .await
        .expect("failed to build HTTP client")
}

/// Builds a browser client that follows redirects, stores cookies, and accepts
/// the conformance suite's self-signed certificate.
pub fn build_browser() -> Browser {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .cookie_store(true)
        .build()
        .expect("failed to build browser client");
    Browser::spawn(client)
}

/// Makes a GET request to `uri` using the authorizer, retrying once on a DPoP nonce challenge.
///
/// Each call to `get_headers` generates a fresh DPoP proof (including the current nonce).
/// After each response, `update_from_response_headers` persists any new `DPoP-Nonce` so
/// the retry carries the correct nonce.
pub async fn call_resource_get<T>(
    http_client: &ReqwestClient,
    authorizer: &HttpAuthorizer<T>,
    uri: &Uri,
) where
    T: TokenCache,
    T::Error<ReqwestClient>: std::fmt::Debug,
    <T::DPoP as huskarl::core::dpop::ResourceServerDPoP>::Error: std::fmt::Debug,
{
    let mut retry = false;
    loop {
        let headers = match authorizer.get_headers(http_client, &Method::GET, uri).await {
            Ok(h) => h,
            Err(_) => break,
        };

        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.headers = headers;
        parts.uri = uri.clone();
        let request = http::Request::from_parts(parts, Bytes::new());

        let response = match http_client.execute(request).await {
            Ok(r) => r,
            Err(_) => break,
        };

        let status = response.status();
        authorizer.update_from_response_headers(uri, &response.headers());
        let _ = response.body().await;

        if status.is_success() || retry {
            break;
        }
        if status == StatusCode::UNAUTHORIZED {
            retry = true;
            continue;
        }
        break;
    }
}

/// Drives a single authorization code flow, binding a fresh loopback listener.
///
/// Convenience wrapper for standalone use where the redirect URI doesn't need
/// to match a pre-registered value.
pub async fn run_auth_code_flow<
    Auth: ClientAuthentication + Clone + 'static,
    D: AuthorizationServerDPoP + Clone + 'static,
    J: Jar + Clone + 'static,
>(
    http_client: &ReqwestClient,
    browser: &Browser,
    issuer: &str,
    client_id: &str,
    client_auth: Auth,
    dpop: D,
    scopes: impl IntoIterator<Item = impl Into<String>>,
    allowed_id_token_signed_response_algs: Option<std::collections::HashSet<String>>,
    jar: J,
) -> Result<(TokenResponse, FlowAuthorizer<Auth, D>), String> {
    let listener = bind_loopback(0)
        .await
        .map_err(|e| format!("failed to bind loopback: {e}"))?;
    let port = listener.local_addr().unwrap().port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    run_auth_code_flow_with_listener(
        http_client,
        browser,
        issuer,
        client_id,
        client_auth,
        dpop,
        scopes,
        &listener,
        &redirect_uri,
        allowed_id_token_signed_response_algs,
        jar,
    )
    .await
}

/// Drives a single authorization code flow using an existing listener.
///
/// Use this when running multiple modules within a conformance suite plan — bind
/// once, configure the plan with the resulting redirect URI, then call this for
/// each module. The listener is not consumed and can be reused across modules.
pub async fn run_auth_code_flow_with_listener<
    Auth: ClientAuthentication + Clone + 'static,
    D: AuthorizationServerDPoP + Clone + 'static,
    J: Jar + Clone + 'static,
>(
    http_client: &ReqwestClient,
    browser: &Browser,
    issuer: &str,
    client_id: &str,
    client_auth: Auth,
    dpop: D,
    scopes: impl IntoIterator<Item = impl Into<String>>,
    listener: &TcpListener,
    redirect_uri: &str,
    allowed_id_token_signed_response_algs: Option<std::collections::HashSet<String>>,
    jar: J,
) -> Result<(TokenResponse, FlowAuthorizer<Auth, D>), String> {
    let metadata = AuthorizationServerMetadata::oidc_fetch()
        .issuer(issuer)
        .http_client(http_client)
        .call()
        .await
        .map_err(|e| {
            use std::error::Error as _;
            let mut msg = format!("failed to get server metadata: {e}");
            let mut src = e.source();
            while let Some(s) = src {
                msg.push_str(&format!(": {s}"));
                src = s.source();
            }
            msg
        })?;

    let grant: AuthorizationCodeGrant<Auth, D, J> =
        AuthorizationCodeGrant::builder_from_metadata(&metadata)
            .ok_or("authorization server does not advertise an authorization endpoint")?
            .client_id(client_id)
            .client_auth(client_auth)
            .redirect_uri(redirect_uri)
            .dpop(dpop)
            .jar(jar)
            .jws_verifier_factory(Arc::new(
                JwksSource::builder()
                    .http_client(http_client.clone())
                    .build(),
            ))
            .maybe_allowed_id_token_signed_response_algs(allowed_id_token_signed_response_algs)
            .build()
            .await
            .map_err(|e| format!("failed to build grant: {e}"))?;

    // Build the token cache from the refresh grant (takes &self, so `grant` is still usable).
    // The cache's resource_server_dpop is derived from grant.dpop() at this point.
    let cache = InMemoryTokenCache::builder()
        .grant(grant.to_refresh_grant())
        .refresh_store(InMemoryRefreshTokenStore::default())
        .build();
    let authorizer = HttpAuthorizer::builder().cache(cache).build();

    let StartOutput {
        authorization_url,
        pending_state,
        ..
    } = grant
        .start(http_client, StartInput::scopes(scopes))
        .await
        .map_err(|e| format!("failed to start authorization: {e}"))?;

    println!("    auth URL: {authorization_url}");
    let browser_result = browser.navigate(authorization_url.to_string()).await;

    let token_response = tokio::select! {
        result = grant.complete_on_loopback(http_client, listener, &pending_state, None) => {
            println!("    loopback completed: {}", result.as_ref().map(|_| "ok").unwrap_or_else(|_e| "err"));
            result.map_err(|e| format!("failed to complete authorization: {e}"))
        }
        nav = browser_result => {
            match nav.unwrap() {
                Ok(r) => {
                    println!("    browser final URL: {} ({})", r.final_url, r.status);
                    Err(format!(
                        "browser reached {} (HTTP {}) without hitting our callback",
                        r.final_url, r.status,
                    ))
                }
                Err(e) => Err(format!("browser navigation failed: {e}")),
            }
        }
    }?;

    // Prime the cache so get_headers() immediately returns the fresh token.
    authorizer.prime(Arc::new(token_response.clone())).await;

    Ok((token_response, authorizer))
}
