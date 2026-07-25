pub mod api;
pub mod browser;

use std::sync::Arc;

use browser::Browser;
use bytes::Bytes;
use http::{Method, StatusCode, Uri};
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache, NoSource},
    core::{
        client_auth::ClientAuthentication,
        dpop::AuthorizationServerDPoP,
        http::{HttpClient, Idempotency},
        server_metadata::AuthorizationServerMetadata,
    },
    grant::{
        authorization_code::{AuthorizationCodeGrant, Jar, StartInput, StartOutput, bind_loopback},
        core::{OAuth2ExchangeGrant, TokenResponse},
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

/// Builds an HTTP client that accepts the conformance suite's self-signed certificate.
pub async fn build_http_client() -> ReqwestClient {
    ReqwestClient::builder()
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

/// Makes a GET request to `uri` using the authorizer, re-sending once on a 401.
///
/// Each call to `get_headers` generates a fresh DPoP proof (including the current nonce).
/// `process_response` records each response's `DPoP-Nonce` (and invalidates the token on an
/// `invalid_token` challenge), so the re-sent request carries the fix if there is one.
pub async fn call_resource_get(
    http_client: &ReqwestClient,
    authorizer: &HttpAuthorizer,
    uri: &Uri,
) {
    let mut retried = false;
    loop {
        let headers = match authorizer.get_headers(&Method::GET, uri).await {
            Ok(h) => h,
            Err(_) => break,
        };

        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.headers = headers;
        parts.uri = uri.clone();
        let request = http::Request::from_parts(parts, Bytes::new());

        let response = match http_client.execute(request, Idempotency::Idempotent).await {
            Ok(r) => r,
            Err(_) => break,
        };

        authorizer.process_response(uri, &response.headers);

        if response.status == StatusCode::UNAUTHORIZED && !retried {
            retried = true;
            continue;
        }
        break;
    }
}

/// Drives a single authorization code flow, binding a fresh loopback listener.
///
/// Convenience wrapper for standalone use where the redirect URI doesn't need
/// to match a pre-registered value.
#[allow(clippy::too_many_arguments)]
pub async fn run_auth_code_flow<
    Auth: ClientAuthentication + 'static,
    D: AuthorizationServerDPoP + 'static,
    J: Jar + 'static,
>(
    http_client: &ReqwestClient,
    browser: &Browser,
    issuer: &str,
    client_id: &str,
    client_auth: Auth,
    dpop: D,
    scopes: Vec<String>,
    jar: J,
) -> Result<(TokenResponse, HttpAuthorizer), String> {
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
        jar,
    )
    .await
}

/// Drives a single authorization code flow using an existing listener.
///
/// Use this when running multiple modules within a conformance suite plan — bind
/// once, configure the plan with the resulting redirect URI, then call this for
/// each module. The listener is not consumed and can be reused across modules.
#[allow(clippy::too_many_arguments)]
pub async fn run_auth_code_flow_with_listener<
    Auth: ClientAuthentication + 'static,
    D: AuthorizationServerDPoP + 'static,
    J: Jar + 'static,
>(
    http_client: &ReqwestClient,
    browser: &Browser,
    issuer: &str,
    client_id: &str,
    client_auth: Auth,
    dpop: D,
    scopes: Vec<String>,
    listener: &TcpListener,
    redirect_uri: &str,
    jar: J,
) -> Result<(TokenResponse, HttpAuthorizer), String> {
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

    let grant: AuthorizationCodeGrant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
        .map_err(|e| e.to_string())?
        .client_id(client_id)
        .http_client(http_client.clone())
        .client_auth(client_auth)
        .redirect_uri(redirect_uri)
        .dpop(dpop)
        .jar(jar)
        // jws_verifier_factory defaults to a JwksSource wired from http_client.
        .build()
        .await
        .map_err(|e| format!("failed to build grant: {e}"))?;

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
        .start(StartInput::scope(scopes))
        .await
        .map_err(|e| format!("failed to start authorization: {e}"))?;

    println!("    auth URL: {authorization_url}");
    let browser_result = browser.navigate(authorization_url.to_string()).await;

    let token_response = tokio::select! {
        result = grant.complete_on_loopback(listener, &pending_state, None) => {
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
    }?
    .token_response;

    // Prime the source so get_headers() immediately returns the fresh token.
    source
        .prime(token_response.clone())
        .await
        .map_err(|e| format!("failed to prime token source: {e}"))?;

    Ok((token_response, authorizer))
}
