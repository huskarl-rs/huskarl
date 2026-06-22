//! Loopback redirect server for the authorization code flow (RFC 8252 §7.3).
//!
//! A minimal HTTP server bound to a loopback address that receives the
//! authorization callback, for native apps and CLI tools that cannot host a
//! public redirect URI. `bind_loopback` creates the listener;
//! `AuthorizationCodeGrant::complete_on_loopback` drives the exchange.
//! Feature-gated behind `authorization-flow-loopback`.

use std::sync::Arc;

use snafu::{ResultExt as _, Snafu};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, TcpStream},
};
use url::Url;

use crate::{
    core::{Error, jwt::validator::ValidatedJwt},
    grant::{authorization_code::CompleteInput, core::TokenResponse},
    token::id_token::IdTokenClaims,
};

/// Errors that can occur when handling the authorization code callback with the loopback implementation.
///
/// The `OAuthError` variant is control flow for login UIs (e.g. the user
/// denied access); the rest carry the underlying failure.
#[derive(Debug, Snafu)]
pub enum LoopbackError {
    /// Invalid redirect URI in callback.
    #[snafu(display("Invalid redirect URI in callback state: {source}"))]
    InvalidRedirectUri {
        /// The underlying error.
        source: url::ParseError,
    },
    /// Failed to accept connection.
    #[snafu(display("Failed to accept connection: {source}"))]
    Accept {
        /// The underlying error.
        source: std::io::Error,
    },
    /// Failed to read request.
    #[snafu(display("Failed to read request: {source}"))]
    ReadRequest {
        /// The underlying error.
        source: std::io::Error,
    },
    /// Authorization server returned error.
    #[snafu(display("Authorization server returned error: {error}"))]
    OAuthError {
        /// The `error` field in the `OAuth2` error response.
        error: String,
        /// The `error_description` field in the `OAuth2` error response.
        error_description: Option<String>,
    },
    /// The callback parameters could not be parsed (malformed query, or a
    /// single-valued parameter that appeared more than once — RFC 6749 §3.1).
    #[snafu(display("Failed to parse callback parameters: {source}"))]
    InvalidCallbackParameters {
        /// The underlying parse error.
        source: crate::core::oauth_form::Error,
    },
    /// Missing required parameter.
    #[snafu(display("Missing required parameter: {param}"))]
    MissingParameter {
        /// The missing parameter name.
        param: &'static str,
    },
    /// Failed to complete authorization.
    #[snafu(display("Failed to complete authorization: {source}"))]
    Complete {
        /// The underlying error.
        source: Error,
    },
}

impl LoopbackError {
    /// If true, a failed callback handling attempt may succeed if retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            LoopbackError::InvalidRedirectUri { .. }
            | LoopbackError::OAuthError { .. }
            | LoopbackError::InvalidCallbackParameters { .. }
            | LoopbackError::MissingParameter { .. } => false,
            LoopbackError::Accept { .. } | LoopbackError::ReadRequest { .. } => true,
            LoopbackError::Complete { source } => source.is_retryable(),
        }
    }
}

/// Context passed to the success page renderer.
pub struct SuccessContext {
    /// The port the loopback server is listening on.
    pub port: u16,
}

/// Context passed to the error page renderer.
pub enum ErrorContext {
    /// The authorization server returned an OAuth error response (e.g. `access_denied`).
    OAuthError {
        /// The port the loopback server is listening on.
        port: u16,
        /// The OAuth error code.
        error: String,
        /// The optional human-readable error description.
        description: Option<String>,
    },
    /// Token exchange or another internal operation failed.
    InternalError {
        /// The port the loopback server is listening on.
        port: u16,
        /// A description of what went wrong.
        message: String,
    },
}

/// The response to show in the browser after the loopback callback.
#[derive(Clone)]
pub enum CallbackResponse {
    /// Serve an HTML page with the given body.
    Html(String),
    /// Redirect the browser to the given URL.
    Redirect(String),
}

/// Renders the response shown in the browser after the loopback callback.
#[derive(Clone)]
pub struct CallbackRenderer {
    /// Produces the response for a successful authorization.
    pub success: Arc<dyn Fn(&SuccessContext) -> CallbackResponse + Send + Sync>,
    /// Produces the response for a failed authorization.
    pub error: Arc<dyn Fn(&ErrorContext) -> CallbackResponse + Send + Sync>,
}

impl Default for CallbackRenderer {
    fn default() -> Self {
        Self {
            success: Arc::new(|_ctx| {
                CallbackResponse::Html(
                    "<html><body><h1>Authorization Successful!</h1>\
                     <p>You can close this window and return to the application.</p>\
                     </body></html>"
                        .to_owned(),
                )
            }),
            error: Arc::new(|ctx| {
                let message = match ctx {
                    ErrorContext::OAuthError {
                        error, description, ..
                    } => html_escape(description.as_deref().unwrap_or(error.as_str())),
                    ErrorContext::InternalError { message, .. } => html_escape(message),
                };
                CallbackResponse::Html(format!(
                    "<html><body><h1>Authorization Failed</h1><p>{message}</p></body></html>"
                ))
            }),
        }
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn error_query_string(ctx: &ErrorContext) -> String {
    #[derive(serde::Serialize)]
    struct Params<'a> {
        error: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_description: Option<&'a str>,
    }

    let params = match ctx {
        ErrorContext::OAuthError {
            error, description, ..
        } => Params {
            error,
            error_description: description.as_deref(),
        },
        ErrorContext::InternalError { message, .. } => Params {
            error: "server_error",
            error_description: Some(message),
        },
    };

    crate::core::oauth_form::to_string(&params).unwrap_or_default()
}

fn to_error_context(port: u16, err: &LoopbackError) -> ErrorContext {
    match err {
        LoopbackError::OAuthError {
            error,
            error_description,
        } => ErrorContext::OAuthError {
            port,
            error: error.clone(),
            description: error_description.clone(),
        },
        _ => ErrorContext::InternalError {
            port,
            message: err.to_string(),
        },
    }
}

/// Deadline for reading a single HTTP request once a connection is accepted.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Maximum bytes accepted for the request line plus headers.
const MAX_HEADER_BYTES: u64 = 16 * 1024;

/// Maximum `Content-Length` accepted for a `form_post` callback body.
///
/// Real callback bodies are a few hundred bytes; this bound prevents a local
/// peer from triggering a huge allocation via the `Content-Length` header.
const MAX_BODY_BYTES: u64 = 16 * 1024;

/// Deadline for the browser to follow the post-callback redirect and fetch
/// the result page (which is cosmetic).
const RESULT_PAGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Waits for the authorization callback on `listener`, completes the flow
/// via `complete`, and serves a result page to the browser.
pub async fn complete_on_loopback_oidc(
    listener: &TcpListener,
    redirect_uri: &str,
    renderer: Option<CallbackRenderer>,
    complete: impl AsyncFnOnce(
        CompleteInput,
    )
        -> Result<(TokenResponse, Option<ValidatedJwt<IdTokenClaims>>), Error>,
) -> Result<(TokenResponse, Option<ValidatedJwt<IdTokenClaims>>), LoopbackError> {
    complete_on_loopback_oidc_with_timeouts(
        listener,
        redirect_uri,
        renderer,
        READ_TIMEOUT,
        RESULT_PAGE_TIMEOUT,
        complete,
    )
    .await
}

async fn complete_on_loopback_oidc_with_timeouts(
    listener: &TcpListener,
    redirect_uri: &str,
    renderer: Option<CallbackRenderer>,
    read_timeout: std::time::Duration,
    result_page_timeout: std::time::Duration,
    complete: impl AsyncFnOnce(
        CompleteInput,
    )
        -> Result<(TokenResponse, Option<ValidatedJwt<IdTokenClaims>>), Error>,
) -> Result<(TokenResponse, Option<ValidatedJwt<IdTokenClaims>>), LoopbackError> {
    let port = listener.local_addr().map_or(0, |a| a.port());

    let expected_path = Url::parse(redirect_uri)
        .context(InvalidRedirectUriSnafu)?
        .path()
        .to_owned();

    let renderer = renderer.unwrap_or_default();

    let result = loop {
        let (mut stream, _) = listener.accept().await.context(AcceptSnafu)?;
        let path = read_request_path(&mut stream, read_timeout)
            .await
            .context(ReadRequestSnafu)?;

        let Some(path) = path else {
            let _ = send_error_response(&mut stream, 400, "Bad Request").await;
            continue;
        };

        // Only accept callbacks on the expected redirect URI path.
        let request_path = path.split('?').next().unwrap_or(&path);
        if request_path != expected_path {
            let _ = send_error_response(&mut stream, 404, "Not Found").await;
            continue;
        }

        let complete_input = match parse_callback_params(&path) {
            Ok(input) => input,
            Err(e) => {
                let _ = send_redirect(&mut stream, "/failure").await;
                break Err(e);
            }
        };
        let result = complete(complete_input).await.context(CompleteSnafu);

        // Redirect to a clean URL so the authorization code and state
        // are not left in the browser's address bar or history.
        let redirect_path = if result.is_ok() {
            "/success"
        } else {
            "/failure"
        };
        let _ = send_redirect(&mut stream, redirect_path).await;

        break result;
    };

    // Serve the result page on the clean URL.
    let serve_result_page = async {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let Ok(path) = read_request_path(&mut stream, read_timeout).await else {
                continue;
            };

            match path.as_deref() {
                Some("/success") => {
                    let response = (renderer.success)(&SuccessContext { port });
                    let _ = send_callback_response(&mut stream, response, "").await;
                    break;
                }
                Some("/failure") => {
                    if let Err(ref err) = result {
                        let ctx = to_error_context(port, err);
                        let query = error_query_string(&ctx);
                        let response = (renderer.error)(&ctx);
                        let _ = send_callback_response(&mut stream, response, &query).await;
                    }
                    break;
                }
                _ => {
                    let _ = send_error_response(&mut stream, 404, "Not Found").await;
                }
            }
        }
    };
    let _ = tokio::time::timeout(result_page_timeout, serve_result_page).await;

    result
}

/// Reads one HTTP request and returns its path (with the `form_post` body
/// folded in as a query string).
///
/// Returns `Ok(None)` for anything malformed or abusive — a stalled
/// connection, an oversized request, a truncated body — so the caller can
/// reply 400 and keep waiting for the real callback. `Err` is reserved for
/// genuine I/O failures.
async fn read_request_path(
    stream: &mut TcpStream,
    read_timeout: std::time::Duration,
) -> Result<Option<String>, std::io::Error> {
    match tokio::time::timeout(read_timeout, read_request_path_inner(stream)).await {
        Ok(result) => result,
        Err(_elapsed) => Ok(None),
    }
}

async fn read_request_path_inner(stream: &mut TcpStream) -> Result<Option<String>, std::io::Error> {
    // Bound the total bytes read for one request so a local peer cannot grow
    // memory without bound. Header overrun is detected by the cumulative
    // count below; hitting the outer cap mid-line surfaces as a line without
    // a trailing newline.
    let mut reader = BufReader::new((&mut *stream).take(MAX_HEADER_BYTES + MAX_BODY_BYTES));
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    if !request_line.ends_with('\n') {
        return Ok(None);
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(None);
    }
    let method = parts[0];
    let path = parts[1].to_owned();

    // Read headers, collecting Content-Length for POST bodies.
    let mut header_bytes = request_line.len() as u64;
    let mut content_length: Option<u64> = None;
    let mut header_line = String::new();
    loop {
        header_line.clear();
        let n = reader.read_line(&mut header_line).await?;
        header_bytes += n as u64;
        if header_bytes > MAX_HEADER_BYTES {
            return Ok(None);
        }
        if header_line.trim().is_empty() {
            break;
        }
        let lower = header_line.to_ascii_lowercase();
        if let Some(val) = lower.strip_prefix("content-length:") {
            content_length = val.trim().parse().ok();
        }
    }

    // For POST requests (response_mode=form_post), the callback parameters
    // arrive as a form-encoded body rather than query parameters. Read the
    // body and append it as a query string so parse_callback_params works
    // without modification.
    if method.eq_ignore_ascii_case("POST")
        && let Some(len) = content_length
    {
        if len > MAX_BODY_BYTES {
            return Ok(None);
        }
        #[expect(clippy::cast_possible_truncation, reason = "len <= MAX_BODY_BYTES")]
        let mut body = vec![0u8; len as usize];
        match reader.read_exact(&mut body).await {
            Ok(_) => {}
            // The peer closed (or the read cap cut it off) before sending the
            // advertised body length.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let body_str = String::from_utf8(body)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let path_base = path.split('?').next().unwrap_or(&path);
        return Ok(Some(format!("{path_base}?{body_str}")));
    }

    Ok(Some(path))
}

fn parse_callback_params(path_and_query: &str) -> Result<CompleteInput, LoopbackError> {
    /// The authorization-response parameters delivered to the redirect URI
    /// (RFC 6749 §4.1.2 / §4.1.2.1, plus the RFC 9207 `iss`). Unknown
    /// parameters are ignored; a repeated single-valued parameter is rejected.
    #[derive(serde::Deserialize)]
    struct CallbackParams {
        code: Option<String>,
        state: Option<String>,
        error: Option<String>,
        error_description: Option<String>,
        iss: Option<String>,
    }

    // The callback parameters are the query component. For `response_mode=form_post`
    // the body is folded in as a query string upstream, so this handles both.
    let query = path_and_query.split_once('?').map_or("", |(_, q)| q);

    let params: CallbackParams =
        crate::core::oauth_form::from_str(query).context(InvalidCallbackParametersSnafu)?;

    // An OAuth error response takes precedence (RFC 6749 §4.1.2.1).
    if let Some(error) = params.error {
        return Err(LoopbackError::OAuthError {
            error,
            error_description: params.error_description,
        });
    }

    let code = params
        .code
        .ok_or(LoopbackError::MissingParameter { param: "code" })?;
    let state = params
        .state
        .ok_or(LoopbackError::MissingParameter { param: "state" })?;

    Ok(CompleteInput::builder()
        .code(code)
        .state(state)
        .maybe_iss(params.iss)
        .build())
}

async fn send_redirect(stream: &mut TcpStream, location: &str) -> Result<(), std::io::Error> {
    let response = format!(
        "HTTP/1.1 303 See Other\r\n\
         Location: {location}\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n"
    );

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn send_callback_response(
    stream: &mut TcpStream,
    response: CallbackResponse,
    query: &str,
) -> Result<(), std::io::Error> {
    match response {
        CallbackResponse::Html(body) => send_html_response(stream, 200, &body).await,
        CallbackResponse::Redirect(base_url) => {
            let url = if query.is_empty() {
                base_url
            } else {
                format!("{base_url}?{query}")
            };
            send_redirect(stream, &url).await
        }
    }
}

async fn send_html_response(
    stream: &mut TcpStream,
    status: u16,
    body: &str,
) -> Result<(), std::io::Error> {
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        status,
        get_status_text(status),
        body.len(),
        body
    );

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn send_error_response(
    stream: &mut TcpStream,
    status: u16,
    message: &str,
) -> Result<(), std::io::Error> {
    let body = format!("<html><body><h1>Error {status}</h1><p>{message}</p></body></html>");
    send_html_response(stream, status, &body).await
}

fn get_status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

/// Attempts to bind to a local port, following recommendations from RFC 8252.
///
/// In particular, an implementation should not assume that `localhost` resolves,
/// and should also not assume the type of IP network (IPv4/IPv6) that is available.
///
/// If the provided port is `0`, then the port will be chosen from available
/// ports on the machine. This is only usable with authorization servers which
/// allow the port value to vary for loopback redirect URLs.
///
/// Only one address family is bound (IPv4 preferred, IPv6 as fallback).
/// Register the redirect URI with a literal loopback address (`127.0.0.1` or
/// `[::1]`) rather than `localhost`, per RFC 8252 §7.3 — a `localhost`
/// redirect may resolve to the family this listener did not bind, in which
/// case the callback never arrives.
///
/// # Errors
///
/// Returns an error if the function was unable to bind to the requested port
/// on either IPv4 or IPv6 localhost.
pub async fn bind_loopback(port: u16) -> std::io::Result<TcpListener> {
    // Try IPv4 first (more commonly supported), fall back to IPv6
    let listener = match TcpListener::bind(format!("127.0.0.1:{port}")).await {
        Ok(l) => l,
        Err(_) => TcpListener::bind(format!("[::1]:{port}")).await?,
    };

    Ok(listener)
}

#[cfg(test)]
#[cfg(any(
    not(target_family = "wasm"),
    all(target_arch = "wasm32", target_os = "wasi", target_env = "p2")
))]
mod tests {
    use tokio::net::TcpStream;

    use super::*;
    use crate::token::{AccessToken, id_token::IdTokenClaims};

    fn ok_token_response() -> (TokenResponse, Option<ValidatedJwt<IdTokenClaims>>) {
        (
            crate::grant::core::token_response::RawTokenResponse::builder()
                .access_token(crate::core::secrets::SecretString::new("test-token"))
                .token_type("Bearer")
                .build()
                .into_token_response(None, crate::core::platform::SystemTime::now())
                .unwrap(),
            None,
        )
    }

    async fn send_http_request(addr: std::net::SocketAddr, request_line: &str) {
        let raw = format!("{request_line}\r\nHost: localhost\r\n\r\n");
        send_raw_request(addr, &raw).await;
    }

    /// Sends a raw HTTP request and returns the start of the response.
    async fn send_raw_request(addr: std::net::SocketAddr, raw: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(raw.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        // Read the full response to avoid connection reset errors
        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
            .await
            .unwrap_or(0);
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[tokio::test]
    async fn test_successful_callback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback_oidc(
                &listener,
                "http://127.0.0.1/callback",
                None,
                async |_input| Ok(ok_token_response()),
            )
            .await
        });

        // Send the callback with code and state
        send_http_request(addr, "GET /callback?code=abc&state=xyz HTTP/1.1").await;
        // Send the success follow-up
        send_http_request(addr, "GET /success HTTP/1.1").await;

        let (token_response, id_token) = handle.await.unwrap().unwrap();

        assert!(matches!(
            token_response.access_token(),
            AccessToken::Bearer(_)
        ));
        assert_eq!(
            token_response.access_token().token().expose_secret(),
            "test-token"
        );
        assert!(id_token.is_none());
    }

    #[tokio::test]
    async fn test_callback_with_iss() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback_oidc(
                &listener,
                "http://127.0.0.1/callback",
                None,
                async |input| {
                    assert_eq!(input.iss.as_deref(), Some("https://issuer.example.com"));
                    Ok(ok_token_response())
                },
            )
            .await
        });

        send_http_request(
            addr,
            "GET /callback?code=abc&state=xyz&iss=https%3A%2F%2Fissuer.example.com HTTP/1.1",
        )
        .await;
        send_http_request(addr, "GET /success HTTP/1.1").await;

        let (token_response, _) = handle.await.unwrap().unwrap();
        assert!(matches!(
            token_response.access_token(),
            AccessToken::Bearer(_)
        ));
    }

    #[tokio::test]
    async fn test_oauth_error_callback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback_oidc(&listener, "http://127.0.0.1/callback", None, async |_| {
                Ok(ok_token_response())
            })
            .await
        });

        send_http_request(
            addr,
            "GET /callback?error=access_denied&error_description=user+denied HTTP/1.1",
        )
        .await;
        // Send the failure follow-up so the server can render the error page
        send_http_request(addr, "GET /failure HTTP/1.1").await;

        let err = handle.await.unwrap().unwrap_err();
        assert!(
            matches!(&err, LoopbackError::OAuthError { error, .. } if error == "access_denied")
        );
    }

    #[tokio::test]
    async fn test_missing_code() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback_oidc(&listener, "http://127.0.0.1/callback", None, async |_| {
                Ok(ok_token_response())
            })
            .await
        });

        send_http_request(addr, "GET /callback?state=xyz HTTP/1.1").await;
        // Send the failure follow-up so the server can render the error page
        send_http_request(addr, "GET /failure HTTP/1.1").await;

        let err = handle.await.unwrap().unwrap_err();
        assert!(matches!(
            &err,
            LoopbackError::MissingParameter { param: "code" }
        ));
    }

    #[tokio::test]
    async fn test_duplicate_parameter_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback_oidc(&listener, "http://127.0.0.1/callback", None, async |_| {
                Ok(ok_token_response())
            })
            .await
        });

        // A repeated single-valued parameter is rejected (RFC 6749 §3.1),
        // rather than silently taking one value.
        send_http_request(addr, "GET /callback?code=abc&state=xyz&state=zzz HTTP/1.1").await;
        send_http_request(addr, "GET /failure HTTP/1.1").await;

        let err = handle.await.unwrap().unwrap_err();
        assert!(matches!(
            &err,
            LoopbackError::InvalidCallbackParameters { .. }
        ));
    }

    #[tokio::test]
    async fn test_wrong_path_ignored() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback_oidc(&listener, "http://127.0.0.1/callback", None, async |_| {
                Ok(ok_token_response())
            })
            .await
        });

        // Wrong path — gets 404, loopback continues waiting
        send_http_request(addr, "GET /other HTTP/1.1").await;
        // Correct callback
        send_http_request(addr, "GET /callback?code=abc&state=xyz HTTP/1.1").await;
        // Follow-up success page
        send_http_request(addr, "GET /success HTTP/1.1").await;

        let (token_response, _) = handle.await.unwrap().unwrap();
        assert_eq!(
            token_response.access_token().token().expose_secret(),
            "test-token"
        );
    }

    #[tokio::test]
    async fn test_form_post_callback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback_oidc(
                &listener,
                "http://127.0.0.1/callback",
                None,
                async |input| {
                    assert_eq!(input.code, "abc");
                    assert_eq!(input.state, "xyz");
                    Ok(ok_token_response())
                },
            )
            .await
        });

        let body = "code=abc&state=xyz";
        let raw = format!(
            "POST /callback HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {body}",
            body.len()
        );
        send_raw_request(addr, &raw).await;
        send_http_request(addr, "GET /success HTTP/1.1").await;

        let (token_response, _) = handle.await.unwrap().unwrap();
        assert_eq!(
            token_response.access_token().token().expose_secret(),
            "test-token"
        );
    }

    #[tokio::test]
    async fn test_silent_connection_does_not_block_flow() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback_oidc_with_timeouts(
                &listener,
                "http://127.0.0.1/callback",
                None,
                std::time::Duration::from_millis(100),
                RESULT_PAGE_TIMEOUT,
                async |_input| Ok(ok_token_response()),
            )
            .await
        });

        // A connection that opens but never sends a request (port scanner,
        // browser preconnect) must time out instead of hanging the flow.
        let silent = TcpStream::connect(addr).await.unwrap();

        send_http_request(addr, "GET /callback?code=abc&state=xyz HTTP/1.1").await;
        send_http_request(addr, "GET /success HTTP/1.1").await;

        let (token_response, _) = handle.await.unwrap().unwrap();
        assert_eq!(
            token_response.access_token().token().expose_secret(),
            "test-token"
        );
        drop(silent);
    }

    #[tokio::test]
    async fn test_result_returned_when_browser_never_follows_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback_oidc_with_timeouts(
                &listener,
                "http://127.0.0.1/callback",
                None,
                READ_TIMEOUT,
                std::time::Duration::from_millis(100),
                async |_input| Ok(ok_token_response()),
            )
            .await
        });

        // The callback arrives and the exchange succeeds, but the browser
        // never follows the /success redirect (tab closed mid-flow). The
        // completed result must still be returned after the bounded wait.
        send_http_request(addr, "GET /callback?code=abc&state=xyz HTTP/1.1").await;

        let (token_response, _) = handle.await.unwrap().unwrap();
        assert_eq!(
            token_response.access_token().token().expose_secret(),
            "test-token"
        );
    }

    #[tokio::test]
    async fn test_oversized_headers_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback_oidc(&listener, "http://127.0.0.1/callback", None, async |_| {
                Ok(ok_token_response())
            })
            .await
        });

        // Headers beyond the cap get a 400 and the flow keeps waiting.
        let filler = "a".repeat(20 * 1024);
        let raw =
            format!("GET /callback?code=evil&state=evil HTTP/1.1\r\nX-Filler: {filler}\r\n\r\n");
        let response = send_raw_request(addr, &raw).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");

        send_http_request(addr, "GET /callback?code=abc&state=xyz HTTP/1.1").await;
        send_http_request(addr, "GET /success HTTP/1.1").await;

        let (token_response, _) = handle.await.unwrap().unwrap();
        assert_eq!(
            token_response.access_token().token().expose_secret(),
            "test-token"
        );
    }

    #[tokio::test]
    async fn test_huge_content_length_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback_oidc(&listener, "http://127.0.0.1/callback", None, async |_| {
                Ok(ok_token_response())
            })
            .await
        });

        // An attacker-sized Content-Length must be rejected before any
        // allocation, not used as a buffer size.
        let raw = "POST /callback HTTP/1.1\r\n\
                   Host: localhost\r\n\
                   Content-Type: application/x-www-form-urlencoded\r\n\
                   Content-Length: 4000000000\r\n\
                   \r\n";
        let response = send_raw_request(addr, raw).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");

        send_http_request(addr, "GET /callback?code=abc&state=xyz HTTP/1.1").await;
        send_http_request(addr, "GET /success HTTP/1.1").await;

        let (token_response, _) = handle.await.unwrap().unwrap();
        assert_eq!(
            token_response.access_token().token().expose_secret(),
            "test-token"
        );
    }

    #[tokio::test]
    async fn test_bind_loopback() {
        let listener = bind_loopback(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert_ne!(addr.port(), 0);
    }
}
