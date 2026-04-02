use std::sync::Arc;

use serde::Deserialize;
use snafu::{ResultExt as _, Snafu};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, TcpStream},
};
use url::Url;

use crate::{
    core::{jwt::validator::ValidatedJwt, platform::MaybeSendSync},
    grant::{authorization_code::CompleteInput, core::TokenResponse},
    token::id_token::IdTokenClaims,
};

/// Errors that can occur when handling the authorization code callback with the loopback implementation.
#[derive(Debug, Snafu)]
pub enum LoopbackError<CompleteErr: crate::core::Error> {
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
        source: CompleteErr,
    },
}

impl<CompleteErr: crate::core::Error + 'static> crate::core::Error for LoopbackError<CompleteErr> {
    fn is_retryable(&self) -> bool {
        match self {
            LoopbackError::InvalidRedirectUri { .. }
            | LoopbackError::OAuthError { .. }
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

    serde_html_form::to_string(&params).unwrap_or_default()
}

fn to_error_context<E: crate::core::Error>(port: u16, err: &LoopbackError<E>) -> ErrorContext {
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

pub async fn complete_on_loopback_oidc<
    E: crate::core::Error + 'static,
    Extra: Clone + for<'de> Deserialize<'de> + MaybeSendSync + 'static,
>(
    listener: &TcpListener,
    redirect_uri: &str,
    renderer: Option<CallbackRenderer>,
    complete: impl AsyncFnOnce(
        CompleteInput,
    )
        -> Result<(TokenResponse, Option<ValidatedJwt<IdTokenClaims<Extra>>>), E>,
) -> Result<(TokenResponse, Option<ValidatedJwt<IdTokenClaims<Extra>>>), LoopbackError<E>> {
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);

    let expected_path = Url::parse(redirect_uri)
        .context(InvalidRedirectUriSnafu)?
        .path()
        .to_owned();

    let renderer = renderer.unwrap_or_default();

    // Phase 1: Accept the callback with query parameters, parse them,
    // perform the token exchange, and redirect to a clean URL.
    let result = loop {
        let (mut stream, _) = listener.accept().await.context(AcceptSnafu)?;
        let path = read_request_path(&mut stream)
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

        let complete_input = match parse_callback_params::<E>(&path) {
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

    // Phase 2: Serve the result page on the clean URL.
    // Accept connections in a loop to handle any stray requests
    // (e.g. favicon) before the redirect arrives.
    loop {
        let (mut stream, _) = listener.accept().await.context(AcceptSnafu)?;
        let path = read_request_path(&mut stream)
            .await
            .context(ReadRequestSnafu)?;

        match path.as_deref() {
            Some("/success") => {
                let response = (renderer.success)(&SuccessContext { port });
                let _ = send_callback_response(&mut stream, response, "").await;
                return result;
            }
            Some("/failure") => {
                if let Err(ref err) = result {
                    let ctx = to_error_context(port, err);
                    let query = error_query_string(&ctx);
                    let response = (renderer.error)(&ctx);
                    let _ = send_callback_response(&mut stream, response, &query).await;
                }
                return result;
            }
            _ => {
                let _ = send_error_response(&mut stream, 404, "Not Found").await;
            }
        }
    }
}

async fn read_request_path(stream: &mut TcpStream) -> Result<Option<String>, std::io::Error> {
    let mut reader = BufReader::new(&mut *stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    // Drain remaining headers until empty line
    let mut header_line = String::new();
    loop {
        header_line.clear();
        reader.read_line(&mut header_line).await?;
        if header_line.trim().is_empty() {
            break;
        }
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(None);
    }

    Ok(Some(parts[1].to_owned()))
}

fn parse_callback_params<E: crate::core::Error + 'static>(
    path_and_query: &str,
) -> Result<CompleteInput, LoopbackError<E>> {
    // Parse the URL to extract query parameters
    // This parse shouldn't fail since we control the format, but we handle it gracefully
    let url = Url::parse(&format!("http://localhost{path_and_query}"))
        .expect("localhost URL with path should always parse");

    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    let mut error: Option<String> = None;
    let mut error_description: Option<String> = None;
    let mut iss: Option<String> = None;

    // Extract query parameters using the url crate
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.to_string()),
            "state" => state = Some(value.to_string()),
            "error" => error = Some(value.to_string()),
            "iss" => iss = Some(value.to_string()),
            "error_description" => error_description = Some(value.to_string()),
            _ => {} // Ignore other parameters
        }
    }

    // Check for OAuth error response first
    if let Some(error) = error {
        return Err(LoopbackError::OAuthError {
            error,
            error_description,
        });
    }

    let code = code.ok_or(LoopbackError::MissingParameter { param: "code" })?;
    let state = state.ok_or(LoopbackError::MissingParameter { param: "state" })?;

    Ok(CompleteInput::builder()
        .code(code)
        .state(state)
        .maybe_iss(iss)
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

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use super::*;
    use crate::token::{AccessToken, id_token::IdTokenClaims};
    use tokio::net::TcpStream;

    #[derive(Debug, snafu::Snafu)]
    #[snafu(display("mock error"))]
    struct MockError;

    impl crate::core::Error for MockError {
        fn is_retryable(&self) -> bool {
            false
        }
    }

    fn ok_token_response() -> (TokenResponse, Option<ValidatedJwt<IdTokenClaims>>) {
        (
            crate::grant::core::token_response::RawTokenResponse::builder()
                .access_token(crate::core::secrets::SecretString::new(
                    "test-token".to_string(),
                ))
                .token_type("Bearer")
                .build()
                .into_token_response(None, crate::core::platform::SystemTime::now())
                .unwrap(),
            None,
        )
    }

    async fn send_http_request(addr: std::net::SocketAddr, request_line: &str) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let raw = format!("{request_line}\r\nHost: localhost\r\n\r\n");
        stream.write_all(raw.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        // Read the full response to avoid connection reset errors
        let mut buf = vec![0u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
    }

    #[tokio::test]
    async fn test_successful_callback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback_oidc::<MockError, _>(
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
            complete_on_loopback_oidc::<MockError, _>(
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
            complete_on_loopback_oidc::<MockError, _>(
                &listener,
                "http://127.0.0.1/callback",
                None,
                async |_| Ok(ok_token_response()),
            )
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
            complete_on_loopback_oidc::<MockError, _>(
                &listener,
                "http://127.0.0.1/callback",
                None,
                async |_| Ok(ok_token_response()),
            )
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
    async fn test_wrong_path_ignored() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback_oidc::<MockError, _>(
                &listener,
                "http://127.0.0.1/callback",
                None,
                async |_| Ok(ok_token_response()),
            )
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
    async fn test_bind_loopback() {
        let listener = bind_loopback(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert_ne!(addr.port(), 0);
    }
}
