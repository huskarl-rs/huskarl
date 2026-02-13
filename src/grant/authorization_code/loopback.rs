use snafu::{ResultExt as _, Snafu};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, TcpStream},
};
use url::Url;

use crate::grant::{authorization_code::CompleteInput, core::TokenResponse};

#[derive(Debug, Snafu)]
pub enum LoopbackError<CompleteErr: crate::Error> {
    #[snafu(display("Invalid redirect URI in callback state: {source}"))]
    InvalidRedirectUri { source: url::ParseError },
    #[snafu(display("Failed to accept connection: {source}"))]
    Accept { source: std::io::Error },
    #[snafu(display("Failed to read request: {source}"))]
    ReadRequest { source: std::io::Error },
    #[snafu(display("Authorization server returned error: {error}"))]
    OAuthError {
        error: String,
        error_description: Option<String>,
    },
    #[snafu(display("Missing required parameter: {param}"))]
    MissingParameter { param: &'static str },
    #[snafu(display("Failed to complete authorization: {source}"))]
    Complete { source: CompleteErr },
}

impl<CompleteErr: crate::Error + 'static> crate::Error for LoopbackError<CompleteErr> {
    fn is_retryable(&self) -> bool {
        match self {
            LoopbackError::InvalidRedirectUri { .. } => false,
            LoopbackError::Accept { .. } => true,
            LoopbackError::ReadRequest { .. } => true,
            LoopbackError::OAuthError { .. } => false,
            LoopbackError::MissingParameter { .. } => false,
            LoopbackError::Complete { source } => source.is_retryable(),
        }
    }
}

pub async fn complete_on_loopback<E: crate::Error + 'static>(
    listener: &TcpListener,
    redirect_uri: &str,
    complete: impl AsyncFnOnce(CompleteInput) -> Result<TokenResponse, E>,
) -> Result<TokenResponse, LoopbackError<E>> {
    let expected_path = Url::parse(redirect_uri)
        .context(InvalidRedirectUriSnafu)?
        .path()
        .to_owned();

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

        let complete_input = parse_callback_params::<E>(&path)?;
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
                let _ = send_success_response(&mut stream).await;
                return result;
            }
            Some("/failure") => {
                let _ = send_error_response(&mut stream, 500, "Token exchange failed").await;
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

fn parse_callback_params<E: crate::Error + 'static>(
    path_and_query: &str,
) -> Result<CompleteInput, LoopbackError<E>> {
    // Parse the URL to extract query parameters
    // This parse shouldn't fail since we control the format, but we handle it gracefully
    let url = Url::parse(&format!("http://localhost{}", path_and_query))
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

async fn send_success_response(stream: &mut TcpStream) -> Result<(), std::io::Error> {
    let body = "<html><body><h1>Authorization Successful!</h1><p>You can close this window and return to the application.</p></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
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
    let body = format!(
        "<html><body><h1>Error {}</h1><p>{}</p></body></html>",
        status, message
    );
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
pub async fn bind_loopback(port: u16) -> std::io::Result<TcpListener> {
    // Try IPv4 first (more commonly supported), fall back to IPv6
    let listener = match TcpListener::bind(format!("127.0.0.1:{port}")).await {
        Ok(l) => l,
        Err(_) => TcpListener::bind(format!("[::1]:{port}")).await?,
    };

    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;
    use tokio::net::TcpStream;

    #[derive(Debug, snafu::Snafu)]
    #[snafu(display("mock error"))]
    struct MockError;

    impl crate::Error for MockError {
        fn is_retryable(&self) -> bool {
            false
        }
    }

    fn ok_token_response() -> TokenResponse {
        TokenResponse::builder()
            .access_token("test-token")
            .token_type("Bearer")
            .build()
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
            complete_on_loopback::<MockError>(
                &listener,
                "http://127.0.0.1/callback",
                async |_input| Ok(ok_token_response()),
            )
            .await
        });

        // Send the callback with code and state
        send_http_request(addr, "GET /callback?code=abc&state=xyz HTTP/1.1").await;
        // Send the success follow-up
        send_http_request(addr, "GET /success HTTP/1.1").await;

        let result = handle.await.unwrap().unwrap();
        assert_eq!(result.token_type, "Bearer");
        assert_eq!(result.access_token.expose_secret(), "test-token");
    }

    #[tokio::test]
    async fn test_callback_with_iss() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback::<MockError>(
                &listener,
                "http://127.0.0.1/callback",
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

        let result = handle.await.unwrap().unwrap();
        assert_eq!(result.token_type, "Bearer");
    }

    #[tokio::test]
    async fn test_oauth_error_callback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            complete_on_loopback::<MockError>(&listener, "http://127.0.0.1/callback", async |_| {
                Ok(ok_token_response())
            })
            .await
        });

        send_http_request(
            addr,
            "GET /callback?error=access_denied&error_description=user+denied HTTP/1.1",
        )
        .await;

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
            complete_on_loopback::<MockError>(&listener, "http://127.0.0.1/callback", async |_| {
                Ok(ok_token_response())
            })
            .await
        });

        send_http_request(addr, "GET /callback?state=xyz HTTP/1.1").await;

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
            complete_on_loopback::<MockError>(&listener, "http://127.0.0.1/callback", async |_| {
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

        let result = handle.await.unwrap().unwrap();
        assert_eq!(result.access_token.expose_secret(), "test-token");
    }

    #[tokio::test]
    async fn test_bind_loopback() {
        let listener = bind_loopback(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert_ne!(addr.port(), 0);
    }
}
