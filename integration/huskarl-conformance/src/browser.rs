use tokio::sync::{mpsc, oneshot};

use crate::api::Error;

/// The result of a browser navigation request.
pub struct NavigationResult {
    pub status: u16,
    pub final_url: String,
}

struct Pending {
    url: String,
    callback: String,
    tx: oneshot::Sender<Result<NavigationResult, Error>>,
}

/// Parse the suite's response form without executing JavaScript. Preserve field
/// order and duplicate names so malformed protocol responses reach the client.
fn response_form(
    html: &str,
    page: &reqwest::Url,
    callback: &str,
) -> Result<Option<Vec<(String, String)>>, Error> {
    let document = scraper::Html::parse_document(html);
    let forms = scraper::Selector::parse("form").expect("static selector");
    let inputs = scraper::Selector::parse("input").expect("static selector");
    let mut forms = document.select(&forms);
    let Some(form) = forms.next() else {
        return Ok(None);
    };
    if forms.next().is_some() {
        return Err("authorization page contains multiple forms".into());
    }
    if !form
        .value()
        .attr("method")
        .is_some_and(|m| m.eq_ignore_ascii_case("post"))
    {
        return Err("authorization response form must use POST".into());
    }
    let action = page
        .join(form.value().attr("action").unwrap_or(""))
        .map_err(|_| "invalid authorization response form action")?;
    if action.as_str() != callback {
        return Err("authorization response form does not target the registered callback".into());
    }
    if form
        .value()
        .attr("enctype")
        .is_some_and(|v| !v.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
    {
        return Err("unsupported authorization response form encoding".into());
    }
    let fields = form
        .select(&inputs)
        .filter_map(|input| {
            let input = input.value();
            if input.attr("disabled").is_some()
                || !input
                    .attr("type")
                    .is_some_and(|v| v.eq_ignore_ascii_case("hidden"))
            {
                return None;
            }
            Some((
                input.attr("name")?.to_owned(),
                input.attr("value").unwrap_or("").to_owned(),
            ))
        })
        .collect();
    Ok(Some(fields))
}

async fn navigate(
    client: &reqwest::Client,
    url: &str,
    callback: &str,
) -> Result<NavigationResult, Error> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(reqwest::Error::without_url)?;
    let result = NavigationResult {
        status: response.status().as_u16(),
        final_url: response.url().to_string(),
    };
    let is_html = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("text/html"))
        });
    if !response.status().is_success() || !is_html || response.url().as_str() == callback {
        return Ok(result);
    }
    let page = response.url().clone();
    let html = response.text().await.map_err(reqwest::Error::without_url)?;
    let Some(fields) = response_form(&html, &page, callback)? else {
        return Ok(result);
    };
    let response = client
        .post(callback)
        .form(&fields)
        .send()
        .await
        .map_err(reqwest::Error::without_url)?;
    Ok(NavigationResult {
        status: response.status().as_u16(),
        final_url: response.url().to_string(),
    })
}

/// A suite browser that follows redirects and submits hidden response forms.
/// Uses a reqwest client with a cookie jar; does not execute JavaScript.
///
/// Runs in a background tokio task. Send navigation requests via [`Browser::navigate`]
/// and await the result on the returned receiver.
#[derive(Clone)]
pub struct Browser {
    tx: mpsc::Sender<Pending>,
}

impl Browser {
    pub fn spawn(client: reqwest::Client) -> Self {
        let (tx, mut rx) = mpsc::channel::<Pending>(4);
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                let result = navigate(&client, &req.url, &req.callback).await;
                let _ = req.tx.send(result);
            }
        });
        Self { tx }
    }

    /// Sends a navigation request and returns a receiver for the result.
    ///
    /// Follows redirects and submits a response form only to `callback`, the
    /// registered redirect URI. The receiver resolves after navigation, including
    /// any form submission to the loopback listener, completes.
    pub async fn navigate(
        &self,
        url: String,
        callback: String,
    ) -> oneshot::Receiver<Result<NavigationResult, Error>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Pending { url, callback, tx })
            .await
            .expect("browser task has stopped");
        rx
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn form_preserves_entities_duplicates_and_missing_protocol_fields() {
        let page = reqwest::Url::parse("http://localhost/authorize").unwrap();
        let fields = response_form(
            r#"<FORM method="POST" action="/callback">
                <input type="hidden" name="error" value="access_denied">
                <input type="hidden" name="state" value="a&amp;b&#43;&quot;">
                <input type="hidden" name="state" value="second">
                <input type="hidden" name="empty">
                <input type="hidden" name="disabled" value="x" disabled>
                <input type="submit" name="submit" value="Continue">
            </FORM>"#,
            &page,
            "http://localhost/callback",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            fields,
            vec![
                ("error".into(), "access_denied".into()),
                ("state".into(), "a&b+\"".into()),
                ("state".into(), "second".into()),
                ("empty".into(), "".into()),
            ]
        );
        assert_eq!(
            response_form("<p>Not a form</p>", &page, "http://localhost/callback").unwrap(),
            None
        );
    }

    #[test]
    fn rejects_unsupported_or_ambiguous_forms() {
        let page = reqwest::Url::parse("http://localhost/authorize").unwrap();
        for html in [
            "<form method=post action=https://other.example/callback></form>",
            "<form method=get action=/callback></form>",
            "<form method=post action=/callback enctype=multipart/form-data></form>",
            "<form method=post action=/callback></form><form></form>",
        ] {
            assert!(response_form(html, &page, "http://localhost/callback").is_err());
        }
    }

    #[tokio::test]
    async fn browser_follows_redirect_and_posts_encoded_fields_with_cookies() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for step in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0; 1024];
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert_ne!(count, 0);
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                        let length = headers
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length: "))
                            .map(|n| n.parse::<usize>().unwrap())
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(request).unwrap();
                let response = match step {
                    0 => {
                        assert!(request.starts_with("GET /start "));
                        "HTTP/1.1 302 Found\r\nLocation: /authorize\r\nSet-Cookie: session=test; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
                    }
                    1 => {
                        assert!(request.starts_with("GET /authorize "));
                        let body = r#"<form method="post" action="/callback"><input type="hidden" name="code" value="a&amp;b+ c"><input type="hidden" name="state" value="one"><input type="hidden" name="state" value="two"></form>"#;
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    }
                    _ => {
                        assert!(request.starts_with("POST /callback "));
                        assert!(request.contains("cookie: session=test"));
                        assert!(
                            request.contains("content-type: application/x-www-form-urlencoded")
                        );
                        assert!(request.ends_with("code=a%26b%2B+c&state=one&state=two"));
                        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_owned()
                    }
                };
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let browser = Browser::spawn(
            reqwest::Client::builder()
                .cookie_store(true)
                .build()
                .unwrap(),
        );
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            browser
                .navigate(format!("{base}/start"), format!("{base}/callback"))
                .await
                .await
                .unwrap()
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.final_url, format!("{base}/callback"));
        server.await.unwrap();
    }
}
