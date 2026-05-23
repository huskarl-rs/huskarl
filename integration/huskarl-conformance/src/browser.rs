use tokio::sync::{mpsc, oneshot};

/// The result of a browser navigation request.
pub struct NavigationResult {
    pub status: u16,
    pub final_url: String,
}

struct Pending {
    url: String,
    tx: oneshot::Sender<Result<NavigationResult, reqwest::Error>>,
}

/// A headless browser that follows redirects, backed by a reqwest client with a cookie jar.
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
                let result = client
                    .get(&req.url)
                    .send()
                    .await
                    .map(|resp| NavigationResult {
                        status: resp.status().as_u16(),
                        final_url: resp.url().to_string(),
                    });
                let _ = req.tx.send(result);
            }
        });
        Self { tx }
    }

    /// Sends a navigation request and returns a receiver for the result.
    ///
    /// The browser follows all redirects (including those back to the loopback listener),
    /// so awaiting the receiver will not resolve until the entire redirect chain completes.
    pub async fn navigate(
        &self,
        url: String,
    ) -> oneshot::Receiver<Result<NavigationResult, reqwest::Error>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Pending { url, tx })
            .await
            .expect("browser task has stopped");
        rx
    }
}
