use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::Config;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Client for the OpenID Conformance Suite REST API.
pub struct ConformanceClient {
    http: reqwest::Client,
    pub base_url: String,
}

/// Complete suite evidence with a stable envelope and unfiltered metadata/log fields.
#[derive(Debug, Deserialize, Serialize)]
pub struct SuiteEvidence {
    #[serde(rename = "testInfo")]
    pub info: serde_json::Map<String, serde_json::Value>,
    pub results: Vec<serde_json::Value>,
}

/// The response from creating a test plan.
#[derive(Debug, Deserialize, Serialize)]
pub struct PlanInfo {
    pub id: String,
    /// The test modules that make up this plan.
    pub modules: Vec<PlanModule>,
}

/// A reference to a test module within a plan.
#[derive(Debug, Deserialize, Serialize)]
pub struct PlanModule {
    #[serde(rename = "testModule")]
    pub test_module: String,
    /// Suite-provided overrides for this module, merged over the plan variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<serde_json::Map<String, serde_json::Value>>,
}

/// The response from creating a test module instance.
#[derive(Debug, Deserialize, Serialize)]
pub struct CreatedModule {
    pub id: String,
    pub name: String,
    /// The issuer URL for this module — use this as the OIDC issuer for the auth flow.
    pub url: String,
    /// Fetched from the running module after it reaches WAITING.
    #[serde(skip)]
    pub exposed: ModuleEndpoints,
}

/// Only retain the endpoint fields needed by scenarios, not arbitrary exposed data.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ModuleEndpoints {
    pub issuer: Option<String>,
    pub accounts_endpoint: Option<String>,
}

impl ModuleEndpoints {
    /// Use the exposed resource URL verbatim. Certificate-bound requests must use
    /// the same HTTPS origin as the discovered mTLS token endpoint.
    pub fn accounts_uri(
        &self,
        mtls_token_endpoint: Option<&huskarl::core::EndpointUrl>,
    ) -> Result<http::Uri, Error> {
        let raw = self
            .accounts_endpoint
            .as_deref()
            .ok_or("suite module omitted accounts_endpoint")?;
        let endpoint = reqwest::Url::parse(raw)?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
        {
            return Err("suite accounts_endpoint must be an absolute HTTPS URL without credentials or fragment".into());
        }
        if let Some(token) = mtls_token_endpoint {
            let token = reqwest::Url::parse(&token.to_string())?;
            if token.scheme() != "https" || endpoint.origin() != token.origin() {
                return Err(
                    "suite accounts_endpoint does not use the discovered mTLS origin".into(),
                );
            }
        }
        Ok(raw.parse()?)
    }
}

/// The status and result of a test module instance (from `GET /api/info/{id}`).
#[derive(Debug, Deserialize, Serialize)]
pub struct ModuleInfo {
    #[serde(rename = "_id")]
    pub id: String,
    pub status: ModuleStatus,
    pub result: Option<TestResult>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleStatus {
    /// Module has been created and is ready for the RP to act.
    Created,
    /// Legacy alias for Created seen in some suite versions.
    Configured,
    Waiting,
    Finished,
    Interrupted,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TestResult {
    Passed,
    Warning,
    Review,
    Failed,
    Skipped,
    Unknown,
}

fn validate_export(bytes: &[u8]) -> Result<(), Error> {
    let validate = || -> Result<(), Error> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
        if archive.is_empty() {
            return Err("empty archive".into());
        }
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index)?;
            // Reading every entry to EOF verifies decompression and CRC without extraction.
            std::io::copy(&mut entry, &mut std::io::sink())?;
        }
        Ok(())
    };
    validate().map_err(|error| format!("invalid suite ZIP: {error}").into())
}

impl ConformanceClient {
    pub fn new(config: &Config) -> Result<Self, Error> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(token) = &config.api_token {
            let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
            value.set_sensitive(true);
            headers.insert(reqwest::header::AUTHORIZATION, value);
        }
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(config.insecure_tls)
            .timeout(config.request_timeout)
            .build()?;
        Ok(Self {
            http,
            base_url: config.base_url.clone(),
        })
    }

    /// Preserve complete suite metadata and condition logs, including unknown fields.
    pub async fn module_evidence(&self, module_id: &str) -> Result<SuiteEvidence, Error> {
        let info: serde_json::Map<String, serde_json::Value> = self
            .http
            .get(format!("{}/api/info/{module_id}", self.base_url))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let logs: Vec<serde_json::Value> = self
            .http
            .get(format!("{}/api/log/{module_id}", self.base_url))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(SuiteEvidence {
            info,
            results: logs,
        })
    }

    /// Download evidence only; this does not publish or lock the plan.
    pub async fn export_plan(&self, plan_id: &str) -> Result<bytes::Bytes, Error> {
        self.export_with_attempts(plan_id, 5, Duration::from_secs(1))
            .await
    }

    async fn export_with_attempts(
        &self,
        plan_id: &str,
        attempts: u32,
        backoff: Duration,
    ) -> Result<bytes::Bytes, Error> {
        let mut errors = Vec::new();
        for attempt in 0..attempts {
            if attempt > 0 {
                tokio::time::sleep(backoff * (1 << (attempt - 1))).await;
            }
            let download = async {
                let response = self
                    .http
                    .get(format!("{}/api/plan/export/{plan_id}", self.base_url))
                    .send()
                    .await?
                    .error_for_status()?;
                let bytes = response.bytes().await?;
                validate_export(&bytes)?;
                Ok::<_, Error>(bytes)
            }
            .await;
            match download {
                Ok(bytes) => return Ok(bytes),
                Err(error) => {
                    // Credentials and invalid requests cannot be fixed by retrying.
                    if error
                        .downcast_ref::<reqwest::Error>()
                        .and_then(reqwest::Error::status)
                        .is_some_and(|status| {
                            status.is_client_error()
                                && status.as_u16() != 429
                                && status.as_u16() != 408
                        })
                    {
                        return Err(error);
                    }
                    errors.push(error.to_string());
                }
            }
        }
        Err(format!(
            "suite export failed after {attempts} attempts: {}",
            errors.join("; ")
        )
        .into())
    }

    /// Returns the OIDC issuer URL for a plan with the given alias.
    ///
    /// All modules within a plan share this issuer URL. The conformance suite
    /// changes the AS behavior for each module instance while keeping the
    /// discovery/token/authorization endpoints stable.
    pub fn plan_issuer(&self, alias: &str) -> String {
        format!("{}/test/a/{}/", self.base_url, alias)
    }

    /// Polls until the conformance suite API is reachable, or until timeout.
    ///
    /// Useful when the suite has just been started via Docker and may not be
    /// accepting connections yet (nginx returns 502 while the backend boots).
    pub async fn wait_until_ready(&self, timeout: Duration) -> Result<(), Error> {
        let deadline = Instant::now() + timeout;
        loop {
            match self
                .http
                .get(format!("{}/api/plan", self.base_url))
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) if matches!(resp.status().as_u16(), 401 | 403) => {
                    return Err(format!(
                        "suite API authentication failed (HTTP {})",
                        resp.status()
                    )
                    .into());
                }
                _ if Instant::now() >= deadline => {
                    return Err("timed out waiting for conformance suite to become ready".into());
                }
                _ => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    }

    /// Creates a test plan. `config` is the plan configuration JSON body;
    /// `variant` selects sub-options (e.g. `server_metadata`, `client_registration`).
    ///
    /// Returns the plan info including the list of module names to run.
    pub async fn create_plan(
        &self,
        plan_name: &str,
        config: &serde_json::Value,
        variant: Option<&serde_json::Value>,
    ) -> Result<PlanInfo, Error> {
        let mut query = vec![("planName", plan_name.to_string())];
        if let Some(v) = variant {
            query.push(("variant", v.to_string()));
        }

        let resp = self
            .http
            .post(format!("{}/api/plan", self.base_url))
            .query(&query)
            .json(config)
            .send()
            .await?;

        if resp.status().as_u16() != 201 {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("create_plan failed (HTTP {status}): {body}").into());
        }

        Ok(resp.json().await?)
    }

    /// Creates a test module instance from an existing plan.
    ///
    /// The returned `CreatedModule::url` is the OIDC issuer URL to use for the
    /// auth flow. The module status is not yet available; poll with
    /// [`Self::wait_for_status`] before starting the flow.
    pub async fn create_module_from_plan(
        &self,
        plan_id: &str,
        test_name: &str,
        variant: Option<&serde_json::Map<String, serde_json::Value>>,
    ) -> Result<CreatedModule, Error> {
        let mut request = self
            .http
            .post(format!("{}/api/runner", self.base_url))
            .query(&[("test", test_name), ("plan", plan_id)]);
        if let Some(variant) = variant {
            request = request.query(&[("variant", serde_json::to_string(variant)?)]);
        }
        let resp = request.send().await?;

        if resp.status().as_u16() != 201 {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "create_module_from_plan({test_name}) failed (HTTP {status}): {body}"
            )
            .into());
        }

        Ok(resp.json().await?)
    }

    /// Fetch endpoints exposed by an active module after it reaches WAITING.
    pub async fn get_module_endpoints(&self, module_id: &str) -> Result<ModuleEndpoints, Error> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(default)]
            exposed: Option<ModuleEndpoints>,
        }
        let response = self
            .http
            .get(format!("{}/api/runner/{module_id}", self.base_url))
            .send()
            .await?
            .error_for_status()?;
        Ok(response
            .json::<Response>()
            .await?
            .exposed
            .unwrap_or_default())
    }

    /// Fetches the current info for a module.
    pub async fn get_module_info(&self, module_id: &str) -> Result<ModuleInfo, Error> {
        let resp = self
            .http
            .get(format!("{}/api/info/{}", self.base_url, module_id))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("get_module_info failed (HTTP {status}): {body}").into());
        }

        Ok(resp.json().await?)
    }

    /// Polls until the module reaches one of the target statuses, or until timeout.
    pub async fn wait_for_status(
        &self,
        module_id: &str,
        targets: &[ModuleStatus],
        timeout: Duration,
    ) -> Result<ModuleInfo, Error> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let info = tokio::time::timeout(remaining, self.get_module_info(module_id))
                .await
                .map_err(|_| format!("timed out fetching status for module {module_id}"))??;
            if targets.contains(&info.status) {
                return Ok(info);
            }
            if info.status == ModuleStatus::Interrupted {
                return Err(format!("module {module_id} was INTERRUPTED").into());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for module {module_id} to reach {targets:?} (last status: {:?})",
                    info.status
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn server(response: impl Into<String>) -> (String, tokio::task::JoinHandle<String>) {
        let response = response.into();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 1024];
                let count = stream.read(&mut buffer).await.unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|s| s == b"\r\n\r\n") {
                    break;
                }
            }
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        });
        (base, task)
    }

    fn config(base_url: String) -> Config {
        Config {
            base_url,
            api_token: Some("test-token".into()),
            insecure_tls: false,
            request_timeout: Duration::from_secs(2),
            evidence_dir: std::env::temp_dir(),
        }
    }

    #[test]
    fn accounts_endpoint_requires_https_and_preserves_resource_path_and_query() {
        let mut exposed = ModuleEndpoints::default();
        assert!(exposed.accounts_uri(None).is_err());
        for endpoint in [
            "/accounts",
            "http://resource.example/accounts",
            "https://user:pass@resource.example/accounts",
            "https://resource.example/accounts#fragment",
            "not a url",
        ] {
            exposed.accounts_endpoint = Some(endpoint.into());
            assert!(exposed.accounts_uri(None).is_err(), "{endpoint}");
        }
        exposed.accounts_endpoint = Some("https://resource.example/custom/path?version=2".into());
        let token = "https://resource.example:443/unrelated/token"
            .parse()
            .unwrap();
        assert_eq!(
            exposed.accounts_uri(Some(&token)).unwrap().to_string(),
            "https://resource.example/custom/path?version=2"
        );
        for token in [
            "https://other.example/token",
            "https://resource.example:8444/token",
        ] {
            assert!(exposed.accounts_uri(Some(&token.parse().unwrap())).is_err());
        }
    }

    #[tokio::test]
    async fn exposed_endpoints_use_management_auth_and_allow_missing_optional_fields() {
        for body in [
            r#"{"exposed":{"issuer":"https://issuer.example/","unrelated":"secret"}}"#,
            "{}",
            r#"{"exposed":null}"#,
        ] {
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let (base, request) = server(response).await;
            let api = ConformanceClient::new(&config(base)).unwrap();
            let endpoints = api.get_module_endpoints("module").await.unwrap();
            assert!(endpoints.accounts_endpoint.is_none());
            let request = request.await.unwrap().to_lowercase();
            assert!(request.starts_with("get /api/runner/module "));
            assert!(request.contains("authorization: bearer test-token"));
        }
    }

    #[tokio::test]
    async fn authenticates_export_and_rejects_non_archive_response() {
        let (base, request) = server("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnope").await;
        let api = ConformanceClient::new(&config(base)).unwrap();
        assert!(
            api.export_with_attempts("plan-id", 1, Duration::ZERO)
                .await
                .unwrap_err()
                .to_string()
                .contains("ZIP")
        );
        let request = request.await.unwrap().to_lowercase();
        assert!(request.starts_with("get /api/plan/export/plan-id "));
        assert!(request.contains("authorization: bearer test-token"));
    }

    fn test_zip() -> Vec<u8> {
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file(
                "log.json",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(b"unique-log-content").unwrap();
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn validates_archive_contents_and_crc() {
        let bytes = test_zip();
        validate_export(&bytes).unwrap();
        assert!(validate_export(&bytes[..bytes.len() - 10]).is_err());
        let mut corrupt = bytes.clone();
        let offset = corrupt
            .windows(18)
            .position(|w| w == b"unique-log-content")
            .unwrap();
        corrupt[offset] ^= 1;
        assert!(validate_export(&corrupt).is_err());
        assert!(validate_export(b"PKgarbage").is_err());
    }

    #[tokio::test]
    async fn retries_transient_and_corrupt_exports_then_preserves_valid_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = ConformanceClient::new(&config(format!(
            "http://{}",
            listener.local_addr().unwrap()
        )))
        .unwrap();
        let valid = test_zip();
        let expected = valid.clone();
        let server = tokio::spawn(async move {
            for (status, body) in [
                (503, Vec::new()),
                (200, b"PKcorrupt".to_vec()),
                (200, valid),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let byte = stream.read_u8().await.unwrap();
                    request.push(byte);
                }
                let head = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            }
        });
        let actual = api
            .export_with_attempts("id", 3, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(actual.as_ref(), expected);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn export_auth_failure_is_not_retried() {
        let (base, request) =
            server("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n").await;
        let api = ConformanceClient::new(&config(base)).unwrap();
        let error = api
            .export_with_attempts("id", 5, Duration::ZERO)
            .await
            .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<reqwest::Error>()
                .unwrap()
                .status()
                .unwrap(),
            401
        );
        request.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_auth_failure_without_waiting_for_readiness_deadline() {
        let (base, request) =
            server("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n").await;
        let api = ConformanceClient::new(&config(base)).unwrap();
        let error = api
            .wait_until_ready(Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("authentication failed"));
        request.await.unwrap();
    }

    #[tokio::test]
    async fn management_client_does_not_follow_redirects() {
        let (base, request) = server("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\n\r\n").await;
        let api = ConformanceClient::new(&config(base)).unwrap();
        let response = api.http.get(&api.base_url).send().await.unwrap();
        assert_eq!(response.status(), 302);
        request.await.unwrap();
    }
}
