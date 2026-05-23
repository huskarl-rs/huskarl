use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::CONFORMANCE_SUITE_BASE;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Client for the OpenID Conformance Suite REST API.
pub struct ConformanceClient {
    http: reqwest::Client,
    pub base_url: String,
}

/// The response from creating a test plan.
#[derive(Debug, Deserialize)]
pub struct PlanInfo {
    pub id: String,
    /// The test modules that make up this plan.
    pub modules: Vec<PlanModule>,
}

/// A reference to a test module within a plan.
#[derive(Debug, Deserialize)]
pub struct PlanModule {
    #[serde(rename = "testModule")]
    pub test_module: String,
}

/// The response from creating a test module instance.
#[derive(Debug, Deserialize)]
pub struct CreatedModule {
    pub id: String,
    pub name: String,
    /// The issuer URL for this module — use this as the OIDC issuer for the auth flow.
    pub url: String,
}

/// The status and result of a test module instance (from `GET /api/info/{id}`).
#[derive(Debug, Deserialize)]
pub struct ModuleInfo {
    #[serde(rename = "_id")]
    pub id: String,
    pub status: ModuleStatus,
    pub result: Option<TestResult>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TestResult {
    Passed,
    Warning,
    Review,
    Failed,
    Skipped,
    Unknown,
}

impl ConformanceClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build conformance API client");
        Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    pub fn local() -> Self {
        Self::new(CONFORMANCE_SUITE_BASE)
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
    ) -> Result<CreatedModule, Error> {
        let resp = self
            .http
            .post(format!("{}/api/runner", self.base_url))
            .query(&[("test", test_name), ("plan", plan_id)])
            .send()
            .await?;

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
            let info = self.get_module_info(module_id).await?;
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
