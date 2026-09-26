//! Shared suite lifecycle. Protocol actions remain in the scenario functions.
use std::time::{Duration, Instant};

use huskarl_reqwest::mtls::{MtlsProvider, NoMtls};
use serde_json::Value;

use crate::{
    api::{ConformanceClient, CreatedModule, Error, ModuleStatus, PlanModule},
    config::Config,
    flow::FlowContext,
    report::{Evidence, ModuleEvidence},
};

/// Suite readiness, status polling, and complete module execution budgets.
pub struct Deadlines {
    pub suite_ready: Duration,
    pub status: Duration,
    pub module: Duration,
}

impl Default for Deadlines {
    fn default() -> Self {
        Self {
            suite_ready: Duration::from_secs(60),
            status: Duration::from_secs(30),
            module: Duration::from_secs(180),
        }
    }
}

pub struct Runner {
    settings: Config,
    api: ConformanceClient,
    pub alias: String,
    pub client: FlowContext,
    pub deadlines: Deadlines,
}

impl Runner {
    pub async fn new(settings: Config) -> Result<Self, Error> {
        Self::new_with_mtls(settings, NoMtls).await
    }

    /// Install a client certificate on protocol transport only.
    pub async fn new_with_mtls(
        settings: Config,
        mtls: impl MtlsProvider + 'static,
    ) -> Result<Self, Error> {
        let api = ConformanceClient::new(&settings)?;
        let alias = format!("huskarl-{}", uuid::Uuid::new_v4());
        let client = FlowContext::new_with_mtls(&settings, api.plan_issuer(&alias), mtls).await?;
        Ok(Self {
            settings,
            api,
            alias,
            client,
            deadlines: Deadlines::default(),
        })
    }

    /// The scenario owns registration/configuration and protocol observations.
    /// Its Err means a harness failure; expected protocol rejections belong in evidence.
    pub async fn run(
        &self,
        plan_name: &str,
        config: &Value,
        variant: &Value,
        drive: impl AsyncFn(&CreatedModule, &Value, &mut ModuleEvidence) -> Result<(), Error>,
    ) -> Result<Vec<String>, Error> {
        self.api
            .wait_until_ready(self.deadlines.suite_ready)
            .await?;
        let plan = self
            .api
            .create_plan(plan_name, config, Some(variant))
            .await?;
        println!(
            "Created plan {plan_name} {} ({} modules)",
            plan.id,
            plan.modules.len()
        );
        let mut evidence = Evidence::new(&self.settings, plan_name, &plan, variant)?;
        let mut recording_errors = Vec::new();
        for entry in &plan.modules {
            let mut observation =
                run_module(&self.api, &plan.id, entry, variant, &self.deadlines, &drive).await;
            if let Some(id) = &observation.id {
                match self.api.module_evidence(id).await {
                    Ok(raw) => {
                        observation.conditions =
                            Some(crate::report::ConditionSummary::from_logs(&raw.results));
                        observation.raw_suite_evidence = Some(raw);
                    }
                    Err(error) => observation.suite_evidence_error = Some(error.to_string()),
                }
            }
            if let Err(error) = evidence.record(observation) {
                recording_errors.push(format!("saving module evidence: {error}"));
                // Still try to export the plan and save all observations collected so far.
                break;
            }
        }
        let mut failures = evidence.finish(&self.api, &plan).await;
        failures.extend(recording_errors);
        Ok(failures)
    }
}

/// Reject effective settings that a scenario's preconfigured client cannot honor.
/// Include implicit defaults in `configured`; absent suite settings impose no constraint.
pub fn require_configured_variant(effective: &Value, configured: &Value) -> Result<(), Error> {
    let effective = effective
        .as_object()
        .ok_or("effective variant must be an object")?;
    for (key, value) in effective {
        if configured.get(key) != Some(value) {
            return Err(format!("scenario cannot honor module variant {key}={value}").into());
        }
    }
    Ok(())
}

async fn run_module(
    api: &ConformanceClient,
    plan_id: &str,
    entry: &PlanModule,
    plan_variant: &Value,
    deadlines: &Deadlines,
    drive: &impl AsyncFn(&CreatedModule, &Value, &mut ModuleEvidence) -> Result<(), Error>,
) -> ModuleEvidence {
    let started = Instant::now();
    let name = &entry.test_module;
    println!("--- {name}");
    let mut observation = ModuleEvidence {
        name: name.clone(),
        ..Default::default()
    };
    let execution = async {
        let mut effective = plan_variant
            .as_object()
            .cloned()
            .ok_or("plan variant must be an object")?;
        if let Some(overrides) = &entry.variant {
            effective.extend(overrides.clone());
        }
        observation.effective_variant = Value::Object(effective.clone());
        let effective = Value::Object(effective);
        let mut module = api
            .create_module_from_plan(plan_id, name, entry.variant.as_ref())
            .await
            .map_err(|e| format!("creating module: {e}"))?;
        observation.id = Some(module.id.clone());
        observation.url = Some(format!(
            "{}/log-detail.html?log={}",
            api.base_url, module.id
        ));
        let ready = api
            .wait_for_status(
                &module.id,
                &[
                    ModuleStatus::Waiting,
                    ModuleStatus::Finished,
                    ModuleStatus::Interrupted,
                ],
                deadlines.status,
            )
            .await
            .map_err(|e| format!("waiting for readiness: {e}"))?;
        if ready.status != ModuleStatus::Waiting {
            observation.suite = Some(ready);
            return Ok::<(), Error>(());
        }
        module.exposed = api
            .get_module_endpoints(&module.id)
            .await
            .map_err(|e| format!("fetching exposed endpoints: {e}"))?;
        observation.exposed = Some(module.exposed.clone());
        drive(&module, &effective, &mut observation).await?;
        observation.suite = Some(
            api.wait_for_status(
                &module.id,
                &[ModuleStatus::Finished, ModuleStatus::Interrupted],
                deadlines.status,
            )
            .await
            .map_err(|e| format!("waiting for verdict: {e}"))?,
        );
        Ok(())
    };
    match tokio::time::timeout(deadlines.module, execution).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => observation.harness_error = Some(error.to_string()),
        Err(_) => {
            observation.harness_error =
                Some(format!("module exceeded {:?} deadline", deadlines.module))
        }
    }
    observation.elapsed_seconds = Some(started.elapsed().as_secs_f64());
    observation.client_check = Some(crate::expectations::check(
        &observation,
        &observation.effective_variant,
    ));
    observation
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn mock_api(
        responses: Vec<(&'static str, u16, Value)>,
    ) -> (ConformanceClient, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = ConformanceClient::new(&Config {
            base_url: format!("http://{}", listener.local_addr().unwrap()),
            api_token: None,
            insecure_tls: false,
            request_timeout: Duration::from_secs(2),
            evidence_dir: std::env::temp_dir(),
        })
        .unwrap();
        let server = tokio::spawn(async move {
            for (expected, status, body) in responses {
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
                assert!(String::from_utf8(request).unwrap().starts_with(expected));
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (api, server)
    }

    fn entry() -> PlanModule {
        PlanModule {
            test_module: "test".into(),
            variant: None,
        }
    }

    fn created() -> (&'static str, u16, Value) {
        (
            "POST /api/runner?test=test&plan=plan ",
            201,
            json!({"id":"module", "name":"test", "url":"https://issuer.example/"}),
        )
    }

    fn exposed() -> (&'static str, u16, Value) {
        (
            "GET /api/runner/module ",
            200,
            json!({"exposed": {
                "issuer": "https://issuer.example/",
                "accounts_endpoint": "https://resource.example/custom/accounts?version=2",
                "unrelated": "not retained",
            }}),
        )
    }

    fn status(state: &str, result: Option<&str>) -> (&'static str, u16, Value) {
        (
            "GET /api/info/module ",
            200,
            json!({"_id":"module", "status":state, "result":result}),
        )
    }

    #[tokio::test]
    async fn raw_evidence_preserves_suite_metadata_and_condition_payloads() {
        let info = json!({"_id": "id", "status": "FINISHED", "extra": {"future": true}});
        let logs = json!([{"result": "WARNING", "src": "Check", "details": {"raw": 42}}]);
        let (api, server) = mock_api(vec![
            ("GET /api/info/id", 200, info.clone()),
            ("GET /api/log/id", 200, logs.clone()),
        ])
        .await;
        let raw = api.module_evidence("id").await.unwrap();
        assert_eq!(
            serde_json::to_value(raw).unwrap(),
            json!({"testInfo": info, "results": logs})
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn module_override_reaches_creation_scenario_check_and_evidence() {
        let entry: PlanModule = serde_json::from_value(json!({
            "testModule": "fapi2-security-profile-final-client-test-happy-path",
            "variant": {"fapi_client_type": "plain_oauth"},
        }))
        .unwrap();
        let plan_variant = json!({"fapi_client_type": "oidc", "sender_constrain": "dpop"});
        let (api, server) = mock_api(vec![
            (
                "POST /api/runner?test=fapi2-security-profile-final-client-test-happy-path&plan=plan&variant=%7B%22fapi_client_type%22%3A%22plain_oauth%22%7D ",
                201,
                json!({"id":"module", "name":entry.test_module, "url":"https://issuer.example/"}),
            ),
            status("WAITING", None),
            exposed(),
            status("FINISHED", Some("PASSED")),
        ]).await;
        let observation = run_module(
            &api,
            "plan",
            &entry,
            &plan_variant,
            &Deadlines::default(),
            &async |_, effective, evidence| {
                assert_eq!(
                    effective,
                    &json!({"fapi_client_type": "plain_oauth", "sender_constrain": "dpop"})
                );
                evidence.preparation = Some(Ok(()));
                evidence.authorization = Some(Ok(()));
                evidence.resources.insert("accounts".into(), Ok(Some(200)));
                Ok(())
            },
        )
        .await;
        server.await.unwrap();
        assert!(observation.harness_error.is_none());
        // The plan's OIDC setting would demand UserInfo; the override must win.
        assert_eq!(observation.client_check, Some(Ok(())));
        assert!(crate::expectations::check(&observation, &plan_variant).is_err());
        let saved = serde_json::to_value(&observation).unwrap();
        assert_eq!(
            saved["effective_variant"],
            json!({"fapi_client_type": "plain_oauth", "sender_constrain": "dpop"})
        );
        assert_eq!(plan_variant["fapi_client_type"], "oidc");
    }

    #[test]
    fn absent_null_and_empty_overrides_are_supported_but_malformed_ones_fail() {
        for value in [
            json!({"testModule": "test"}),
            json!({"testModule": "test", "variant": null}),
            json!({"testModule": "test", "variant": {}}),
        ] {
            let entry: PlanModule = serde_json::from_value(value).unwrap();
            assert!(entry.variant.is_none_or(|v| v.is_empty()));
        }
        for variant in [json!("code"), json!([]), json!(false)] {
            assert!(
                serde_json::from_value::<PlanModule>(
                    json!({"testModule": "test", "variant": variant})
                )
                .is_err()
            );
        }
        assert!(
            require_configured_variant(
                &json!({"response_type": "code"}),
                &json!({"response_type": "code"})
            )
            .is_ok()
        );
        assert!(
            require_configured_variant(
                &json!({"response_type": "id_token"}),
                &json!({"response_type": "code"})
            )
            .is_err()
        );
        assert!(require_configured_variant(&json!({"unknown": "value"}), &json!({})).is_err());
    }

    #[tokio::test]
    async fn negative_protocol_result_still_collects_suite_verdict() {
        let (api, server) = mock_api(vec![
            created(),
            status("WAITING", None),
            exposed(),
            status("FINISHED", Some("PASSED")),
        ])
        .await;
        let observation = run_module(
            &api,
            "plan",
            &entry(),
            &json!({"response_type": "code"}),
            &Deadlines::default(),
            &async |module, effective, evidence| {
                assert_eq!(effective, &json!({"response_type": "code"}));
                assert_eq!(module.id, "module");
                assert_eq!(
                    module.exposed.issuer.as_deref(),
                    Some("https://issuer.example/")
                );
                assert_eq!(
                    module.exposed.accounts_uri(None).unwrap().to_string(),
                    "https://resource.example/custom/accounts?version=2"
                );
                evidence.authorization = Some(Err("invalid signature".into()));
                Ok(())
            },
        )
        .await;
        server.await.unwrap();
        let saved = serde_json::to_value(&observation).unwrap();
        assert_eq!(saved["exposed"]["issuer"], "https://issuer.example/");
        assert!(saved["exposed"].get("unrelated").is_none());
        assert!(observation.authorization.unwrap().is_err());
        assert!(observation.harness_error.is_none());
        assert_eq!(
            observation.suite.unwrap().result,
            Some(crate::api::TestResult::Passed)
        );
    }

    #[tokio::test]
    async fn exposed_endpoint_fetch_failure_prevents_scenario_execution() {
        for (code, body) in [
            (503, json!({})),
            (200, json!({"exposed": {"accounts_endpoint": 42}})),
        ] {
            let (api, server) = mock_api(vec![
                created(),
                status("WAITING", None),
                ("GET /api/runner/module ", code, body),
            ])
            .await;
            let observation = run_module(
                &api,
                "plan",
                &entry(),
                &json!({}),
                &Deadlines::default(),
                &async |_, _, _| panic!("failed endpoint lookup must stop protocol actions"),
            )
            .await;
            server.await.unwrap();
            assert_eq!(observation.id.as_deref(), Some("module"));
            assert!(
                observation
                    .harness_error
                    .unwrap()
                    .contains("fetching exposed endpoints")
            );
            assert!(observation.exposed.is_none());
        }
    }

    #[tokio::test]
    async fn terminal_modules_do_not_drive_protocol() {
        for (state, result) in [("FINISHED", "SKIPPED"), ("INTERRUPTED", "FAILED")] {
            let (api, server) = mock_api(vec![created(), status(state, Some(result))]).await;
            let observation = run_module(
                &api,
                "plan",
                &entry(),
                &json!({}),
                &Deadlines::default(),
                &async |_, _, _| panic!("terminal module must not run protocol actions"),
            )
            .await;
            server.await.unwrap();
            assert!(observation.authorization.is_none());
            assert!(observation.suite.is_some());
            assert!(observation.harness_error.is_none());
        }
    }

    #[tokio::test]
    async fn deadline_preserves_observations_and_module_identity() {
        let (api, server) = mock_api(vec![created(), status("WAITING", None), exposed()]).await;
        let deadlines = Deadlines {
            module: Duration::from_millis(100),
            ..Default::default()
        };
        let observation = run_module(
            &api,
            "plan",
            &entry(),
            &json!({}),
            &deadlines,
            &async |_, _, evidence| {
                evidence.authorization = Some(Ok(()));
                std::future::pending::<Result<(), Error>>().await
            },
        )
        .await;
        server.await.unwrap();
        assert_eq!(observation.id.as_deref(), Some("module"));
        assert_eq!(observation.authorization, Some(Ok(())));
        assert!(observation.harness_error.unwrap().contains("deadline"));
    }
}
