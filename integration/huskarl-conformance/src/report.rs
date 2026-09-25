//! Incremental client observations and suite exports. Raw suite exports may contain secrets.
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    api::{
        ConformanceClient, Error, ModuleInfo, ModuleStatus, PlanInfo, SuiteEvidence, TestResult,
    },
    client_error::ClientError,
    config::Config,
};

#[derive(Default, Serialize)]
pub struct ModuleEvidence {
    pub name: String,
    pub elapsed_seconds: Option<f64>,
    pub suite_log: Option<String>,
    pub suite_evidence_error: Option<String>,
    pub conditions: Option<ConditionSummary>,
    /// Written separately so raw configuration and logs stay out of RP upload files.
    #[serde(skip)]
    pub raw_suite_evidence: Option<SuiteEvidence>,
    /// Relative path to the per-test RP evidence uploaded during certification.
    pub client_log: Option<String>,
    /// Plan variant with this module's overrides applied.
    pub effective_variant: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposed: Option<crate::api::ModuleEndpoints>,
    pub id: Option<String>,
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preparation: Option<Result<(), ClientError>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration: Option<Result<(), ClientError>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_exchange: Option<Result<(), ClientError>>,
    pub authorization: Option<Result<(), ClientError>>,
    /// Ordered flows for scenarios that need multiple authorizations; top-level
    /// authorization/resources summarize the last attempt.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_attempts: Vec<AuthorizationAttempt>,
    pub resources: BTreeMap<String, Result<Option<u16>, ClientError>>,
    /// Independent assertion of the observed client behavior, separate from the suite verdict.
    pub client_check: Option<Result<(), String>>,
    pub suite: Option<ModuleInfo>,
    pub harness_error: Option<String>,
}

/// Counts retain every result category; diagnostics identify warning/failure/review entries.
#[derive(Default, Serialize)]
pub struct ConditionSummary {
    pub counts: BTreeMap<String, usize>,
    pub diagnostics: Vec<Value>,
}

impl ConditionSummary {
    pub fn from_logs(logs: &[Value]) -> Self {
        let mut summary = Self::default();
        for entry in logs {
            if let Some(result) = entry.get("result").and_then(Value::as_str) {
                *summary.counts.entry(result.to_owned()).or_default() += 1;
                if matches!(result, "FAILURE" | "WARNING" | "REVIEW") {
                    // Avoid copying arbitrary suite payloads into RP client logs.
                    summary.diagnostics.push(json!({
                        "result": result, "src": entry.get("src"),
                        "msg": entry.get("msg"), "blockId": entry.get("blockId"),
                        "time": entry.get("time"),
                    }));
                }
            }
        }
        summary
    }
}

#[derive(Serialize)]
pub struct AuthorizationAttempt {
    pub authorization: Result<(), ClientError>,
    pub resources: BTreeMap<String, Result<Option<u16>, ClientError>>,
}

impl ModuleEvidence {
    fn verdict(&self) -> &'static str {
        if self.harness_error.is_some() {
            return "HARNESS_ERROR";
        }
        let Some(info) = &self.suite else {
            return "INCOMPLETE";
        };
        if info.status == ModuleStatus::Interrupted {
            return "INTERRUPTED";
        }
        if info.status != ModuleStatus::Finished {
            return "INCOMPLETE";
        }
        match info.result {
            Some(TestResult::Passed) => "PASSED",
            Some(TestResult::Warning) => "WARNING",
            Some(TestResult::Review) => "REVIEW",
            Some(TestResult::Skipped) => "SKIPPED",
            Some(TestResult::Failed) => "FAILED",
            _ => "UNKNOWN",
        }
    }
    fn accepted(&self) -> bool {
        self.suite_evidence_error.is_none()
            && matches!(self.verdict(), "PASSED" | "WARNING" | "REVIEW" | "SKIPPED")
            && matches!(self.client_check, Some(Ok(())))
    }
}

// Suite names and response types are remote input, never filesystem paths.
fn filename_component(value: &str, limit: usize) -> String {
    let value: String = value
        .chars()
        .take(limit)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if value.is_empty() {
        "test".into()
    } else {
        value
    }
}

fn client_log_path(module: &ModuleEvidence, sequence: usize) -> String {
    let name = filename_component(&module.name, 160);
    let response = module
        .effective_variant
        .get("response_type")
        .and_then(Value::as_str)
        .map(|value| format!("_{}", filename_component(value, 60)))
        .unwrap_or_default();
    // Sequence also distinguishes repeated tests with identical variants and
    // prevents collisions caused by sanitizing untrusted names.
    format!("client-logs/{name}{response}-{sequence}.log")
}

/// Replace an artifact only after its complete contents have been written.
fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<(), Error> {
        std::fs::write(&temporary, contents)?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub struct Evidence {
    dir: PathBuf,
    manifest: Value,
    modules: Vec<ModuleEvidence>,
    expected: usize,
    started: Instant,
}

impl Evidence {
    pub fn new(
        config: &Config,
        plan_name: &str,
        plan: &PlanInfo,
        variant: &Value,
    ) -> Result<Self, Error> {
        // Use our own identifier for filesystem paths, never a server-provided ID.
        let dir = config.evidence_dir.join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir)?;
        let revision = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        let working_tree_dirty = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| !o.stdout.is_empty());
        let image_tag = std::env::var("IMAGE_TAG").unwrap_or_else(|_| "latest".into());
        // Local image metadata is provenance for the cached images, not a claim about hosted builds.
        let local_images = if config.base_url == crate::CONFORMANCE_SUITE_BASE {
            Command::new("docker")
                .args([
                    "image",
                    "inspect",
                    "--format",
                    "{{json .RepoDigests}} {{.Id}}",
                    &format!("registry.gitlab.com/openid/conformance-suite:{image_tag}"),
                    &format!("registry.gitlab.com/openid/conformance-suite/nginx:{image_tag}"),
                ])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        } else {
            None
        };
        let manifest = json!({
            "schema_version": 2, "incremental_suite_evidence": true, "local_cached_images": local_images, "plan_name": plan_name, "plan": plan,
            "variant": variant, "suite_base": config.base_url,
            "plan_url": format!("{}/plan-detail.html?plan={}", config.base_url, plan.id),
            "revision": revision, "working_tree_dirty": working_tree_dirty, "insecure_tls": config.insecure_tls,
            "started_at_unix_seconds": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
        });
        let evidence = Self {
            dir,
            manifest,
            modules: vec![],
            expected: plan.modules.len(),
            started: Instant::now(),
        };
        evidence.save()?;
        println!("Evidence: {}", evidence.dir.display());
        println!("Plan: {}", evidence.manifest["plan_url"]);
        Ok(evidence)
    }

    fn save(&self) -> Result<(), Error> {
        let mut counts = BTreeMap::<&str, usize>::new();
        for module in &self.modules {
            *counts.entry(module.verdict()).or_default() += 1;
        }
        let document = json!({"run": self.manifest, "modules": self.modules,
            "counts": counts, "expected_modules": self.expected,
            "recorded_modules": self.modules.len(),
            "client_check_failures": self.modules.iter()
                .filter(|m| !matches!(m.client_check, Some(Ok(())))).count()});
        write_atomic(
            &self.dir.join("report.json"),
            &serde_json::to_vec_pretty(&document)?,
        )
    }

    fn write_client_log(&self, module: &ModuleEvidence, sequence: usize) -> Result<(), Error> {
        let path = self.dir.join(client_log_path(module, sequence));
        let document = json!({
            "plan_name": self.manifest["plan_name"],
            "plan_url": self.manifest["plan_url"],
            "revision": self.manifest["revision"],
            "working_tree_dirty": self.manifest["working_tree_dirty"],
            "run_started_at_unix_seconds": self.manifest["started_at_unix_seconds"],
            "outcome": module.verdict(),
            "client_observations": module,
        });
        let contents = format!(
            "Huskarl RP client evidence\nObserved operations and captured client errors for this test.\nAbsent operations were not performed; suite verdict and client_check are separate.\n\n{}\n",
            serde_json::to_string_pretty(&document)?,
        );
        write_atomic(&path, contents.as_bytes())
    }

    pub fn record(&mut self, mut module: ModuleEvidence) -> Result<(), Error> {
        println!("{}: {}", module.name, module.verdict());
        if let Some(Err(error)) = &module.client_check {
            println!("    client check failed: {error}");
        }
        if let Some(raw) = module.raw_suite_evidence.take() {
            let relative = format!("suite-logs/module-{}.json", self.modules.len() + 1);
            let persist =
                || write_atomic(&self.dir.join(&relative), &serde_json::to_vec_pretty(&raw)?);
            match persist() {
                Ok(()) => module.suite_log = Some(relative),
                Err(error) => {
                    module.suite_evidence_error = Some(format!("saving suite logs: {error}"))
                }
            }
        }
        module.client_log = Some(client_log_path(&module, self.modules.len() + 1));
        let log_result = self.write_client_log(&module, self.modules.len() + 1);
        self.modules.push(module);
        // Preserve observations even if the client-log write failed.
        self.save()?;
        log_result
    }

    pub async fn finish(mut self, api: &ConformanceClient, plan: &PlanInfo) -> Vec<String> {
        let mut failures: Vec<String> = self
            .modules
            .iter()
            .filter(|m| !m.accepted())
            .map(|m| {
                format!(
                    "{}: {}{}",
                    m.name,
                    m.verdict(),
                    m.harness_error
                        .as_ref()
                        .map(|e| format!(": {e}"))
                        .unwrap_or_default()
                        + &match &m.client_check {
                            Some(Ok(())) => String::new(),
                            Some(Err(error)) => format!("; client check failed: {error}"),
                            None => "; client check was not performed".into(),
                        }
                        + &m.suite_evidence_error
                            .as_ref()
                            .map(|error| format!("; suite evidence: {error}"))
                            .unwrap_or_default()
                )
            })
            .collect();
        if self.expected == 0 || self.modules.len() != self.expected {
            failures.push("plan has no modules or module evidence is incomplete".into());
        }
        match api.export_plan(&plan.id).await {
            Ok(bytes) => match write_atomic(&self.dir.join("suite-export.zip"), &bytes) {
                Ok(()) => self.manifest["export"] = json!("suite-export.zip"),
                Err(e) => {
                    self.manifest["export_error"] = json!(e.to_string());
                    failures.push(format!("saving suite export: {e}"));
                }
            },
            Err(e) => {
                self.manifest["export_error"] = json!(e.to_string());
                failures.push(format!("exporting suite evidence: {e}"));
            }
        }
        self.manifest["elapsed_seconds"] = json!(self.started.elapsed().as_secs_f64());
        self.manifest["finished"] = json!(true);
        if let Err(e) = self.save() {
            failures.push(format!("saving evidence: {e}"));
        }
        let mut counts = BTreeMap::<&str, usize>::new();
        for module in &self.modules {
            *counts.entry(module.verdict()).or_default() += 1;
        }
        println!("Suite outcomes: {counts:?}");
        failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persists_partial_run_and_distinct_verdict_counts() {
        let dir = std::env::temp_dir().join(format!("huskarl-evidence-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut evidence = Evidence {
            dir: dir.clone(),
            manifest: json!({"plan_name": "test"}),
            modules: vec![],
            expected: 3,
            started: Instant::now(),
        };
        evidence.save().unwrap();
        for result in [TestResult::Passed, TestResult::Review] {
            evidence
                .record(ModuleEvidence {
                    name: "test".into(),
                    authorization_attempts: vec![
                        AuthorizationAttempt {
                            authorization: Ok(()),
                            resources: BTreeMap::new(),
                        },
                        AuthorizationAttempt {
                            authorization: Err("second flow rejected".into()),
                            resources: BTreeMap::new(),
                        },
                    ],
                    suite: Some(ModuleInfo {
                        id: "id".into(),
                        status: ModuleStatus::Finished,
                        result: Some(result),
                    }),
                    ..Default::default()
                })
                .unwrap();
        }
        let report: Value =
            serde_json::from_slice(&std::fs::read(dir.join("report.json")).unwrap()).unwrap();
        assert_eq!(
            report["modules"][0]["authorization_attempts"][0]["authorization"],
            json!({"Ok": null})
        );
        assert_eq!(
            report["modules"][0]["authorization_attempts"][1]["authorization"],
            json!({"Err": {"message": "second flow rejected", "rejection": null}})
        );
        assert_eq!(report["counts"]["PASSED"], 1);
        assert_eq!(report["counts"]["REVIEW"], 1);
        assert_eq!(report["recorded_modules"], 2);
        assert_eq!(report["expected_modules"], 3);
        assert!(!dir.join("report.json.tmp").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn persists_raw_logs_before_export_and_summarizes_conditions() {
        let dir = std::env::temp_dir().join(format!("huskarl-raw-logs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let logs = json!([
            {"result": "SUCCESS", "src": "CheckIssuer"},
            {"result": "WARNING", "src": "CheckScope", "msg": "scope missing", "blockId": "block"},
            {"result": "FAILURE", "src": "CheckAudience"},
            {"result": "INFO"}, {"msg": "no result"}
        ]);
        let raw = json!({"testInfo": {"_id": "id", "config": {"client_secret": "private"}}, "results": logs});
        let mut evidence = Evidence {
            dir: dir.clone(),
            manifest: json!({}),
            modules: vec![],
            expected: 1,
            started: Instant::now(),
        };
        evidence
            .record(ModuleEvidence {
                name: "test".into(),
                elapsed_seconds: Some(1.25),
                conditions: Some(ConditionSummary::from_logs(logs.as_array().unwrap())),
                raw_suite_evidence: Some(serde_json::from_value(raw.clone()).unwrap()),
                ..Default::default()
            })
            .unwrap();
        let saved: Value =
            serde_json::from_slice(&std::fs::read(dir.join("suite-logs/module-1.json")).unwrap())
                .unwrap();
        assert_eq!(saved, raw);
        assert!(!dir.join("suite-export.zip").exists());
        let report: Value =
            serde_json::from_slice(&std::fs::read(dir.join("report.json")).unwrap()).unwrap();
        let module = &report["modules"][0];
        assert_eq!(
            module["conditions"]["counts"],
            json!({"SUCCESS": 1, "WARNING": 1, "FAILURE": 1, "INFO": 1})
        );
        assert_eq!(
            module["conditions"]["diagnostics"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(module["elapsed_seconds"], 1.25);
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("client_secret")
        );
        evidence.modules[0].suite_evidence_error = Some("download failed".into());
        assert!(!evidence.modules[0].accepted());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recording_and_finishing_do_not_rewrite_previous_client_logs() {
        let dir = std::env::temp_dir().join(format!("huskarl-once-{}", uuid::Uuid::new_v4()));
        let mut evidence = Evidence {
            dir: dir.clone(),
            manifest: json!({}),
            modules: vec![],
            expected: 2,
            started: Instant::now(),
        };
        evidence
            .record(ModuleEvidence {
                name: "first".into(),
                ..Default::default()
            })
            .unwrap();
        let first = dir.join("client-logs/first-1.log");
        // A sentinel makes rewriting observable without relying on filesystem clock precision.
        std::fs::write(&first, "already saved").unwrap();
        evidence
            .record(ModuleEvidence {
                name: "second".into(),
                ..Default::default()
            })
            .unwrap();
        evidence.manifest["finished"] = json!(true);
        evidence.save().unwrap();
        assert_eq!(std::fs::read_to_string(first).unwrap(), "already saved");
        assert!(dir.join("client-logs/second-2.log").is_file());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn atomic_writes_replace_complete_artifacts_and_clean_failed_temporaries() {
        let dir = std::env::temp_dir().join(format!("huskarl-atomic-{}", uuid::Uuid::new_v4()));
        let artifact = dir.join("suite-export.zip");
        write_atomic(&artifact, b"original").unwrap();
        write_atomic(&artifact, b"replacement").unwrap();
        assert_eq!(std::fs::read(&artifact).unwrap(), b"replacement");
        let blocked = dir.join("directory");
        std::fs::create_dir(&blocked).unwrap();
        assert!(write_atomic(&blocked, b"cannot replace directory").is_err());
        assert!(blocked.is_dir());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn per_test_logs_preserve_rejections_variants_and_duplicate_instances() {
        use crate::client_error::{Rejection, TokenRejection};
        let dir =
            std::env::temp_dir().join(format!("huskarl-client-logs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut evidence = Evidence {
            dir: dir.clone(),
            manifest: json!({"plan_url": "https://suite.example/plan", "revision": "abc123"}),
            modules: vec![],
            expected: 3,
            started: Instant::now(),
        };
        for response in ["code id_token", "code token", "code id_token"] {
            evidence
                .record(ModuleEvidence {
                    name: "oidcc-client-test-invalid-iss".into(),
                    effective_variant: json!({"response_type": response}),
                    preparation: Some(Ok(())),
                    authorization: Some(Err(ClientError {
                        message:
                            "ID token issuer mismatch: expected issuer.example, got wrong.example"
                                .into(),
                        rejection: Some(Rejection::IdToken(TokenRejection::ClaimMismatch("iss"))),
                    })),
                    client_check: Some(Ok(())),
                    ..Default::default()
                })
                .unwrap();
        }
        for (index, response) in ["code-id_token", "code-token", "code-id_token"]
            .iter()
            .enumerate()
        {
            let relative = format!(
                "client-logs/oidcc-client-test-invalid-iss_{response}-{}.log",
                index + 1
            );
            assert_eq!(
                evidence.modules[index].client_log.as_deref(),
                Some(relative.as_str())
            );
            let log = std::fs::read_to_string(dir.join(relative)).unwrap();
            assert!(log.contains("ID token issuer mismatch"));
            assert!(log.contains("ClaimMismatch"));
            assert!(log.contains("abc123"));
            assert!(!log.contains("client_secret"));
            let data: Value = serde_json::from_str(log.split_once("\n\n").unwrap().1).unwrap();
            assert_eq!(
                data["client_observations"]["client_check"],
                json!({"Ok": null})
            );
            assert_eq!(
                data["client_observations"]["authorization"]["Err"]["rejection"],
                json!({"IdToken": {"ClaimMismatch": "iss"}})
            );
        }
        assert_eq!(
            std::fs::read_dir(dir.join("client-logs")).unwrap().count(),
            3
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn client_log_names_cannot_escape_directory_and_export_failures_propagate() {
        let module = ModuleEvidence {
            name: "../../outside".into(),
            effective_variant: json!({"response_type": "../../code id_token"}),
            ..Default::default()
        };
        let path = PathBuf::from(client_log_path(&module, 1));
        assert_eq!(path.parent().unwrap(), std::path::Path::new("client-logs"));
        assert!(!path.to_str().unwrap().contains(".."));
        let dir =
            std::env::temp_dir().join(format!("huskarl-log-failure-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // A file where the log directory belongs must fail, retaining the report.
        std::fs::write(dir.join("client-logs"), b"blocked").unwrap();
        let mut evidence = Evidence {
            dir: dir.clone(),
            manifest: json!({}),
            modules: vec![],
            expected: 1,
            started: Instant::now(),
        };
        assert!(evidence.record(module).is_err());
        assert!(dir.join("report.json").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn separates_acceptable_verdicts_from_passes_and_harness_failures() {
        for result in [
            TestResult::Passed,
            TestResult::Warning,
            TestResult::Review,
            TestResult::Skipped,
        ] {
            let mut module = ModuleEvidence {
                client_check: Some(Ok(())),
                suite: Some(ModuleInfo {
                    id: "id".into(),
                    status: ModuleStatus::Finished,
                    result: Some(result),
                }),
                ..Default::default()
            };
            assert!(module.accepted());
            module.client_check = Some(Err("unexpected client rejection".into()));
            assert!(!module.accepted());
            module.client_check = None;
            assert!(!module.accepted());
            module.client_check = Some(Ok(()));
            module.harness_error = Some("timeout".into());
            assert!(!module.accepted());
        }
        assert!(!ModuleEvidence::default().accepted());
    }
}
