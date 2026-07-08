use std::time::Duration;

use huskarl::{
    core::{client_auth::ClientSecret, dpop::NoDPoP, server_metadata::AuthorizationServerMetadata},
    grant::authorization_code::{NoJar, bind_loopback},
    userinfo::UserInfoClient,
};
use huskarl_conformance::{
    api::{ConformanceClient, ModuleStatus},
    assert_no_failures, base_url, build_browser, build_http_client, client_id,
    report_module_result, run_auth_code_flow_with_listener,
};
use huskarl_testkit::PlainSecret;
use uuid::Uuid;

fn client_secret() -> String {
    std::env::var("CONFORMANCE_CLIENT_SECRET").unwrap_or_else(|_| "client-secret".to_string())
}

fn client_auth() -> ClientSecret {
    ClientSecret::new(PlainSecret::new(client_secret()))
}

/// Drives every module in a conformance plan.
///
/// Fetches metadata per module, runs the auth code flow, calls userinfo if the
/// flow succeeded, then waits for the suite's verdict. Modules that the RP is
/// expected to reject (bad signature, wrong issuer, etc.) will return an `Err`
/// from the flow — that is fine and expected.
///
/// Returns a list of failure descriptions (empty on full success).
async fn run_plan(plan_name: &str) -> Vec<String> {
    let conformance = ConformanceClient::new(base_url());
    conformance
        .wait_until_ready(Duration::from_secs(60))
        .await
        .expect("conformance suite not ready");

    let http_client = build_http_client().await;
    let browser = build_browser();

    let listener = bind_loopback(0).await.expect("failed to bind loopback");
    let port = listener.local_addr().unwrap().port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let alias = format!("huskarl-{}", Uuid::new_v4());

    let config = serde_json::json!({
        "alias": alias,
        "client": {
            "client_id": client_id(),
            "client_secret": client_secret(),
            "redirect_uri": redirect_uri,
        },
    });

    let variant = serde_json::json!({
        "client_registration": "static_client",
        "request_type": "plain_http_request",
    });

    let plan = conformance
        .create_plan(plan_name, &config, Some(&variant))
        .await
        .expect("failed to create test plan");

    println!("Created plan {} ({} modules)", plan.id, plan.modules.len(),);

    let issuer = conformance.plan_issuer(&alias);
    let mut failures: Vec<String> = Vec::new();

    for plan_module in &plan.modules {
        let test_name = &plan_module.test_module;

        println!("--- {test_name}");

        let module = conformance
            .create_module_from_plan(&plan.id, test_name)
            .await
            .unwrap_or_else(|e| panic!("failed to create module {test_name}: {e}"));

        println!("    issuer: {}", module.url);

        // Wait for the AS to be ready to receive the RP's requests.
        conformance
            .wait_for_status(
                &module.id,
                &[ModuleStatus::Waiting, ModuleStatus::Finished],
                Duration::from_secs(30),
            )
            .await
            .unwrap_or_else(|e| panic!("module {test_name} did not become ready: {e}"));

        // Fetch metadata while the module is active so the discovery endpoint is live.
        // Use the same well-known path and transformation as drive_auth_code_flow.
        let userinfo_client = AuthorizationServerMetadata::oidc_fetch()
            .issuer(&issuer)
            .http_client(&http_client)
            .call()
            .await
            .ok()
            .and_then(|m| {
                UserInfoClient::builder_from_metadata(&m).map(|b| b.dpop(NoDPoP).build())
            });
        // Await the async builder outside the Option chain.
        let userinfo_client = match userinfo_client {
            Some(fut) => fut.await.ok(),
            None => None,
        };

        // Run the auth code flow. Some modules expect the RP to reject the AS
        // response (bad signature, wrong issuer, etc.) — in those cases the flow
        // will return an Err, which is fine. What matters is the conformance suite's
        // verdict, not whether our flow succeeded or failed.
        let flow_result = run_auth_code_flow_with_listener(
            &http_client,
            &browser,
            &issuer,
            &client_id(),
            client_auth(),
            NoDPoP,
            bon::vec!["openid", "profile", "email"],
            &listener,
            &redirect_uri,
            NoJar,
        )
        .await;

        println!(
            "    flow result: {}",
            flow_result
                .as_ref()
                .map(|_| "ok")
                .unwrap_or_else(|e| e.as_str())
        );

        // Call userinfo if the flow succeeded and the server advertises the endpoint.
        // We pass a dummy expected_sub and ignore errors — the conformance suite
        // only needs to see the HTTP request.
        if let (Ok((token_response, _)), Some(client)) = (&flow_result, &userinfo_client) {
            let _ = client
                .get(&http_client, token_response.access_token(), "_")
                .await;
        }

        let finished = conformance
            .wait_for_status(
                &module.id,
                &[ModuleStatus::Finished],
                Duration::from_secs(30),
            )
            .await
            .unwrap_or_else(|e| panic!("module {test_name} did not finish: {e}"));

        if let Some(msg) = report_module_result(test_name, &finished, flow_result.is_ok()) {
            failures.push(msg);
        }
    }

    println!(
        "{}/{} modules passed",
        plan.modules.len() - failures.len(),
        plan.modules.len()
    );
    failures
}

/// Runs the `oidcc-client-basic-certification-test-plan` with `client_secret_basic` auth.
///
/// Setup required:
///   - Conformance suite running at CONFORMANCE_SUITE_BASE (default: https://localhost.emobix.co.uk:8443)
#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn oidcc_client_basic_certification_test_plan_basic() {
    let failures = run_plan("oidcc-client-basic-certification-test-plan").await;
    assert_no_failures(failures);
}
