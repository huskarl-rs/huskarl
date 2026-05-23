use std::time::Duration;

use huskarl::{
    core::{
        client_auth::{Audience, JwtBearer},
        crypto::signer::AsymmetricJwsSigner as _,
        dpop::DPoP,
        server_metadata::AuthorizationServerMetadata,
    },
    grant::authorization_code::{Jar, NoJar, bind_loopback},
};
use huskarl_conformance::{
    api::{ConformanceClient, ModuleStatus},
    assert_no_failures, base_url, build_browser, build_http_client, call_resource_get, client_id,
    report_module_result, run_auth_code_flow_with_listener,
};
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
use uuid::Uuid;

/// Runs `fapi2-security-profile-final-client-test-plan` with the given variant.
///
/// Generates fresh EC key pairs on each run:
/// - `client_key` — used for `private_key_jwt` client authentication (`JwtBearer`)
/// - `dpop_key`   — used for DPoP sender-constrained tokens
///
/// The client's public JWK is registered with the conformance suite in the plan
/// config so the AS can verify client assertions.
async fn run_fapi2_plan<J: Jar + Clone + 'static>(
    plan_name: &str,
    variant: serde_json::Value,
    make_jar: impl Fn(&PrivateKey) -> J,
) -> Vec<String> {
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

    // Generate fresh key pairs for each test run.
    let client_key = PrivateKey::generate(GenerateAlgorithm::Es256, Some("client-key".to_string()));
    let dpop_key = PrivateKey::generate(GenerateAlgorithm::Es256, Some("dpop-key".to_string()));
    // The conformance suite AS needs a private signing key to issue tokens.
    let server_key = PrivateKey::generate(GenerateAlgorithm::Es256, Some("server-key".to_string()));

    // Extract the public JWK to register with the conformance suite as the client JWKS.
    let client_public_jwk = client_key.public_key_jwk().into_owned();
    // Provide the full private JWK so the simulated AS can sign tokens.
    let server_private_jwk: huskarl::core::jwk::Jwk = server_key.as_private_jwk(None).into();

    let alias = format!("huskarl-fapi2-{}", Uuid::new_v4());

    let config = serde_json::json!({
        "alias": alias,
        "server": {
            "jwks": { "keys": [server_private_jwk] },
        },
        "client": {
            "client_id": client_id(),
            "jwks": { "keys": [client_public_jwk] },
            "redirect_uri": redirect_uri,
            "scope": "openid profile email",
        },
    });

    let plan = conformance
        .create_plan(plan_name, &config, Some(&variant))
        .await
        .expect("failed to create FAPI2 test plan");

    println!(
        "Created plan {plan_name} {} ({} modules)",
        plan.id,
        plan.modules.len(),
    );

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

        conformance
            .wait_for_status(
                &module.id,
                &[ModuleStatus::Waiting, ModuleStatus::Finished],
                Duration::from_secs(30),
            )
            .await
            .unwrap_or_else(|e| panic!("module {test_name} did not become ready: {e}"));

        // Fetch metadata while the module is active; extract userinfo URI for resource calls.
        let userinfo_uri = AuthorizationServerMetadata::oidc_fetch()
            .issuer(&issuer)
            .http_client(&http_client)
            .call()
            .await
            .ok()
            .and_then(|m| m.userinfo_endpoint)
            .map(|e| e.as_uri().clone());

        let client_auth = JwtBearer::builder()
            .signer(client_key.clone())
            .audience(Audience::PreferIssuer)
            .build();

        let dpop = DPoP::builder().signer(dpop_key.clone()).build();

        let jar = make_jar(&client_key);

        let flow_result = run_auth_code_flow_with_listener(
            &http_client,
            &browser,
            &issuer,
            &client_id(),
            client_auth,
            dpop,
            ["openid", "profile", "email"],
            &listener,
            &redirect_uri,
            Some(std::collections::HashSet::from([
                "PS256".to_string(),
                "ES256".to_string(),
                "EdDSA".to_string(),
            ])),
            jar,
        )
        .await;

        println!(
            "    flow result: {}",
            flow_result
                .as_ref()
                .map(|_| "ok")
                .unwrap_or_else(|e| e.as_str())
        );

        if let Ok((_, authorizer)) = &flow_result {
            if let Some(uri) = &userinfo_uri {
                call_resource_get(&http_client, authorizer, uri).await;
            }
            let accounts_uri: http::Uri = format!(
                "{}/open-banking/v1.1/accounts",
                module.url.trim_end_matches('/')
            )
            .parse()
            .expect("invalid accounts URI");
            call_resource_get(&http_client, authorizer, &accounts_uri).await;
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

/// Runs the FAPI 2.0 Security Profile conformance plan (plain_fapi, OIDC client, simple auth request).
///
/// Setup required:
///   - Conformance suite running at CONFORMANCE_SUITE_BASE (default: https://localhost.emobix.co.uk:8443)
///   - Static client registered with client_id from CONFORMANCE_CLIENT_ID (default: "client")
#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_security_profile_plain() {
    let failures = run_fapi2_plan(
        "fapi2-security-profile-final-client-test-plan",
        serde_json::json!({
            "client_auth_type": "private_key_jwt",
            "sender_constrain": "dpop",
            "authorization_request_type": "simple",
            "fapi_client_type": "oidc",
            "fapi_profile": "plain_fapi",
        }),
        |_| NoJar,
    )
    .await;
    assert_no_failures(failures);
}

/// Runs the FAPI 2.0 Message Signing conformance plan (plain_fapi, OIDC client, signed non-repudiation request, plain response).
///
/// Setup required:
///   - Conformance suite running at CONFORMANCE_SUITE_BASE (default: https://localhost.emobix.co.uk:8443)
///   - Static client registered with client_id from CONFORMANCE_CLIENT_ID (default: "client")
#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_plain() {
    let failures = run_fapi2_plan(
        "fapi2-message-signing-final-client-test-plan",
        serde_json::json!({
            "sender_constrain": "dpop",
            "client_auth_type": "private_key_jwt",
            "authorization_request_type": "simple",
            "fapi_request_method": "signed_non_repudiation",
            "fapi_client_type": "oidc",
            "fapi_profile": "plain_fapi",
            "fapi_response_mode": "plain_response",
        }),
        |k| k.clone(),
    )
    .await;
    assert_no_failures(failures);
}
