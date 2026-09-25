use huskarl::{
    core::{
        client_auth::{Audience, ClientAuthentication, ClientSecret, JwtBearer},
        dpop::NoDPoP,
        jwk::{OctKey, SymmetricJwk},
        secrets::{ProvidedSecret, SecretString},
    },
    grant::authorization_code::{Jar, NoJar, ResponseMode},
    registration::{ClientMetadata, ClientRegistration},
    userinfo::UserInfoClient,
};
use huskarl_conformance::{
    assert_no_failures, client_error::ClientError, config::Config, flow::AuthorizationOptions,
    report::AuthorizationAttempt, runner::Runner,
};
use huskarl_crypto_native::{
    asymmetric::signer::{GenerateAlgorithm, PrivateKey},
    symmetric::SymmetricKey,
};

fn client_secret() -> SecretString {
    std::env::var("CONFORMANCE_CLIENT_SECRET")
        .unwrap_or_else(|_| "client-secret".to_string())
        .into()
}

struct Authentication<F> {
    method: &'static str,
    secret: Option<SecretString>,
    public_jwk: Option<huskarl::core::jwk::PublicJwk>,
    signing_alg: Option<&'static str>,
    make: F,
}

fn secret_auth(secret: Option<SecretString>, basic: bool) -> Result<ClientSecret, ClientError> {
    let secret = secret.ok_or_else(|| ClientError::from("client secret omitted"))?;
    Ok(ClientSecret::builder()
        .client_secret(ProvidedSecret::new(secret))
        .prefer_basic_auth(basic)
        .build())
}

/// Drives every module in a conformance plan.
///
/// Fetches metadata per module, runs the auth code flow, calls userinfo if the
/// flow succeeded, then waits for the suite's verdict. Modules that the RP is
/// expected to reject (bad signature, wrong issuer, etc.) will return an `Err`
/// from the flow — that is fine and expected.
///
/// Returns a list of failure descriptions (empty on full success).
async fn run_plan<J: Jar + Clone + 'static>(
    plan_name: &str,
    variant: serde_json::Value,
    response_mode: Option<ResponseMode>,
    jar: J,
    public_jwk: Option<huskarl::core::jwk::PublicJwk>,
) -> Vec<String> {
    run_plan_with_auth(
        plan_name,
        variant,
        response_mode,
        jar,
        public_jwk,
        Authentication {
            method: "client_secret_basic",
            secret: Some(client_secret()),
            public_jwk: None,
            signing_alg: None,
            make: |secret| secret_auth(secret, true),
        },
    )
    .await
}

async fn run_plan_with_auth<J, A>(
    plan_name: &str,
    variant: serde_json::Value,
    response_mode: Option<ResponseMode>,
    jar: J,
    public_jwk: Option<huskarl::core::jwk::PublicJwk>,
    authentication: Authentication<impl Fn(Option<SecretString>) -> Result<A, ClientError>>,
) -> Vec<String>
where
    J: Jar + Clone + 'static,
    A: ClientAuthentication + 'static,
{
    let runner = Runner::new(Config::from_env().expect("invalid conformance configuration"))
        .await
        .expect("failed to initialize runner");
    let dynamic = variant["client_registration"] == "dynamic_client";
    let options = AuthorizationOptions {
        response_mode,
        prefer_pushed_authorization_requests: variant["request_type"] != "request_object",
        ..Default::default()
    };

    let mut config = serde_json::json!({
        "alias": runner.alias,
        "client": {
            "client_id": options.client_id,
            "redirect_uri": runner.client.redirect_uri,
        },
    });

    let public_keys: Vec<_> = public_jwk
        .iter()
        .chain(authentication.public_jwk.iter())
        .cloned()
        .collect();
    if let Some(secret) = &authentication.secret {
        config["client"]["client_secret"] = serde_json::json!(secret);
    }
    if authentication.method == "client_secret_jwt" {
        config["client"]["client_secret_jwt_alg"] = serde_json::json!(authentication.signing_alg);
    }
    if !public_keys.is_empty() {
        config["client"]["jwks"] = serde_json::json!({"keys": public_keys});
    }
    if dynamic {
        config["client"] = serde_json::json!({});
    }

    let mut configured_variant = variant.clone();
    configured_variant["response_type"] = "code".into();
    configured_variant["client_auth_type"] = authentication.method.into();
    if configured_variant.get("response_mode").is_none() {
        configured_variant["response_mode"] = match response_mode {
            Some(ResponseMode::FormPost) => "form_post",
            _ => "default",
        }
        .into();
    }

    runner
        .run(
            plan_name,
            &config,
            &variant,
            async |module, effective, observation| {
                huskarl_conformance::runner::require_configured_variant(
                    effective,
                    &configured_variant,
                )?;
                if module.name == "oidcc-client-test-discovery-openid-config" {
                    observation.preparation = Some(runner.client.discover().await.map(|_| ()));
                    return Ok(());
                }
                if module.name == "oidcc-client-test-discovery-jwks-uri-keys" {
                    // Explicit OIDC makes initial JWKS retrieval fail-fast. This module
                    // finishes at that retrieval; it must not receive an authorization.
                    let options = AuthorizationOptions {
                        oidc: Some(true),
                        ..Default::default()
                    };
                    observation.preparation = Some(
                        runner
                            .client
                            .prepare_authorization(
                                &options,
                                (authentication.make)(authentication.secret.clone())
                                    .map_err(|e| e.to_string())?,
                                NoDPoP,
                                jar.clone(),
                            )
                            .await
                            .map(|_| ()),
                    );
                    return Ok(());
                }
                let metadata = match runner.client.discover().await {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        observation.preparation = Some(Err(error));
                        return Ok(());
                    }
                };
                let mut options = options.clone();
                let auth = if dynamic {
                    let registered = async {
                        let registration = ClientRegistration::builder_from_metadata(&metadata)
                            .map_err(|e| ClientError::capture(&e))?
                            .build();
                        let mut requested = ClientMetadata::builder()
                            .redirect_uris(vec![runner.client.redirect_uri.clone()])
                            .grant_types(vec!["authorization_code".into()])
                            .response_types(vec!["code".into()])
                            .token_endpoint_auth_method(authentication.method)
                            .application_type("native")
                            .scope(options.scopes.clone())
                            .build();
                        if !public_keys.is_empty() {
                            requested.jwks =
                                Some(huskarl::core::jwk::PublicJwks::new(public_keys.clone()));
                        }
                        if public_jwk.is_some() {
                            requested.request_object_signing_alg = Some("RS256".into());
                        }
                        requested.token_endpoint_auth_signing_alg =
                            authentication.signing_alg.map(str::to_owned);
                        let response = registration
                            .register(&runner.client.http_client, &requested)
                            .await
                            .map_err(|e| ClientError::capture(&e))?;
                        if response.client_id.is_empty() {
                            return Err(ClientError::from(
                                "registration returned an empty client ID",
                            ));
                        }
                        Ok((
                            response.client_id,
                            (authentication.make)(response.client_secret)?,
                        ))
                    }
                    .await;
                    observation.registration =
                        Some(registered.as_ref().map(|_| ()).map_err(Clone::clone));
                    match registered {
                        Ok((id, auth)) => {
                            options.client_id = id;
                            auth
                        }
                        Err(_) => return Ok(()),
                    }
                } else {
                    (authentication.make)(authentication.secret.clone())
                        .map_err(|e| e.to_string())?
                };
                let prepared = match runner
                    .client
                    .prepare_authorization_from_metadata(
                        &options,
                        auth,
                        NoDPoP,
                        jar.clone(),
                        metadata,
                    )
                    .await
                {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        observation.preparation = Some(Err(error));
                        return Ok(());
                    }
                };
                // Upstream rotates keys on the second authorization request.
                let attempts = if module.name == "oidcc-client-test-signing-key-rotation" {
                    2
                } else {
                    1
                };
                observation.preparation = Some(Ok(()));
                for _ in 0..attempts {
                    observation.resources.clear();
                    let flow_result = runner.client.authorize_prepared(&prepared).await;

                    observation.authorization =
                        Some(flow_result.as_ref().map(|_| ()).map_err(Clone::clone));
                    if let Ok(flow) = &flow_result
                        && flow.metadata.userinfo_endpoint.is_some()
                    {
                        let result: Result<Option<u16>, ClientError> = async {
                            let subject = flow
                                .complete
                                .id_token
                                .as_ref()
                                .and_then(|t| t.sub.as_deref())
                                .ok_or("validated ID token has no subject")?;
                            let client = UserInfoClient::builder_from_grant(
                                prepared.grant(),
                                &flow.metadata,
                            )
                            .map_err(|e| ClientError::capture(&e))?
                            .build()
                            .await
                            .map_err(|e| ClientError::capture(&e))?;
                            client
                                .get(
                                    &runner.client.http_client,
                                    flow.complete.token_response.access_token(),
                                    subject,
                                )
                                .await
                                .map_err(|e| ClientError::capture(&e))?;
                            Ok(None)
                        }
                        .await;
                        observation.resources.insert("userinfo".into(), result);
                    }

                    observation
                        .authorization_attempts
                        .push(AuthorizationAttempt {
                            authorization: flow_result.as_ref().map(|_| ()).map_err(Clone::clone),
                            resources: observation.resources.clone(),
                        });
                    // A failed first flow cannot establish the cache/session needed by the second.
                    if flow_result.is_err() || observation.resources.values().any(Result::is_err) {
                        break;
                    }
                }
                Ok(())
            },
        )
        .await
        .expect("failed to run conformance plan")
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
    let failures = run_plan(
        "oidcc-client-basic-certification-test-plan",
        serde_json::json!({
            "client_registration": "static_client",
            "request_type": "plain_http_request",
        }),
        None,
        NoJar,
        None,
    )
    .await;
    assert_no_failures(failures);
}

/// Discovery, issuer validation, JWKS retrieval, and signing-key rotation.
#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn oidcc_client_config_certification_test_plan() {
    let failures = run_plan(
        "oidcc-client-config-certification-test-plan",
        serde_json::json!({
            "client_auth_type": "client_secret_basic",
            "client_registration": "static_client",
            "request_type": "plain_http_request",
            "response_mode": "default",
        }),
        None,
        NoJar,
        None,
    )
    .await;
    assert_no_failures(failures);
}

/// Basic OIDC with authorization responses delivered by HTML form POST.
#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn oidcc_client_formpost_basic_certification_test_plan() {
    let failures = run_plan(
        "oidcc-client-formpost-basic-certification-test-plan",
        serde_json::json!({
            "client_registration": "static_client",
            "request_type": "plain_http_request",
        }),
        Some(ResponseMode::FormPost),
        NoJar,
        None,
    )
    .await;
    assert_no_failures(failures);
}

/// OIDC request objects delivered directly in the authorization URL.
#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn oidcc_client_basic_request_object() {
    let key = PrivateKey::generate(
        GenerateAlgorithm::Rs256 {
            modulus_length: 2048,
        },
        Some("request-object-key".into()),
    )
    .unwrap();
    let public_jwk = key.as_private_jwk().public_jwk();
    let failures = run_plan(
        "oidcc-client-basic-certification-test-plan",
        serde_json::json!({
            "client_registration": "static_client",
            "request_type": "request_object",
        }),
        None,
        key,
        Some(public_jwk),
    )
    .await;
    assert_no_failures(failures);
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn oidcc_client_basic_dynamic_registration() {
    assert_no_failures(run_plan(
        "oidcc-client-basic-certification-test-plan",
        serde_json::json!({"client_registration": "dynamic_client", "request_type": "plain_http_request"}),
        None, NoJar, None,
    ).await);
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn oidcc_client_config_dynamic_registration() {
    assert_no_failures(
        run_plan(
            "oidcc-client-config-certification-test-plan",
            serde_json::json!({
                "client_auth_type": "client_secret_basic", "client_registration": "dynamic_client",
                "request_type": "plain_http_request", "response_mode": "default",
            }),
            None,
            NoJar,
            None,
        )
        .await,
    );
}

fn config_auth_variant(method: &str) -> serde_json::Value {
    serde_json::json!({
        "client_auth_type": method,
        "client_registration": "static_client",
        "request_type": "plain_http_request",
        "response_mode": "default",
    })
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn oidcc_client_config_auth_post() {
    assert_no_failures(
        run_plan_with_auth(
            "oidcc-client-config-certification-test-plan",
            config_auth_variant("client_secret_post"),
            None,
            NoJar,
            None,
            Authentication {
                method: "client_secret_post",
                secret: Some(client_secret()),
                public_jwk: None,
                signing_alg: None,
                make: |secret| secret_auth(secret, false),
            },
        )
        .await,
    );
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn oidcc_client_config_auth_secret_jwt() {
    // Fresh 64-byte ASCII secret for HS256; the default test
    // password is too short for HS256. Register exactly the bytes used to sign.
    let secret: SecretString = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
    .into();
    assert_no_failures(
        run_plan_with_auth(
            "oidcc-client-config-certification-test-plan",
            config_auth_variant("client_secret_jwt"),
            None,
            NoJar,
            None,
            Authentication {
                method: "client_secret_jwt",
                secret: Some(secret),
                public_jwk: None,
                signing_alg: Some("HS256"),
                make: |secret: Option<SecretString>| {
                    let secret =
                        secret.ok_or_else(|| ClientError::from("client secret omitted"))?;
                    let key = SymmetricKey::from_jwk(
                        SymmetricJwk::builder()
                            .key(
                                OctKey::builder()
                                    .k(secret.expose_secret().as_bytes().to_vec())
                                    .build(),
                            )
                            .algorithm("HS256")
                            .build(),
                    )
                    .map_err(|e| ClientError::capture(&e))?;
                    Ok(JwtBearer::builder()
                        .signer(key)
                        .audience(Audience::TargetEndpoint)
                        .build())
                },
            },
        )
        .await,
    );
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn oidcc_client_config_auth_private_key_jwt() {
    let key = PrivateKey::generate(
        GenerateAlgorithm::Rs256 {
            modulus_length: 2048,
        },
        Some("client-auth-key".into()),
    )
    .unwrap();
    assert_no_failures(
        run_plan_with_auth(
            "oidcc-client-config-certification-test-plan",
            config_auth_variant("private_key_jwt"),
            None,
            NoJar,
            None,
            Authentication {
                method: "private_key_jwt",
                secret: None,
                public_jwk: Some(key.as_private_jwk().public_jwk()),
                signing_alg: Some("RS256"),
                make: |_| {
                    Ok(JwtBearer::builder()
                        .signer(key.clone())
                        .audience(Audience::TargetEndpoint)
                        .build())
                },
            },
        )
        .await,
    );
}
