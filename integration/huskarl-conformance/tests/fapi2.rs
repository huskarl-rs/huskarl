use huskarl::{
    core::{
        AuthorizationDetail,
        client_auth::{Audience, JwtBearer, NoAuth},
        dpop::{DPoP, NoDPoP},
        secrets::{ProvidedSecret, SecretString},
    },
    grant::authorization_code::{Jar, NoJar, ResponseMode},
    userinfo::UserInfoClient,
};
use huskarl_conformance::{
    assert_no_failures,
    client_error::ClientError,
    config::Config,
    flow::{AuthorizationOptions, FlowContext, PreparedAuthorization, call_resource_get},
    runner::Runner,
};
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
use huskarl_reqwest::{ReqwestClient, mtls::MtlsPem};

/// Runs a FAPI 2.0 client plan with the selected suite variant and client options.
///
/// Generates fresh EC key pairs on each run:
/// - `client_key` — used for `private_key_jwt` client authentication (`JwtBearer`)
/// - `dpop_key`   — used for DPoP sender-constrained tokens
///
/// The client's public JWK is registered with the conformance suite in the plan
/// config so the AS can verify client assertions.
async fn run_fapi2_plan<J: Jar + Clone + 'static>(
    plan_name: &str,
    mut variant: serde_json::Value,
    options: AuthorizationOptions,
    protection: Protection,
    make_jar: impl Fn(&PrivateKey) -> J,
) -> Vec<String> {
    let settings = Config::from_env().expect("invalid conformance configuration");
    let insecure = settings.insecure_tls;
    let timeout = settings.request_timeout;
    let certificate = protection.uses_mtls().then(|| {
        rcgen::generate_simple_self_signed(vec!["huskarl-client.example".into()])
            .expect("failed to generate client certificate")
    });
    let runner = if let Some(material) = &certificate {
        let identity: SecretString = format!(
            "{}{}",
            material.signing_key.serialize_pem(),
            material.cert.pem()
        )
        .into();
        Runner::new_with_mtls(settings, MtlsPem::new(ProvidedSecret::new(identity))).await
    } else {
        Runner::new(settings).await
    }
    .expect("failed to initialize runner");
    // mTLS authentication with DPoP tokens does not require a certificate at resources.
    let resource_http = if protection.mtls_auth() && !protection.mtls_tokens() {
        ReqwestClient::builder()
            .configure_builder(Box::new(move |b| {
                b.danger_accept_invalid_certs(insecure).timeout(timeout)
            }))
            .build()
            .await
            .expect("failed to initialize resource client")
    } else {
        runner.client.http_client.clone()
    };
    variant["client_auth_type"] = protection.auth_variant().into();
    variant["sender_constrain"] = protection.sender_variant().into();

    // Generate fresh key pairs for each test run.
    let client_key =
        PrivateKey::generate(GenerateAlgorithm::Es256, Some("client-key".to_string())).unwrap();
    let dpop_key =
        PrivateKey::generate(GenerateAlgorithm::Es256, Some("dpop-key".to_string())).unwrap();
    // The conformance suite AS needs a private signing key to issue tokens.
    let server_key =
        PrivateKey::generate(GenerateAlgorithm::Es256, Some("server-key".to_string())).unwrap();

    // Extract the public JWK to register with the conformance suite as the client JWKS.
    let client_public_jwk = client_key.as_private_jwk().public_jwk();
    // Provide the full private JWK so the simulated AS can sign tokens.
    let server_private_jwk: huskarl::core::jwk::Jwk = server_key.as_private_jwk().into();

    let mut config = serde_json::json!({
        "alias": runner.alias,
        "server": {
            "jwks": { "keys": [server_private_jwk] },
        },
        "client": {
            "client_id": options.client_id,
            "jwks": { "keys": [client_public_jwk] },
            "redirect_uri": runner.client.redirect_uri,
            "scope": options.scopes.join(" "),
        },
    });

    if let Some(material) = &certificate {
        config["client"]["certificate"] = material.cert.pem().into();
        // The grant selects aliases for all protocol endpoints when mTLS is installed.
        config["client"]["use_mtls_endpoint_aliases"] = true.into();
    }

    if let Some(details) = &options.authorization_details {
        let types: Vec<_> = details.iter().map(|detail| &detail.r#type).collect();
        config["resource"] = serde_json::json!({
            "authorization_details_types_supported": types,
        });
    }

    let mut configured_variant = variant.clone();
    // Security Profile owns these module settings; Message Signing selects them
    // at plan level. Keep module-owned defaults out of the plan creation request.
    if plan_name == "fapi2-security-profile-final-client-test-plan" {
        configured_variant["fapi_request_method"] = "unsigned".into();
        configured_variant["fapi_response_mode"] = "plain_response".into();
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
                let prepared = match protection
                    .prepare(
                        &runner.client,
                        &options,
                        &client_key,
                        &dpop_key,
                        make_jar(&client_key),
                    )
                    .await
                {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        observation.preparation = Some(Err(error));
                        return Ok(());
                    }
                };
                observation.preparation = Some(Ok(()));
                let flow_result = runner.client.authorize_prepared(&prepared).await;

                observation.authorization =
                    Some(flow_result.as_ref().map(|_| ()).map_err(Clone::clone));
                if let Ok(flow) = &flow_result {
                    if options.oidc != Some(false) && flow.metadata.userinfo_endpoint.is_some() {
                        let result: Result<Option<u16>, ClientError> = async {
                            let subject = flow
                                .complete
                                .id_token
                                .as_ref()
                                .and_then(|token| token.sub.as_deref())
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
                                    &resource_http,
                                    flow.complete.token_response.access_token(),
                                    subject,
                                )
                                .await
                                .map_err(|e| ClientError::capture(&e))?;
                            Ok(None)
                        }
                        .await;
                        let rejected = result.is_err();
                        observation.resources.insert("userinfo".into(), result);
                        if rejected {
                            return Ok(());
                        }
                    }
                    let accounts_uri =
                        accounts_uri(&flow.metadata, &module.exposed, protection.mtls_tokens())?;
                    let result =
                        call_resource_get(&resource_http, &flow.authorizer, &accounts_uri).await;
                    observation
                        .resources
                        .insert("accounts".into(), result.map(Some));
                }

                Ok(())
            },
        )
        .await
        .expect("failed to run conformance plan")
}

/// Keep the suite's client type and the actual client's OIDC behavior aligned.
#[derive(Clone, Copy)]
enum ClientType {
    Oidc,
    PlainOAuth,
}

impl ClientType {
    fn variant(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::PlainOAuth => "plain_oauth",
        }
    }

    fn options(self) -> AuthorizationOptions {
        match self {
            Self::Oidc => AuthorizationOptions::default(),
            Self::PlainOAuth => AuthorizationOptions {
                scopes: vec!["accounts".into()],
                oidc: Some(false),
                ..Default::default()
            },
        }
    }
}

async fn security_profile(
    client_type: ClientType,
    request_type: RequestType,
    protection: Protection,
) {
    let failures = run_fapi2_plan(
        "fapi2-security-profile-final-client-test-plan",
        serde_json::json!({
            "authorization_request_type": request_type.variant(),
            "fapi_client_type": client_type.variant(),
            "fapi_profile": "plain_fapi",
        }),
        request_type.options(client_type),
        protection,
        |_| NoJar,
    )
    .await;
    assert_no_failures(failures);
}

async fn message_signing(
    client_type: ClientType,
    jarm: bool,
    request_type: RequestType,
    protection: Protection,
) {
    let mut options = request_type.options(client_type);
    options.response_mode = jarm.then_some(ResponseMode::QueryJwt);
    let failures = run_fapi2_plan(
        "fapi2-message-signing-final-client-test-plan",
        serde_json::json!({
            "authorization_request_type": request_type.variant(),
            "fapi_request_method": "signed_non_repudiation",
            "fapi_client_type": client_type.variant(),
            "fapi_profile": "plain_fapi",
            "fapi_response_mode": if jarm { "jarm" } else { "plain_response" },
        }),
        options,
        protection,
        |k| k.clone(),
    )
    .await;
    assert_no_failures(failures);
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_security_profile_plain() {
    security_profile(ClientType::Oidc, RequestType::Simple, Protection::JwtDpop).await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_plain() {
    message_signing(
        ClientType::Oidc,
        false,
        RequestType::Simple,
        Protection::JwtDpop,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_jarm() {
    message_signing(
        ClientType::Oidc,
        true,
        RequestType::Simple,
        Protection::JwtDpop,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_security_profile_plain_oauth() {
    security_profile(
        ClientType::PlainOAuth,
        RequestType::Simple,
        Protection::JwtDpop,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_plain_oauth() {
    message_signing(
        ClientType::PlainOAuth,
        false,
        RequestType::Simple,
        Protection::JwtDpop,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_jarm_oauth() {
    message_signing(
        ClientType::PlainOAuth,
        true,
        RequestType::Simple,
        Protection::JwtDpop,
    )
    .await;
}

/// Keep the suite variant, requested details, and resource metadata aligned.
#[derive(Clone, Copy)]
enum RequestType {
    Simple,
    Rar,
}

impl RequestType {
    fn variant(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Rar => "rar",
        }
    }

    fn options(self, client_type: ClientType) -> AuthorizationOptions {
        let mut options = client_type.options();
        if matches!(self, Self::Rar) {
            options.authorization_details = Some(vec![
                AuthorizationDetail::builder("account_information")
                    .with(
                        "actions",
                        serde_json::json!(["list_accounts", "read_balances"]),
                    )
                    .build(),
            ]);
        }
        options
    }
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_security_profile_rar() {
    security_profile(ClientType::Oidc, RequestType::Rar, Protection::JwtDpop).await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_jarm_rar() {
    message_signing(
        ClientType::Oidc,
        true,
        RequestType::Rar,
        Protection::JwtDpop,
    )
    .await;
}

/// Client authentication and token sender-constraining are independent choices.
#[derive(Clone, Copy)]
enum Protection {
    JwtDpop,
    JwtMtls,
    MtlsDpop,
    MtlsMtls,
}

impl Protection {
    fn mtls_auth(self) -> bool {
        matches!(self, Self::MtlsDpop | Self::MtlsMtls)
    }
    fn mtls_tokens(self) -> bool {
        matches!(self, Self::JwtMtls | Self::MtlsMtls)
    }
    fn uses_mtls(self) -> bool {
        self.mtls_auth() || self.mtls_tokens()
    }
    fn auth_variant(self) -> &'static str {
        if self.mtls_auth() {
            "mtls"
        } else {
            "private_key_jwt"
        }
    }
    fn sender_variant(self) -> &'static str {
        if self.mtls_tokens() { "mtls" } else { "dpop" }
    }

    async fn prepare<J: Jar + 'static>(
        self,
        client: &FlowContext,
        options: &AuthorizationOptions,
        client_key: &PrivateKey,
        dpop_key: &PrivateKey,
        jar: J,
    ) -> Result<PreparedAuthorization, ClientError> {
        let jwt = JwtBearer::builder()
            .signer(client_key.clone())
            .audience(Audience::Issuer)
            .build();
        let dpop = DPoP::builder().signer(dpop_key.clone()).build();
        match self {
            Self::JwtDpop => client.prepare_authorization(options, jwt, dpop, jar).await,
            Self::JwtMtls => {
                client
                    .prepare_authorization(options, jwt, NoDPoP, jar)
                    .await
            }
            Self::MtlsDpop => {
                client
                    .prepare_authorization(options, NoAuth, dpop, jar)
                    .await
            }
            Self::MtlsMtls => {
                client
                    .prepare_authorization(options, NoAuth, NoDPoP, jar)
                    .await
            }
        }
    }
}

/// Validate certificate-bound routing without reconstructing the resource URL.
fn accounts_uri(
    metadata: &huskarl::core::server_metadata::AuthorizationServerMetadata,
    exposed: &huskarl_conformance::api::ModuleEndpoints,
    mtls_tokens: bool,
) -> Result<http::Uri, huskarl_conformance::api::Error> {
    let token = if mtls_tokens {
        Some(
            metadata
                .mtls_endpoint_aliases
                .as_ref()
                .and_then(|aliases| aliases.token_endpoint.as_ref())
                .ok_or("suite discovery omitted the mTLS token endpoint alias")?,
        )
    } else {
        None
    };
    exposed.accounts_uri(token)
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_security_profile_private_key_jwt_mtls() {
    security_profile(ClientType::Oidc, RequestType::Simple, Protection::JwtMtls).await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_security_profile_mtls_dpop() {
    security_profile(ClientType::Oidc, RequestType::Simple, Protection::MtlsDpop).await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_security_profile_mtls_mtls() {
    security_profile(ClientType::Oidc, RequestType::Simple, Protection::MtlsMtls).await;
}

#[test]
fn accounts_routing_uses_discovered_certificate_endpoint_only_for_bound_tokens() {
    let mut metadata: huskarl::core::server_metadata::AuthorizationServerMetadata =
        serde_json::from_value(serde_json::json!({
            "issuer": "https://suite.example/test/a/plan/",
            "token_endpoint": "https://suite.example/test/a/plan/token",
            "response_types_supported": ["code"],
            "mtls_endpoint_aliases": {
                "token_endpoint": "https://certs.example:9444/test-mtls/a/plan/token"
            }
        }))
        .unwrap();
    let mut exposed = huskarl_conformance::api::ModuleEndpoints {
        issuer: None,
        accounts_endpoint: Some("https://certs.example:9444/custom/resource?version=2".into()),
    };
    assert_eq!(
        accounts_uri(&metadata, &exposed, true).unwrap().to_string(),
        "https://certs.example:9444/custom/resource?version=2"
    );
    exposed.accounts_endpoint = Some("https://suite.example/custom/accounts".into());
    assert!(accounts_uri(&metadata, &exposed, true).is_err());
    assert_eq!(
        accounts_uri(&metadata, &exposed, false)
            .unwrap()
            .to_string(),
        "https://suite.example/custom/accounts"
    );
    metadata.mtls_endpoint_aliases = None;
    assert!(accounts_uri(&metadata, &exposed, true).is_err());
    assert!(accounts_uri(&metadata, &exposed, false).is_ok());
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_plain_private_key_jwt_mtls() {
    message_signing(
        ClientType::Oidc,
        false,
        RequestType::Simple,
        Protection::JwtMtls,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_plain_private_key_jwt_mtls_oauth() {
    message_signing(
        ClientType::PlainOAuth,
        false,
        RequestType::Simple,
        Protection::JwtMtls,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_plain_mtls_dpop() {
    message_signing(
        ClientType::Oidc,
        false,
        RequestType::Simple,
        Protection::MtlsDpop,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_plain_mtls_dpop_oauth() {
    message_signing(
        ClientType::PlainOAuth,
        false,
        RequestType::Simple,
        Protection::MtlsDpop,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_plain_mtls_mtls() {
    message_signing(
        ClientType::Oidc,
        false,
        RequestType::Simple,
        Protection::MtlsMtls,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_plain_mtls_mtls_oauth() {
    message_signing(
        ClientType::PlainOAuth,
        false,
        RequestType::Simple,
        Protection::MtlsMtls,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_jarm_private_key_jwt_mtls() {
    message_signing(
        ClientType::Oidc,
        true,
        RequestType::Simple,
        Protection::JwtMtls,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_jarm_private_key_jwt_mtls_oauth() {
    message_signing(
        ClientType::PlainOAuth,
        true,
        RequestType::Simple,
        Protection::JwtMtls,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_jarm_mtls_dpop() {
    message_signing(
        ClientType::Oidc,
        true,
        RequestType::Simple,
        Protection::MtlsDpop,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_jarm_mtls_dpop_oauth() {
    message_signing(
        ClientType::PlainOAuth,
        true,
        RequestType::Simple,
        Protection::MtlsDpop,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_jarm_mtls_mtls() {
    message_signing(
        ClientType::Oidc,
        true,
        RequestType::Simple,
        Protection::MtlsMtls,
    )
    .await;
}

#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_message_signing_jarm_mtls_mtls_oauth() {
    message_signing(
        ClientType::PlainOAuth,
        true,
        RequestType::Simple,
        Protection::MtlsMtls,
    )
    .await;
}
