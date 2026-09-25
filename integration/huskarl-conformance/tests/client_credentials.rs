use std::sync::Arc;

use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache, NoSource},
    core::{
        EndpointUrl,
        client_auth::{Audience, JwtBearer},
        dpop::DPoP,
        http::{HttpClient, Idempotency},
    },
    grant::{
        client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
        core::OAuth2ExchangeGrant,
    },
};
use huskarl_conformance::{
    assert_no_failures, client_error::ClientError, config::Config, flow::call_resource_get,
    runner::Runner,
};
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

/// The suite's token-only profile omits `response_types_supported`, required by
/// Huskarl's general metadata type. Decode only this grant's discovery inputs;
/// this driver tests the grant, not general metadata conformance.
#[derive(serde::Deserialize)]
struct ClientCredentialsMetadata {
    issuer: String,
    token_endpoint: EndpointUrl,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl ClientCredentialsMetadata {
    fn decode(body: &[u8], issuer: &str) -> Result<Self, ClientError> {
        let metadata: Self = serde_json::from_slice(body)
            .map_err(|_| ClientError::from("invalid client-credentials discovery document"))?;
        if metadata.issuer != issuer {
            return Err(ClientError {
                message: "client-credentials discovery issuer mismatch".into(),
                rejection: Some(huskarl_conformance::client_error::Rejection::DiscoveryIssuer),
            });
        }
        Ok(metadata)
    }

    async fn discover(
        client: &huskarl_conformance::flow::FlowContext,
    ) -> Result<Self, ClientError> {
        let uri = format!(
            "{}/.well-known/openid-configuration",
            client.issuer.trim_end_matches('/')
        );
        let request = http::Request::get(uri)
            .body(bytes::Bytes::new())
            .map_err(|_| ClientError::from("invalid discovery URL"))?;
        let response = client
            .http_client
            .execute(request, Idempotency::Idempotent)
            .await
            .map_err(|e| ClientError::capture(&e))?;
        if response.status != http::StatusCode::OK {
            return Err(ClientError::from(format!(
                "client-credentials discovery returned HTTP {}",
                response.status
            )));
        }
        Self::decode(&response.body, &client.issuer)
    }
}

#[test]
fn token_only_discovery_requires_exact_issuer_and_valid_token_endpoint() {
    let issuer = "https://suite.example/plan/";
    let mut metadata = serde_json::json!({
        "issuer": issuer,
        "token_endpoint": "https://suite.example/plan/token",
        "grant_types_supported": ["client_credentials"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
    });
    assert!(
        ClientCredentialsMetadata::decode(&serde_json::to_vec(&metadata).unwrap(), issuer).is_ok()
    );
    metadata["issuer"] = "https://suite.example/plan".into();
    assert_eq!(
        ClientCredentialsMetadata::decode(&serde_json::to_vec(&metadata).unwrap(), issuer)
            .err()
            .unwrap()
            .rejection,
        Some(huskarl_conformance::client_error::Rejection::DiscoveryIssuer)
    );
    metadata["issuer"] = issuer.into();
    metadata["token_endpoint"] = "/token".into();
    assert!(
        ClientCredentialsMetadata::decode(&serde_json::to_vec(&metadata).unwrap(), issuer).is_err()
    );
    metadata.as_object_mut().unwrap().remove("token_endpoint");
    assert!(
        ClientCredentialsMetadata::decode(&serde_json::to_vec(&metadata).unwrap(), issuer).is_err()
    );
}

/// Acquire and use a token directly, with no authorization or UserInfo requests.
#[cfg_attr(
    not(feature = "conformance-suite-tests"),
    ignore = "requires conformance suite (run with --features conformance-suite-tests)"
)]
#[tokio::test]
async fn fapi2_client_credentials_private_key_jwt_dpop() {
    let runner = Runner::new(Config::from_env().expect("invalid conformance configuration"))
        .await
        .expect("failed to initialize runner");
    let key = PrivateKey::generate(GenerateAlgorithm::Es256, Some("client-key".into())).unwrap();
    let dpop_key = PrivateKey::generate(GenerateAlgorithm::Es256, Some("dpop-key".into())).unwrap();
    let server_key =
        PrivateKey::generate(GenerateAlgorithm::Es256, Some("server-key".into())).unwrap();
    let server_jwk: huskarl::core::jwk::Jwk = server_key.as_private_jwk().into();
    let client_id = huskarl_conformance::client_id();
    let config = serde_json::json!({
        "alias": runner.alias,
        "server": {"jwks": {"keys": [server_jwk]}},
        "client": {
            "client_id": client_id,
            "jwks": {"keys": [key.as_private_jwk().public_jwk()]},
            "scope": "accounts",
        },
    });
    let variant = serde_json::json!({
        "client_auth_type": "private_key_jwt",
        "sender_constrain": "dpop",
        "authorization_request_type": "simple",
        "fapi_profile": "fapi_client_credentials_grant",
        // The suite's plan naming still reads client type for this profile.
        "fapi_client_type": "plain_oauth",
    });
    let mut configured_variant = variant.clone();
    // These are module-owned defaults: recognize them locally, but do not send
    // them in plan creation (the suite rejects user-supplied values for them).
    configured_variant["fapi_request_method"] = "unsigned".into();
    configured_variant["fapi_response_mode"] = "plain_response".into();
    let failures = runner
        .run(
            "fapi2-security-profile-final-client-test-plan",
            &config,
            &variant,
            async |module, effective, observation| {
                huskarl_conformance::runner::require_configured_variant(
                    effective,
                    &configured_variant,
                )?;
                let prepared = async {
                    let metadata = ClientCredentialsMetadata::discover(&runner.client).await?;
                    let grant = ClientCredentialsGrant::builder()
                        .issuer(metadata.issuer)
                        .token_endpoint(metadata.token_endpoint)
                        .maybe_token_endpoint_auth_methods_supported(
                            metadata.token_endpoint_auth_methods_supported,
                        )
                        .client_id(&client_id)
                        .http_client(runner.client.http_client.clone())
                        .client_auth(
                            JwtBearer::builder()
                                .signer(key.clone())
                                .audience(Audience::Issuer)
                                .build(),
                        )
                        .dpop(DPoP::builder().signer(dpop_key.clone()).build())
                        .build();
                    Ok::<_, ClientError>(grant)
                }
                .await;
                observation.preparation = Some(prepared.as_ref().map(|_| ()).map_err(Clone::clone));
                let Ok(grant) = prepared else { return Ok(()) };
                let token = grant
                    .exchange(
                        ClientCredentialsGrantParameters::builder()
                            .scope(vec!["accounts".into()])
                            .build(),
                    )
                    .await
                    .map_err(|e| ClientError::capture(&e));
                observation.token_exchange = Some(token.as_ref().map(|_| ()).map_err(Clone::clone));
                let Ok(token) = token else { return Ok(()) };
                let source = Arc::new(
                    GrantTokenSource::builder()
                        .grant(grant)
                        .grant_parameters(NoSource)
                        .refresh_store(InMemoryRefreshTokenStore::default())
                        .build(),
                );
                source.prime(token).await?;
                let authorizer = HttpAuthorizer::builder()
                    .cache(InMemoryTokenCache::builder().source(source).build())
                    .build();
                let uri = module.exposed.accounts_uri(None)?;
                observation.resources.insert(
                    "accounts".into(),
                    call_resource_get(&runner.client.http_client, &authorizer, &uri)
                        .await
                        .map(Some),
                );
                Ok(())
            },
        )
        .await
        .expect("failed to run client-credentials plan");
    assert_no_failures(failures);
}
