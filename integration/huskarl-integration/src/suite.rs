//! Generic flow bodies shared across providers.

use std::{collections::HashMap, sync::Arc};

use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use http::Method;
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache},
    core::{
        client_auth::{Audience, ClientAuthentication, ClientSecret, JwtBearer},
        crypto::verifier::JwsVerifierFactory,
        dpop::DPoP,
        jwk::{JwksSource, PublicJwk},
        jwt::parse_compact_jws,
        secrets::{ProvidedSecret, SecretString},
        server_metadata::AuthorizationServerMetadata,
    },
    grant::{
        authorization_code::{AuthorizationCodeGrant, StartInput, StartOutput, bind_loopback},
        client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
        core::OAuth2ExchangeGrant,
        device_authorization::{self, DeviceAuthorizationGrant, PollResult},
        refresh::{RefreshGrant, RefreshGrantParameters},
    },
    token::id_token::IdTokenValidator,
};
use huskarl_crypto_native::{
    NativeVerifierPlatform,
    asymmetric::signer::{GenerateAlgorithm, PrivateKey},
};
use huskarl_reqwest::{ReqwestClient, mtls::MtlsPem};
use huskarl_resource_server::{
    core::jwt::validator::ClaimCheck,
    validator::{custom::CustomValidator, introspection::IntrospectionValidator},
};
use huskarl_testkit::{ClientSpec, Features, ProvisionedClient, TestProvider, Transport};

pub const AUDIENCE: &str = "huskarl-rs";

fn http_client() -> ReqwestClient {
    reqwest::Client::new().into()
}

fn test_request() -> (Method, http::Uri) {
    (Method::GET, "https://test".parse().expect("valid test uri"))
}

async fn fetch_metadata(
    provider: &dyn TestProvider,
    http: &ReqwestClient,
    transport: Transport,
) -> AuthorizationServerMetadata {
    if provider.uses_oidc_discovery() {
        return AuthorizationServerMetadata::oidc_fetch()
            .http_client(http)
            .issuer(provider.issuer(transport))
            .call()
            .await
            .expect("fetch OIDC server metadata");
    }
    AuthorizationServerMetadata::fetch()
        .http_client(http)
        .issuer(provider.issuer(transport))
        .call()
        .await
        .expect("fetch server metadata")
}

async fn provision_with_secret(
    provider: &dyn TestProvider,
    spec: ClientSpec,
) -> (ProvisionedClient, SecretString) {
    let client = provider
        .provision_client(spec)
        .await
        .expect("provision client");
    let secret = client
        .secret
        .clone()
        .expect("confidential client has a secret");
    (client, secret)
}

/// Validates tokens locally by JWKS, requiring `audience`.
async fn jwks_validator(
    metadata: &AuthorizationServerMetadata,
    http: &ReqwestClient,
    audience: &str,
) -> CustomValidator {
    CustomValidator::builder_from_metadata(metadata)
        .iss(metadata.issuer.clone())
        .aud(ClaimCheck::required_value(audience))
        .jws_verifier_factory(Arc::new(
            JwksSource::builder().http_client(http.clone()).build(),
        ))
        .build()
        .await
        .expect("create validator")
}

/// Asserts `validator` accepts `headers` for the canonical [`test_request`].
async fn assert_accepted(
    validator: &CustomValidator,
    headers: &http::HeaderMap,
    client_cert_der: Option<&[u8]>,
) {
    let (method, uri) = test_request();
    assert!(
        validator
            .validate_request(headers, &method, &uri, client_cert_der)
            .await
            .outcome
            .unwrap()
            .is_some()
    );
}

/// Builds an authorizer over a client-credentials grant; `dpop` sender-constrains it.
fn client_credentials_authorizer(
    metadata: &AuthorizationServerMetadata,
    http: &ReqwestClient,
    client_id: &str,
    client_auth: impl ClientAuthentication + 'static,
    dpop: Option<DPoP>,
) -> HttpAuthorizer {
    let grant = ClientCredentialsGrant::builder_from_metadata(metadata)
        .client_id(client_id)
        .http_client(http.clone())
        .client_auth(client_auth)
        .maybe_dpop(dpop)
        .build();

    HttpAuthorizer::builder()
        .cache(
            InMemoryTokenCache::builder()
                .source(
                    GrantTokenSource::builder()
                        .grant(grant)
                        .grant_parameters(ClientCredentialsGrantParameters::new())
                        .refresh_store(InMemoryRefreshTokenStore::default())
                        .build(),
                )
                .build(),
        )
        .build()
}

/// Client credentials grant validated by local JWKS; DPoP/private_key_jwt variants.
pub async fn client_credentials_flow(provider: &dyn TestProvider, features: Features) {
    let client_assertion_key = features.contains(Features::PRIVATE_KEY_JWT).then(|| {
        PrivateKey::generate(GenerateAlgorithm::Es256, Some("client-key".to_owned()))
            .expect("generate private_key_jwt key")
    });

    let spec = ClientSpec::builder()
        .features(features)
        .audience(AUDIENCE)
        .maybe_signing_jwk(
            client_assertion_key
                .as_ref()
                .map(|k| k.as_private_jwk().public_jwk()),
        )
        .build();
    let (client, secret) = provision_with_secret(provider, spec).await;

    let http = http_client();
    let metadata = fetch_metadata(provider, &http, Transport::Plain).await;
    let validator = jwks_validator(&metadata, &http, AUDIENCE).await;

    let dpop = features.contains(Features::DPOP).then(|| {
        let key = PrivateKey::generate(GenerateAlgorithm::Es256, Some("dpop-key".to_owned()))
            .expect("generate DPoP key");
        DPoP::builder().signer(key).build()
    });

    let client_auth: Arc<dyn ClientAuthentication> = match client_assertion_key {
        Some(key) => Arc::new(
            JwtBearer::builder()
                .signer(key)
                .audience(Audience::Issuer)
                .build(),
        ),
        None => Arc::new(ClientSecret::new(ProvidedSecret::new(secret))),
    };

    let authorizer =
        client_credentials_authorizer(&metadata, &http, &client.client_id, client_auth, dpop);

    let (request_method, request_uri) = test_request();
    let headers = authorizer
        .get_headers(&request_method, &request_uri)
        .await
        .unwrap();

    // Guard against a false green: an unbound Bearer token would still validate.
    let auth = headers
        .get(http::header::AUTHORIZATION)
        .expect("authorization header")
        .to_str()
        .expect("ascii authorization header");
    if features.contains(Features::DPOP) {
        assert!(
            auth.starts_with("DPoP "),
            "DPoP variant: expected a DPoP-scheme Authorization header, got {auth:?}"
        );
        assert!(
            headers.contains_key("dpop"),
            "DPoP variant: expected a DPoP proof header on the request"
        );
    } else {
        assert!(
            auth.starts_with("Bearer "),
            "plain variant: expected a Bearer Authorization header, got {auth:?}"
        );
    }

    assert_accepted(&validator, &headers, None).await;
}

/// Bootstrap a refresh token via client credentials, then exchange it for a fresh token.
pub async fn refresh_flow(provider: &dyn TestProvider, features: Features) {
    let spec = ClientSpec::builder()
        .features(features)
        .audience(AUDIENCE)
        .build();
    let (client, secret) = provision_with_secret(provider, spec).await;

    let http = http_client();
    let metadata = fetch_metadata(provider, &http, Transport::Plain).await;
    let validator = jwks_validator(&metadata, &http, AUDIENCE).await;

    let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
        .client_id(&client.client_id)
        .http_client(http.clone())
        .client_auth(ClientSecret::new(ProvidedSecret::new(secret)))
        .build();

    let initial = grant
        .exchange(ClientCredentialsGrantParameters::new())
        .await
        .expect("initial client-credentials exchange");
    let refresh_token = initial
        .refresh_token()
        .expect("AS issued a refresh token")
        .clone();

    let refresh_grant = grant.to_refresh_grant();
    let refreshed = refresh_grant
        .exchange(RefreshGrantParameters::refresh_token(refresh_token))
        .await
        .expect("refresh-token exchange");

    // Refresh must mint a new token, not echo the bootstrap one.
    assert_ne!(
        initial
            .access_token()
            .expose_header_value()
            .expect("initial header value"),
        refreshed
            .access_token()
            .expose_header_value()
            .expect("refreshed header value"),
        "refresh should mint a new access token"
    );

    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        refreshed
            .access_token()
            .expose_header_value()
            .expect("authorization header value"),
    );
    assert_accepted(&validator, &headers, None).await;
}

/// Client credentials grant validated via token introspection.
pub async fn introspection_flow(provider: &dyn TestProvider, features: Features) {
    let spec = ClientSpec::builder()
        .features(features)
        .audience(AUDIENCE)
        .build();
    let (client, secret) = provision_with_secret(provider, spec).await;

    let issuer = provider.issuer(Transport::Plain);
    let http = http_client();
    let metadata = fetch_metadata(provider, &http, Transport::Plain).await;

    let authorizer = client_credentials_authorizer(
        &metadata,
        &http,
        &client.client_id,
        ClientSecret::new(ProvidedSecret::new(secret.clone())),
        None,
    );

    let (request_method, request_uri) = test_request();
    let headers = authorizer
        .get_headers(&request_method, &request_uri)
        .await
        .expect("get headers");

    let introspection_endpoint = metadata
        .introspection_endpoint
        .expect("provider should expose introspection_endpoint in OIDC metadata");

    let validator = IntrospectionValidator::builder()
        .with_claims::<HashMap<String, serde_json::Value>>()
        .client_id(&client.client_id)
        .issuer(&issuer)
        .introspection_endpoint(introspection_endpoint)
        .aud(ClaimCheck::required_value(AUDIENCE))
        .client_auth(ClientSecret::new(ProvidedSecret::new(secret)))
        .http_client(http.clone())
        .build()
        .await
        .expect("create introspection validator");

    let validated = validator
        .validate_request(&headers, &request_method, &request_uri, None)
        .await
        .outcome
        .expect("introspection should succeed")
        .expect("token should be present and active");
    assert!(
        validated.sub.is_some(),
        "expected subject to be present, got None"
    );
    assert_eq!(validated.iss.as_deref(), Some(issuer.as_str()));
    assert!(
        validated.aud.contains(&AUDIENCE.to_owned()),
        "expected audience to contain '{AUDIENCE}', got {:?}",
        validated.aud
    );
    assert!(validated.introspection_jwt.is_none());
}

/// Authorization code grant with PKCE driven headlessly; PAR/JAR variants.
pub async fn auth_code_flow(provider: &dyn TestProvider, features: Features) {
    let (listener, redirect_uri) = match provider.auth_code_redirect_uri(features) {
        Some(uri) => {
            let port = redirect_uri_port(&uri).expect("port in fixed redirect uri");
            let listener = bind_loopback(port).await.expect("bind fixed loopback port");
            (listener, uri)
        }
        None => {
            let listener = bind_loopback(0).await.expect("bind loopback");
            let port = listener.local_addr().expect("local addr").port();
            (listener, format!("http://127.0.0.1:{port}/callback"))
        }
    };

    let bound_key = features.contains(Features::OPENID_KEY_BINDING);
    let proof_key = bound_key.then(|| {
        PrivateKey::generate(GenerateAlgorithm::Es256, None).expect("generate binding key")
    });
    let expected_jkt = proof_key
        .as_ref()
        .map(|key| key.as_private_jwk().public_jwk().thumbprint());
    let dpop = proof_key.map(|key| DPoP::builder().signer(key).build());

    let jar_key = features.contains(Features::JAR).then(|| {
        PrivateKey::generate(GenerateAlgorithm::Es256, Some("jar-key".to_owned()))
            .expect("generate JAR key")
    });

    let spec = ClientSpec::builder()
        .features(features)
        .redirect_uris(vec![redirect_uri.clone()])
        .maybe_signing_jwk(jar_key.as_ref().map(|k| k.as_private_jwk().public_jwk()))
        .build();
    let (client, secret) = provision_with_secret(provider, spec).await;

    let http = http_client();
    let metadata = AuthorizationServerMetadata::oidc_fetch()
        .http_client(&http)
        .issuer(provider.issuer(Transport::Plain))
        .call()
        .await
        .expect("fetch OIDC server metadata");

    let grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
        .expect("server advertises an authorization endpoint")
        .client_id(&client.client_id)
        .http_client(http.clone())
        .client_auth(ClientSecret::new(ProvidedSecret::new(secret)))
        .redirect_uri(&redirect_uri)
        // jws_verifier_factory defaults to a JwksSource wired from http_client.
        .maybe_jar(jar_key)
        .maybe_dpop(dpop)
        // Knob defaults to true, so force off explicitly for the non-PAR variants.
        .prefer_pushed_authorization_requests(features.contains(Features::PAR))
        .build()
        .await
        .expect("build auth-code grant");

    let StartOutput {
        authorization_url,
        pending_state,
        ..
    } = grant
        .start(StartInput::scope(if bound_key {
            bon::vec!["openid", "bound_key", "offline_access"]
        } else {
            bon::vec!["openid"]
        }))
        .await
        .expect("start auth-code flow");

    assert_eq!(pending_state.openid_bound_key_requested, bound_key);
    assert_eq!(pending_state.dpop_jkt, expected_jkt);
    let authorization_url = authorization_url.to_string();

    // Guard against a false green: assert each variant changed the wire shape.
    if features.contains(Features::PAR) {
        assert!(
            authorization_url.contains("request_uri="),
            "PAR variant: authorization_url should carry a request_uri handle, got {authorization_url}"
        );
    } else if features.contains(Features::JAR) {
        assert!(
            authorization_url.contains("request="),
            "JAR variant: authorization_url should carry a signed request object, got {authorization_url}"
        );
        assert!(
            !authorization_url.contains("code_challenge="),
            "JAR variant: request params should be inside the request object, not inline, got {authorization_url}"
        );
    } else {
        assert!(
            !authorization_url.contains("request_uri="),
            "non-PAR variant: authorization_url should not use PAR, got {authorization_url}"
        );
        assert!(
            authorization_url.contains("code_challenge="),
            "non-PAR variant: authorization_url should carry inline PKCE params, got {authorization_url}"
        );
    }

    // Run login and loopback completion concurrently so a login error surfaces
    // immediately instead of blocking on the accept loop until timeout.
    let auth_fut = provider.authenticate(&authorization_url);
    let complete_fut = grant.complete_on_loopback(&listener, &pending_state, None);
    tokio::pin!(auth_fut, complete_fut);

    let token_and_id = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::select! {
            auth = &mut auth_fut => {
                auth.expect("drive login");
                (&mut complete_fut).await
            }
            done = &mut complete_fut => done,
        }
    })
    .await
    .expect("auth-code flow timed out — login likely did not reach the loopback callback");
    let completed = token_and_id.expect("complete auth-code flow");
    if let Some(expected_jkt) = expected_jkt {
        // Completion already validated the initial ID token; the helper also
        // checks its raw wire shape, since the typed confirmation claim does not
        // expose jwk.
        assert_bound_refreshes(
            provider,
            &metadata,
            &http,
            &client.client_id,
            grant.to_refresh_grant(),
            completed.token_response.clone(),
            &expected_jkt,
        )
        .await;
    }
    let id_token = completed.id_token;

    let id_token = id_token.expect("id_token present for the openid scope");
    assert!(
        id_token.aud.contains(&client.client_id),
        "id_token aud {:?} should contain the client_id {}",
        id_token.aud,
        client.client_id
    );
    assert!(id_token.sub.is_some(), "id_token should carry a subject");
}

/// Device authorization with a pending poll, user approval, and bound refresh.
pub async fn device_flow(provider: &dyn TestProvider, features: Features) {
    let (client, secret) =
        provision_with_secret(provider, ClientSpec::builder().features(features).build()).await;
    let http = http_client();
    let metadata = fetch_metadata(provider, &http, Transport::Plain).await;
    let key =
        PrivateKey::generate(GenerateAlgorithm::Es256, None).expect("generate device binding key");
    let expected_jkt = key.as_private_jwk().public_jwk().thumbprint();
    let grant = DeviceAuthorizationGrant::builder_from_metadata(&metadata)
        .expect("device authorization endpoint")
        .client_id(&client.client_id)
        .http_client(http.clone())
        .client_auth(ClientSecret::new(ProvidedSecret::new(secret)))
        .dpop(DPoP::builder().signer(key).build())
        .build();
    let started = grant
        .start(device_authorization::StartInput::scope(bon::vec![
            "openid",
            "bound_key",
            "offline_access"
        ]))
        .await
        .expect("start device authorization");
    assert!(started.pending_state.openid_bound_key_requested);
    assert_eq!(
        started.pending_state.dpop_jkt.as_deref(),
        Some(expected_jkt.as_str())
    );
    let persisted = serde_json::to_vec(&started.pending_state).expect("serialize device state");
    let mut pending = serde_json::from_slice::<device_authorization::PendingState>(&persisted)
        .expect("restore device state");
    let response = tokio::time::timeout(std::time::Duration::from_secs(45), async {
        tokio::time::sleep(std::time::Duration::from_secs(pending.interval_secs.into())).await;
        assert!(matches!(
            grant
                .poll(&mut pending, None)
                .await
                .expect("poll before approval"),
            PollResult::Pending
        ));
        provider
            .approve_device(&started.verification_uri, &started.user_code)
            .await
            .expect("approve device");
        grant
            .poll_to_completion(&mut pending, None)
            .await
            .expect("complete device authorization")
    })
    .await
    .expect("device flow timed out");
    // The device grant exposes the raw ID token. Validation here is an explicit
    // interoperability check, not automatic device-grant behavior.
    assert_bound_refreshes(
        provider,
        &metadata,
        &http,
        &client.client_id,
        grant.to_refresh_grant(),
        response,
        &expected_jkt,
    )
    .await;
}

async fn assert_bound_refreshes(
    provider: &dyn TestProvider,
    metadata: &AuthorizationServerMetadata,
    http: &ReqwestClient,
    client_id: &str,
    refresh_grant: RefreshGrant,
    mut response: huskarl::grant::core::TokenResponse,
    expected_jkt: &str,
) {
    let verifier = JwksSource::builder()
        .http_client(http.clone())
        .build()
        .build(metadata.jwks_uri.as_ref(), Arc::new(NativeVerifierPlatform))
        .await
        .expect("build ID-token verifier");
    let validator = IdTokenValidator::builder()
        .verifier(verifier)
        .issuer(metadata.issuer.clone())
        .audience(client_id)
        .openid_bound_key_requested(true)
        .build();
    let access_token_type = provider.bound_key_access_token_type();
    let initial = validator
        .validate(response.id_token().expect("initial ID token"), None)
        .await
        .expect("validate initial ID token");
    assert!(initial.sub.is_some());
    assert_bound_id_token(&response, expected_jkt, access_token_type);
    for _ in 0..2 {
        let refresh = response
            .refresh_token()
            .expect("offline_access refresh token");
        assert!(refresh.openid_bound_key_requested());
        assert_eq!(refresh.dpop_jkt(), Some(expected_jkt));
        // Exercise the state a caller would restore after a process restart.
        let persisted = serde_json::to_vec(refresh).expect("serialize refresh state");
        let restored = serde_json::from_slice(&persisted).expect("restore refresh state");
        response = refresh_grant
            .exchange(RefreshGrantParameters::refresh_token(restored))
            .await
            .expect("refresh bound ID token");
        let validated = validator
            .validate(response.id_token().expect("refreshed ID token"), None)
            .await
            .expect("validate refreshed ID token");
        assert_eq!(validated.sub, initial.sub);
        assert_bound_id_token(&response, expected_jkt, access_token_type);
    }
}

// These assertions test the OP's response, not a consumer-side PoP protocol.
fn assert_bound_id_token(
    response: &huskarl::grant::core::TokenResponse,
    expected_jkt: &str,
    access_token_type: Option<&str>,
) {
    if let Some(access_token_type) = access_token_type {
        assert_eq!(response.access_token().token_type(), access_token_type);
    }
    let raw = response.id_token().expect("bound ID token").token();
    let parsed = parse_compact_jws::<(), serde_json::Value>(raw).expect("parse ID token");
    assert_eq!(parsed.header.typ.as_deref(), Some("dpop+id_token"));
    let payload = BASE64_URL_SAFE_NO_PAD
        .decode(raw.split('.').nth(1).unwrap())
        .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    let jwk = &claims["cnf"]["jwk"];
    assert!(
        jwk.get("d").is_none(),
        "ID token must contain only the public key"
    );
    let public: PublicJwk = serde_json::from_value(jwk.clone()).expect("cnf.jwk public key");
    assert_eq!(public.thumbprint(), expected_jkt);
}

fn redirect_uri_port(uri: &str) -> Option<u16> {
    uri.parse::<http::Uri>().ok()?.port_u16()
}

/// Client credentials grant with mTLS certificate-bound tokens.
pub async fn mtls_flow(provider: &dyn TestProvider, features: Features) {
    let material = provider
        .mtls_material()
        .expect("provider advertised mtls but returned no certificate material");

    let client_cert_der = pem::parse(material.client_cert_pem)
        .expect("parse client cert")
        .into_contents();
    let ca_cert = reqwest::Certificate::from_pem(&material.ca_pem).expect("parse CA cert");

    let spec = ClientSpec::builder()
        .features(features)
        .audience(AUDIENCE)
        .build();
    let (client, secret) = provision_with_secret(provider, spec).await;

    let http: ReqwestClient = ReqwestClient::builder()
        .mtls(MtlsPem::new(ProvidedSecret::new(
            material.client_identity_pem,
        )))
        .root_certificates(vec![ca_cert])
        .build()
        .await
        .expect("build mTLS client");

    let metadata = fetch_metadata(provider, &http, Transport::Mtls).await;
    let validator = jwks_validator(&metadata, &http, AUDIENCE).await;

    let authorizer = client_credentials_authorizer(
        &metadata,
        &http,
        &client.client_id,
        ClientSecret::new(ProvidedSecret::new(secret)),
        None,
    );

    let (request_method, request_uri) = test_request();
    let headers = authorizer
        .get_headers(&request_method, &request_uri)
        .await
        .unwrap();

    assert_accepted(&validator, &headers, Some(&client_cert_der)).await;
}

/// Negative test: a token must be rejected by a validator requiring a different audience.
pub async fn wrong_audience_flow(provider: &dyn TestProvider, features: Features) {
    let spec = ClientSpec::builder()
        .features(features)
        .audience(AUDIENCE)
        .build();
    let (client, secret) = provision_with_secret(provider, spec).await;

    let http = http_client();
    let metadata = fetch_metadata(provider, &http, Transport::Plain).await;

    let authorizer = client_credentials_authorizer(
        &metadata,
        &http,
        &client.client_id,
        ClientSecret::new(ProvidedSecret::new(secret)),
        None,
    );
    let (request_method, request_uri) = test_request();
    let headers = authorizer
        .get_headers(&request_method, &request_uri)
        .await
        .unwrap();

    // Accept under the real audience first, so the rejection is attributable only to audience.
    let accepting = jwks_validator(&metadata, &http, AUDIENCE).await;
    assert_accepted(&accepting, &headers, None).await;

    const WRONG_AUDIENCE: &str = "huskarl-rs-not-this-one";
    let rejecting = jwks_validator(&metadata, &http, WRONG_AUDIENCE).await;
    let rejected = rejecting
        .validate_request(&headers, &request_method, &request_uri, None)
        .await;
    assert!(
        !matches!(rejected.outcome, Ok(Some(_))),
        "token for {AUDIENCE:?} must not validate when audience {WRONG_AUDIENCE:?} is required"
    );
}
