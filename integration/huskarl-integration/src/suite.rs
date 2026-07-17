//! Generic flow bodies shared across providers.

use std::{collections::HashMap, sync::Arc};

use http::Method;
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache},
    core::{
        client_auth::{Audience, ClientAuthentication, ClientSecret, JwtBearer},
        crypto::signer::AsymmetricJwsSigner as _,
        dpop::DPoP,
        jwk::JwksSource,
        secrets::{ProvidedSecret, SecretString},
        server_metadata::AuthorizationServerMetadata,
    },
    grant::{
        authorization_code::{AuthorizationCodeGrant, StartInput, StartOutput, bind_loopback},
        client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
        core::OAuth2ExchangeGrant,
        refresh::RefreshGrantParameters,
    },
};
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
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
        .audience(ClaimCheck::required_value(audience))
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
                .map(|k| k.public_key_jwk().into_owned()),
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
        .audience(ClaimCheck::required_value(AUDIENCE))
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
        validated.subject.is_some(),
        "expected subject to be present, got None"
    );
    assert_eq!(validated.issuer.as_deref(), Some(issuer.as_str()));
    assert!(
        validated.audience.contains(&AUDIENCE.to_owned()),
        "expected audience to contain '{AUDIENCE}', got {:?}",
        validated.audience
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

    let jar_key = features.contains(Features::JAR).then(|| {
        PrivateKey::generate(GenerateAlgorithm::Es256, Some("jar-key".to_owned()))
            .expect("generate JAR key")
    });

    let spec = ClientSpec::builder()
        .features(features)
        .redirect_uris(vec![redirect_uri.clone()])
        .maybe_signing_jwk(jar_key.as_ref().map(|k| k.public_key_jwk().into_owned()))
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
        .jws_verifier_factory(Arc::new(
            JwksSource::builder().http_client(http.clone()).build(),
        ))
        .maybe_jar(jar_key)
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
        .start(StartInput::scope(bon::vec!["openid"]))
        .await
        .expect("start auth-code flow");

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
    let complete_fut = grant.complete_on_loopback_oidc(&listener, &pending_state, None);
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
    let (_token_response, id_token) = token_and_id.expect("complete auth-code flow");

    let id_token = id_token.expect("id_token present for the openid scope");
    assert!(
        id_token.audience.contains(&client.client_id),
        "id_token aud {:?} should contain the client_id {}",
        id_token.audience,
        client.client_id
    );
    assert!(
        id_token.subject.is_some(),
        "id_token should carry a subject"
    );
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
