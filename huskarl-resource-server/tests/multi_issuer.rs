#![cfg(not(target_family = "wasm"))]

//! Integration tests for [`MultiIssuerValidator`]: routing by issuer, the
//! audience-confusion boundary, unrecognized issuers, unauthenticated requests,
//! and metadata union.

use std::sync::Arc;

use httpmock::prelude::*;
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
use huskarl_reqwest::ReqwestClient;
use huskarl_resource_server::{
    core::{
        EndpointUrl,
        crypto::signer::JwsSignerSelector,
        jwk::{JwksSource, PublicJwks},
        jwt::Jwt,
        platform::SystemTime,
    },
    error::{TokenErrorCode, TokenValidationError},
    validator::{
        AccessTokenValidator,
        custom::CustomValidator,
        metadata::ProvideValidatorMetadata,
        multi_issuer::{MapClaims, MultiIssuerError, MultiIssuerValidator},
    },
};
use serde::{Deserialize, Serialize};

const GOOGLE_AUDIENCE: &str = "google-oauth-client-id";
const OKTA_AUDIENCE: &str = "api://my-resource";

#[derive(Clone, Deserialize)]
struct GoogleIdClaims {
    email: Option<String>,
    email_verified: Option<bool>,
}

#[derive(Clone, Deserialize)]
struct OktaClaims {
    #[serde(default)]
    scp: Vec<String>,
}

/// The canonical, source-agnostic claims an application would consume.
#[derive(Clone, Debug, PartialEq)]
struct Principal {
    email: Option<String>,
    scopes: Vec<String>,
}

/// A mock authorization server: a signing key and a JWKS endpoint.
struct MockAs {
    // Held only to keep the mock server (and its JWKS endpoint) alive.
    #[allow(dead_code)]
    server: MockServer,
    key: PrivateKey,
    issuer: String,
}

impl MockAs {
    fn start() -> Self {
        let server = MockServer::start();
        let key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
        let jwks = PublicJwks::new(vec![key.as_private_jwk().public_jwk()]);
        server.mock(|when, then| {
            when.method(GET).path("/jwks.json");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .json_body_obj(&jwks);
        });
        let issuer = format!("http://{}", server.address());
        Self {
            server,
            key,
            issuer,
        }
    }

    fn jwks_uri(&self) -> EndpointUrl {
        format!("{}/jwks.json", self.issuer).parse().unwrap()
    }

    /// Mints a token signed by this AS with the given issuer/audience/claims.
    /// `issuer` is a parameter so tests can forge a mismatching `iss`.
    async fn mint<C: Serialize + Clone>(&self, issuer: &str, audience: &str, claims: C) -> String {
        let jwt = Jwt::builder()
            .typ("JWT")
            .issuer(issuer.to_owned())
            .audience(audience.to_owned())
            .subject("user-123")
            .issued_now()
            .expiration(SystemTime::now() + std::time::Duration::from_secs(3600))
            .claims(claims)
            .build();
        jwt.to_jws_compact(&*self.key.select_signer().await)
            .await
            .unwrap()
            .expose_secret()
            .to_owned()
    }
}

#[derive(Serialize, Clone)]
struct GoogleWire {
    email: String,
    email_verified: bool,
}

#[derive(Serialize, Clone)]
struct OktaWire {
    scp: Vec<String>,
}

/// Builds a `MultiIssuerValidator` over the two mock authorization servers.
async fn build(
    http: &ReqwestClient,
    google: &MockAs,
    okta: &MockAs,
) -> MultiIssuerValidator<Principal> {
    let google_validator = CustomValidator::builder()
        .with_claims::<GoogleIdClaims>()
        .authorization_server(google.issuer.clone())
        // Plain strings are `ClaimCheck::RequiredValue`.
        .issuer(google.issuer.as_str())
        .audience(GOOGLE_AUDIENCE)
        .require_jti(false)
        .realm("api")
        .jwks_uri(google.jwks_uri())
        .jws_verifier_factory(Arc::new(
            JwksSource::builder().http_client(http.clone()).build(),
        ))
        .build()
        .await
        .unwrap();

    let okta_validator = CustomValidator::builder()
        .with_claims::<OktaClaims>()
        .authorization_server(okta.issuer.clone())
        .issuer(okta.issuer.as_str())
        .audience(OKTA_AUDIENCE)
        .require_jti(false)
        .realm("api")
        .jwks_uri(okta.jwks_uri())
        .jws_verifier_factory(Arc::new(
            JwksSource::builder().http_client(http.clone()).build(),
        ))
        .build()
        .await
        .unwrap();

    MultiIssuerValidator::<Principal>::builder()
        .source(
            google.issuer.clone(),
            MapClaims::new(google_validator, |c: GoogleIdClaims| Principal {
                email: c.email.filter(|_| c.email_verified == Some(true)),
                scopes: Vec::new(),
            }),
        )
        .source(
            okta.issuer.clone(),
            MapClaims::new(okta_validator, |c: OktaClaims| Principal {
                email: None,
                scopes: c.scp,
            }),
        )
        .build()
}

fn bearer(token: &str) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    headers
}

async fn validate(
    v: &MultiIssuerValidator<Principal>,
    headers: &http::HeaderMap,
) -> Result<Option<Principal>, MultiIssuerError> {
    v.validate_request(
        headers,
        &http::Method::GET,
        &"https://api.example.com/data".parse().unwrap(),
        None,
    )
    .await
    .outcome
    .map(|opt| opt.map(|vr| vr.claims))
}

#[tokio::test]
async fn routes_each_issuer_to_its_validator() {
    let google = MockAs::start();
    let okta = MockAs::start();
    let http = ReqwestClient::builder().build().await.unwrap();
    let validator = build(&http, &google, &okta).await;

    let g_token = google
        .mint(
            &google.issuer,
            GOOGLE_AUDIENCE,
            GoogleWire {
                email: "alice@example.com".into(),
                email_verified: true,
            },
        )
        .await;
    let principal = validate(&validator, &bearer(&g_token))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(principal.email.as_deref(), Some("alice@example.com"));
    assert!(principal.scopes.is_empty());

    let o_token = okta
        .mint(
            &okta.issuer,
            OKTA_AUDIENCE,
            OktaWire {
                scp: vec!["read".into(), "write".into()],
            },
        )
        .await;
    let principal = validate(&validator, &bearer(&o_token))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(principal.email, None);
    assert_eq!(principal.scopes, vec!["read", "write"]);
}

/// A validly Google-signed token minted for a *different* audience must be
/// rejected — the per-source audience pin is the access boundary.
#[tokio::test]
async fn rejects_audience_confusion() {
    let google = MockAs::start();
    let okta = MockAs::start();
    let http = ReqwestClient::builder().build().await.unwrap();
    let validator = build(&http, &google, &okta).await;

    let token = google
        .mint(
            &google.issuer,
            "some-other-relying-party", // not GOOGLE_AUDIENCE
            GoogleWire {
                email: "alice@example.com".into(),
                email_verified: true,
            },
        )
        .await;

    let err = validate(&validator, &bearer(&token)).await.unwrap_err();
    assert!(matches!(err, MultiIssuerError::Validation { .. }));
    assert!(matches!(
        err.token_error_code(),
        Some(TokenErrorCode::InvalidToken)
    ));
}

#[tokio::test]
async fn rejects_unrecognized_issuer() {
    let google = MockAs::start();
    let okta = MockAs::start();
    let http = ReqwestClient::builder().build().await.unwrap();
    let validator = build(&http, &google, &okta).await;

    // Signed by a real key, but `iss` is not registered.
    let token = google
        .mint(
            "https://evil.example",
            GOOGLE_AUDIENCE,
            GoogleWire {
                email: "mallory@evil.example".into(),
                email_verified: true,
            },
        )
        .await;

    let err = validate(&validator, &bearer(&token)).await.unwrap_err();
    assert!(matches!(err, MultiIssuerError::UnrecognizedIssuer));
}

#[tokio::test]
async fn no_token_is_unauthenticated() {
    let google = MockAs::start();
    let okta = MockAs::start();
    let http = ReqwestClient::builder().build().await.unwrap();
    let validator = build(&http, &google, &okta).await;

    let outcome = validate(&validator, &http::HeaderMap::new()).await.unwrap();
    assert!(outcome.is_none());
}

#[tokio::test]
async fn metadata_unions_authorization_servers() {
    let google = MockAs::start();
    let okta = MockAs::start();
    let http = ReqwestClient::builder().build().await.unwrap();
    let validator = build(&http, &google, &okta).await;

    let meta = validator.validator_metadata(Some("https://api.example.com"));
    let servers = meta.authorization_servers.unwrap();
    assert!(servers.contains(&google.issuer));
    assert!(servers.contains(&okta.issuer));
    assert_eq!(meta.resource.as_deref(), Some("https://api.example.com"));
    // Both sources carry the same realm, so the union surfaces it.
    assert_eq!(meta.realm.as_deref(), Some("api"));
}

/// Small helper to read the RFC 6750 error code off a classification.
trait TokenErrorCodeExt {
    fn token_error_code(&self) -> Option<TokenErrorCode>;
}
impl TokenErrorCodeExt for MultiIssuerError {
    fn token_error_code(&self) -> Option<TokenErrorCode> {
        use huskarl_resource_server::error::ToRfc6750Error as _;
        match self.token_error() {
            TokenValidationError::Client(code) => Some(code),
            TokenValidationError::Server(_) => None,
        }
    }
}
