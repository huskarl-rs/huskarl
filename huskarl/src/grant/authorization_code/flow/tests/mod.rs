use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use bytes::Bytes;
use rstest::rstest;

use super::*;
use crate::{
    core::{
        client_auth::NoAuth,
        dpop::SessionKeyedDPoP,
        http::{HttpClient, HttpResponse, Idempotency},
        platform::MaybeSendBoxFuture,
        server_metadata::AuthorizationServerMetadata,
    },
    grant::authorization_code::{
        error::{BuildError, FlowError, StartError},
        types::{CompleteInput, ResponseMode, StartInput},
    },
    token::AccessToken,
};

// Inspect typed causes without depending on display text.
fn build_cause(err: &Error) -> &BuildError {
    err.cause()
        .downcast_ref()
        .unwrap_or_else(|| panic!("expected a BuildError cause, got {err:?}"))
}

fn start_cause(err: &Error) -> &StartError {
    err.cause()
        .downcast_ref()
        .unwrap_or_else(|| panic!("expected a StartError cause, got {err:?}"))
}

fn complete_cause(err: &Error) -> &CompleteError {
    err.cause()
        .downcast_ref()
        .unwrap_or_else(|| panic!("expected a CompleteError cause, got {err:?}"))
}

/// `start()` with direct delivery performs no HTTP; this client asserts that.
struct NoHttp;

impl HttpClient for NoHttp {
    fn execute(
        &self,
        _request: http::Request<Bytes>,
        _idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        panic!("start() with direct delivery must not perform HTTP")
    }
}

type Grant = AuthorizationCodeGrant;

/// A verifier that is present but never invoked — for flows that only
/// need ID-token validation to be *configured*.
#[derive(Debug)]
struct StubVerifier;

impl crate::core::crypto::verifier::JwsVerifier for StubVerifier {
    fn key_match(
        &self,
        _key_match: &crate::core::crypto::verifier::KeyMatch<'_>,
    ) -> Option<crate::core::crypto::KeyMatchStrength> {
        None
    }

    fn verify<'a>(
        &'a self,
        _input: &'a [u8],
        _signature: &'a [u8],
        _key_match: &'a crate::core::crypto::verifier::KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), crate::core::crypto::verifier::VerifyError>> {
        panic!("stub verifier must not be invoked")
    }
}

/// Marks the grant OIDC-capable (verifier + issuer) without real crypto.
fn make_oidc_capable(grant: &mut Grant) {
    grant.jws_verifier = Some(std::sync::Arc::new(StubVerifier));
    grant.issuer = Some("https://as.example.com".to_string());
}

/// Builds [`StubVerifier`] — for exercising the builder's own OIDC checks.
struct StubVerifierFactory;

impl crate::core::crypto::verifier::JwsVerifierFactory for StubVerifierFactory {
    fn build(
        &self,
        _jwks_uri: Option<&EndpointUrl>,
        _platform: std::sync::Arc<dyn crate::core::crypto::verifier::JwsVerifierPlatform>,
    ) -> MaybeSendBoxFuture<
        'static,
        Result<std::sync::Arc<dyn crate::core::crypto::verifier::JwsVerifier>, Error>,
    > {
        Box::pin(async { Ok(std::sync::Arc::new(StubVerifier) as _) })
    }
}

/// Records each request's path and whether it carried a `DPoP` header,
/// serving canned PAR and token responses.
#[derive(Clone, Default)]
struct RecordingHttp {
    seen: Arc<Mutex<Vec<(String, bool)>>>,
}

impl HttpClient for RecordingHttp {
    fn execute(
        &self,
        request: http::Request<Bytes>,
        _idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        let path = request.uri().path().to_string();
        let has_dpop = request.headers().contains_key("DPoP");
        self.seen.lock().unwrap().push((path.clone(), has_dpop));

        let (status, body) = if path.ends_with("/par") {
            (
                http::StatusCode::CREATED,
                Bytes::from_static(
                    br#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}"#,
                ),
            )
        } else {
            (
                http::StatusCode::OK,
                Bytes::from_static(br#"{"access_token":"at","token_type":"DPoP"}"#),
            )
        };
        Box::pin(async move {
            Ok(HttpResponse {
                status,
                headers: http::HeaderMap::new(),
                body,
            })
        })
    }
}

async fn session_keyed_par_grant(http: RecordingHttp) -> Grant {
    AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(http)
        .client_auth(NoAuth)
        .dpop(SessionKeyedDPoP::new())
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .pushed_authorization_request_endpoint("https://as.example.com/par".parse().unwrap())
        .prefer_pushed_authorization_requests(true)
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap()
}

mod complete;
mod start;

/// Requiring PAR without a PAR endpoint must fail at build time: the only
/// way to proceed would be silently downgrading to a plain authorization
/// request (RFC 9126 §5).
#[tokio::test]
async fn required_par_without_endpoint_fails_the_build() {
    let result = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .require_pushed_authorization_requests(true)
        .build()
        .await;

    let _err = result
        .err()
        .expect("build must fail without a PAR endpoint");
}

/// Control: the same requirement with an endpoint configured builds fine.
#[tokio::test]
async fn required_par_with_endpoint_builds() {
    AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .pushed_authorization_request_endpoint("https://as.example.com/par".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .require_pushed_authorization_requests(true)
        .build()
        .await
        .unwrap();
}

/// `oidc(true)` declares every flow OIDC, so a grant that could never
/// validate an ID token fails at build time, not at start. With no
/// `jwks_uri` the default `JwksSource` has no key source, and no custom
/// factory was supplied — so there is no verifier to configure.
#[tokio::test]
async fn oidc_true_without_key_source_fails_the_build() {
    let result = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .oidc(true)
        .build()
        .await;

    let err = result
        .err()
        .expect("oidc(true) with no key source (no jwks_uri, no factory) must not build");
    assert!(
        matches!(build_cause(&err), BuildError::OidcRequiresVerifier),
        "got {err:?}"
    );
}

/// Same build-time check for the issuer once a verifier is present.
#[tokio::test]
async fn oidc_true_without_issuer_fails_the_build() {
    let result = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .oidc(true)
        .jws_verifier_factory(StubVerifierFactory)
        .build()
        .await;

    let err = result
        .err()
        .expect("oidc(true) without an issuer must not build");
    assert!(
        matches!(build_cause(&err), BuildError::OidcRequiresIssuer),
        "got {err:?}"
    );
}

/// A caller-supplied factory is honored even with no `jwks_uri`: a custom
/// factory may carry its own keys (a KMS/enclave signer, or a static JWKS)
/// and need no URI. The default `JwksSource` needs one, but an explicitly
/// supplied factory must never be silently dropped.
#[tokio::test]
async fn supplied_factory_builds_verifier_without_jwks_uri() {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .jws_verifier_factory(StubVerifierFactory)
        .build()
        .await
        .expect("a supplied factory must build even without a jwks_uri");

    assert!(
        grant.jws_verifier.is_some(),
        "the supplied factory must have produced a verifier"
    );
}

/// With no factory and no `jwks_uri`, a plain-OAuth grant builds with no
/// verifier: verification is simply off, not a build error. The default
/// factory is a `JwksSource`, which has no key source without a URI.
#[tokio::test]
async fn default_factory_without_jwks_uri_builds_without_verifier() {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .expect("a plain-OAuth grant must build without a verifier");

    assert!(
        grant.jws_verifier.is_none(),
        "no factory and no jwks_uri means no verifier"
    );
}

/// `oidc(false)` without JARM declares the flow non-OIDC, so no default
/// verifier is built even when a `jwks_uri` is present — and, crucially, no
/// JWKS fetch is attempted (the `NoHttp` client would fail one). A returned
/// ID token is then rejected at completion unless a factory is supplied.
#[tokio::test]
async fn oidc_false_builds_no_verifier_and_skips_the_fetch() {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .jwks_uri("https://as.example.com/jwks".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .oidc(false)
        .build()
        .await
        .expect("oidc(false) must build without touching the JWKS endpoint");

    assert!(
        grant.jws_verifier.is_none(),
        "oidc(false) without JARM must build no default verifier"
    );
}

/// The default `JwksSource` is actually built, and its startup policy is
/// applied: `oidc(true)`/JARM fail the build on an unreachable JWKS
/// (`FailFast`), while an inferred flow (`oidc` unset) comes up cold and
/// self-heals (`SeedEmpty`). A `200` with a valid JWKS builds a working
/// verifier — proving the keys are fetched and parsed end-to-end (a
/// malformed key would fail the build even on `200`).
#[rstest]
#[case::oidc_true_failfast_fatal(Some(true), None, 500, false)]
#[case::oidc_true_valid_jwks_builds(Some(true), None, 200, true)]
#[case::inferred_seed_empty_tolerates(None, None, 500, true)]
#[case::jarm_failfast_fatal(None, Some(ResponseMode::QueryJwt), 500, false)]
#[tokio::test]
async fn default_verifier_startup_policy(
    #[case] oidc: Option<bool>,
    #[case] response_mode: Option<ResponseMode>,
    #[case] status: u16,
    #[case] expect_verifier: bool,
) {
    use httpmock::prelude::*;
    use huskarl_reqwest::ReqwestClient;

    // A valid P-256 public JWK (RFC 7517 §A.1): a `200` must build a real
    // verifier, so a skipped fetch or a malformed key would be caught.
    const JWKS: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}"#;

    let server = MockServer::start_async().await;
    let body = if status == 200 { JWKS } else { "{}" };
    server
        .mock_async(|when, then| {
            when.method(GET).path("/jwks");
            then.status(status)
                .header("content-type", "application/json")
                .body(body);
        })
        .await;

    let http: ReqwestClient = reqwest::Client::new().into();
    let result = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(http)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .jwks_uri(server.url("/jwks").parse().unwrap())
        .issuer("https://as.example.com")
        .maybe_oidc(oidc)
        .maybe_response_mode(response_mode)
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await;

    if expect_verifier {
        let grant = result.expect("build should succeed and yield a verifier");
        assert!(
            grant.jws_verifier.is_some(),
            "a default JwksSource verifier must be present",
        );
    } else {
        assert!(
            result.is_err(),
            "FailFast must fail the build when the JWKS fetch fails",
        );
    }
}

#[tokio::test]
async fn id_token_algs_default_from_metadata_dropping_none() {
    // OIDC Discovery `id_token_signing_alg_values_supported` seeds the
    // allowlist so the ID-token `alg` is pinned to what the issuer
    // advertises; the insecure `none` value is dropped.
    let metadata: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
        "issuer": "https://as.example.com",
        "authorization_endpoint": "https://as.example.com/authorize",
        "token_endpoint": "https://as.example.com/token",
        "response_types_supported": ["code"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256", "none"],
    }))
    .unwrap();

    let grant: Grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
        .unwrap()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();

    let algs = grant
        .allowed_id_token_signed_response_algs
        .expect("allowlist defaulted from metadata");
    assert!(algs.contains("RS256"), "{algs:?}");
    assert!(algs.contains("ES256"), "{algs:?}");
    assert!(
        !algs.contains("none"),
        "insecure `none` must be dropped: {algs:?}"
    );
}

#[tokio::test]
async fn id_token_algs_unset_when_metadata_omits_them() {
    let metadata: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
        "issuer": "https://as.example.com",
        "authorization_endpoint": "https://as.example.com/authorize",
        "token_endpoint": "https://as.example.com/token",
        "response_types_supported": ["code"],
    }))
    .unwrap();

    let grant: Grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
        .unwrap()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();

    assert!(grant.allowed_id_token_signed_response_algs.is_none());
}

#[tokio::test]
async fn explicit_id_token_algs_via_plain_builder() {
    // The plain `builder()` path takes an explicit allowlist (no metadata
    // seeding), pinning exactly the configured algorithms.
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .allowed_id_token_signed_response_algs(
            ["PS256".to_string()]
                .into_iter()
                .collect::<std::collections::HashSet<_>>(),
        )
        .build()
        .await
        .unwrap();

    let algs = grant
        .allowed_id_token_signed_response_algs
        .expect("explicit allowlist");
    assert_eq!(algs.len(), 1, "{algs:?}");
    assert!(algs.contains("PS256"), "{algs:?}");
}

/// A JWT-secured response mode without the means to validate JARM
/// responses fails at build time, mirroring the `oidc(true)` checks.
#[rstest::rstest]
#[case::no_verifier(false, (|e| matches!(e, BuildError::JarmRequiresVerifier)) as fn(&BuildError) -> bool)]
#[case::no_issuer(true, (|e| matches!(e, BuildError::JarmRequiresIssuer)) as fn(&BuildError) -> bool)]
#[tokio::test]
async fn jarm_mode_requires_validation_config(
    #[case] with_verifier: bool,
    #[case] expected: fn(&BuildError) -> bool,
) {
    let builder = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .response_mode(ResponseMode::QueryJwt);
    let result = if with_verifier {
        builder
            .jws_verifier_factory(StubVerifierFactory)
            .build()
            .await
    } else {
        builder.build().await
    };

    let err = result
        .err()
        .expect("jarm mode without config must not build");
    assert!(expected(build_cause(&err)), "got {err:?}");
}

#[tokio::test]
async fn jarm_algs_default_from_metadata_dropping_none() {
    let metadata: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
        "issuer": "https://as.example.com",
        "authorization_endpoint": "https://as.example.com/authorize",
        "token_endpoint": "https://as.example.com/token",
        "response_types_supported": ["code"],
        "authorization_signing_alg_values_supported": ["PS256", "ES256", "none"],
    }))
    .unwrap();

    let grant: Grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
        .unwrap()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();

    let algs = grant
        .allowed_authorization_signed_response_algs
        .expect("allowlist defaulted from metadata");
    assert!(algs.contains("PS256"), "{algs:?}");
    assert!(algs.contains("ES256"), "{algs:?}");
    assert!(
        !algs.contains("none"),
        "insecure `none` must be dropped: {algs:?}"
    );
}
