use std::sync::{Arc, Mutex};

use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};
use huskarl_crypto_native::{
    NativeVerifierPlatform,
    asymmetric::signer::{GenerateAlgorithm, PrivateKey},
};
use huskarl_resource_server::validator::dpop_proof::DPoPProofValidator;
use rstest::rstest;

use super::*;
use crate::{
    core::{
        client_auth::{ClientSecret, NoAuth},
        crypto::{
            signer::{
                AsymmetricJwsSignerSelector, JwsSignerSelector, MultiKeySigner, RefreshableSigner,
            },
            verifier::JwsVerifierPlatform as _,
        },
        dpop::DPoP,
        http::{HttpResponse, Idempotency},
        jwt::Jwt,
        platform::MaybeSendBoxFuture,
        secrets::{ProvidedSecret, SecretString},
    },
    grant::refresh::RefreshGrantParameters,
    token::id_token::IdTokenValidator,
};

const DEVICE_CODE: &str = "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS";

#[derive(Clone)]
struct DeviceHttp {
    requests: Arc<Mutex<Vec<Request<Bytes>>>>,
    id_token: String,
}

impl HttpClient for DeviceHttp {
    fn execute(
        &self,
        request: Request<Bytes>,
        _idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        let mut requests = self.requests.lock().unwrap();
        requests.push(request);
        let index = requests.len();
        let mut headers = HeaderMap::new();
        let (status, body) = match index {
            1 => (
                StatusCode::OK,
                serde_json::json!({
                    "device_code": DEVICE_CODE, "user_code": "1234",
                    "verification_uri": "https://as.example/verify", "expires_in": 600, "interval": 1,
                }),
            ),
            2 => {
                headers.insert("DPoP-Nonce", "poll-nonce".parse().unwrap());
                (
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"error": "use_dpop_nonce"}),
                )
            }
            3 => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"error": "authorization_pending"}),
            ),
            _ => (
                StatusCode::OK,
                serde_json::json!({
                    "access_token": "access", "token_type": "Bearer",
                    "id_token": self.id_token, "refresh_token": format!("refresh-{index}"),
                }),
            ),
        };
        Box::pin(async move {
            Ok(HttpResponse {
                status,
                headers,
                body: body.to_string().into(),
            })
        })
    }
}

#[rstest]
#[case::bound_public(true, false, "dpop+id_token")]
#[case::bound_confidential(true, true, "dpop+id_token")]
#[case::ignored_scope(true, true, "JWT")]
#[case::ordinary_oidc(false, true, "JWT")]
#[tokio::test(start_paused = true)]
async fn device_binding_survives_polling_and_refresh(
    #[case] bound_key: bool,
    #[case] confidential: bool,
    #[case] typ: &str,
) {
    let issuer = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
    let verifier = NativeVerifierPlatform
        .create_verifier_from_jwk(issuer.as_private_jwk().public_jwk())
        .await
        .unwrap();
    let original = PrivateKey::generate(GenerateAlgorithm::Es256, None)
        .unwrap()
        .select_asymmetric_signer()
        .await;
    let original_jkt = original.public_key_jwk().thumbprint();
    let claims = if typ == "dpop+id_token" {
        serde_json::json!({"cnf": {"jwk": original.public_key_jwk()}})
    } else {
        serde_json::json!({})
    };
    let id_token = Jwt::builder()
        .typ(typ)
        .iss("https://as.example")
        .aud(vec!["client".into()])
        .sub("user")
        .issued_now_expires_after(Duration::from_mins(5))
        .claims(claims)
        .build()
        .to_jws_compact(&*issuer.select_signer().await)
        .await
        .unwrap();
    let http = DeviceHttp {
        requests: Arc::default(),
        id_token: id_token.expose_secret().into(),
    };
    let replacement = PrivateKey::generate(GenerateAlgorithm::Es256, None)
        .unwrap()
        .select_asymmetric_signer()
        .await;
    let replacement_jkt = replacement.public_key_jwk().thumbprint();
    let keys = Arc::new(Mutex::new(MultiKeySigner::new(original.clone(), vec![])));
    let signer = RefreshableSigner::builder()
        .factory({
            let keys = keys.clone();
            move || {
                let snapshot = keys.lock().unwrap().clone();
                Box::pin(async move { Ok(snapshot) })
            }
        })
        .build()
        .await
        .unwrap();
    let auth: Arc<dyn ClientAuthentication> = if confidential {
        Arc::new(ClientSecret::new(ProvidedSecret::new(SecretString::new(
            "secret",
        ))))
    } else {
        Arc::new(NoAuth)
    };
    let grant = DeviceAuthorizationGrant::builder()
        .client_id("client")
        .client_auth(auth)
        .http_client(http.clone())
        .dpop(DPoP::builder().signer(signer.clone()).build())
        .token_endpoint("https://as.example/token".parse().unwrap())
        .device_authorization_endpoint("https://as.example/device".parse().unwrap())
        .build();
    let scopes = if bound_key {
        bon::vec!["openid", "bound_key"]
    } else {
        bon::vec!["openid"]
    };
    let start = grant.start(StartInput::scope(scopes)).await.unwrap();
    let mut pending: PendingState =
        serde_json::from_str(&serde_json::to_string(&start.pending_state).unwrap()).unwrap();
    assert_eq!(pending.openid_bound_key_requested, bound_key);
    assert_eq!(
        pending.dpop_jkt.as_deref(),
        bound_key.then_some(original_jkt.as_str())
    );
    *keys.lock().unwrap() = MultiKeySigner::new(replacement, vec![original]);
    signer.refresh().await.unwrap();
    let response = grant.poll_to_completion(&mut pending, None).await.unwrap();
    let validator = IdTokenValidator::builder()
        .verifier(verifier)
        .issuer("https://as.example")
        .audience("client")
        .openid_bound_key_requested(pending.openid_bound_key_requested)
        .build();
    validator
        .validate(response.id_token().unwrap(), None)
        .await
        .unwrap();
    assert_eq!(
        response.id_token().unwrap().token(),
        id_token.expose_secret()
    );
    let refresh = response.refresh_token().unwrap();
    let expected_jkt = if bound_key {
        &original_jkt
    } else {
        &replacement_jkt
    };
    assert_eq!(
        refresh.dpop_jkt(),
        (bound_key || !confidential).then_some(expected_jkt.as_str())
    );
    let refreshed = grant
        .to_refresh_grant()
        .exchange(RefreshGrantParameters::refresh_token(refresh.clone()))
        .await
        .unwrap();
    assert_eq!(
        refreshed.refresh_token().unwrap().dpop_jkt(),
        refresh.dpop_jkt()
    );
    assert_eq!(
        refreshed
            .refresh_token()
            .unwrap()
            .openid_bound_key_requested(),
        bound_key
    );
    let requests = std::mem::take(&mut *http.requests.lock().unwrap());
    assert_eq!(requests.len(), 5);
    let form: std::collections::HashMap<String, String> =
        crate::core::oauth_form::from_str(std::str::from_utf8(requests[0].body()).unwrap())
            .unwrap();
    assert_eq!(
        form.get("dpop_jkt").map(String::as_str),
        bound_key.then_some(original_jkt.as_str())
    );
    let proof_validator = DPoPProofValidator::builder()
        .jws_verifier_platform(Arc::new(NativeVerifierPlatform))
        .build();
    let mut seen_jti = std::collections::HashSet::new();
    for (index, request) in requests.iter().enumerate() {
        let compact = request.headers()["DPoP"].to_str().unwrap();
        let proof = proof_validator.validate(compact).await.unwrap();
        let claims: serde_json::Value = serde_json::from_slice(
            &BASE64_URL_SAFE_NO_PAD
                .decode(compact.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        if bound_key && (1..=3).contains(&index) {
            assert_eq!(
                claims["c_s256"],
                "z-6KJMF671PQKXSuIHAVQfnEVR2x1AUsfHlvC50va38"
            );
        } else {
            assert!(claims.get("c_s256").is_none());
        }
        assert_eq!(
            proof.thumbprint.as_deref(),
            Some(if index == 0 {
                original_jkt.as_str()
            } else {
                expected_jkt.as_str()
            })
        );
        assert!(seen_jti.insert(proof.jti.unwrap()));
        if index >= 2 {
            assert_eq!(claims["nonce"], "poll-nonce");
        }
    }
}

#[test]
fn legacy_device_state_defaults_to_unbound() {
    let state: PendingState =
        serde_json::from_str(r#"{"device_code":"old","interval_secs":5}"#).unwrap();
    assert!(!state.openid_bound_key_requested);
    assert!(state.dpop_jkt.is_none());
}

#[rstest]
#[case::no_dpop(false, vec!["openid", "bound_key"])]
#[case::no_openid(true, vec!["bound_key"])]
#[case::no_bound_key(true, vec!["openid"])]
#[tokio::test]
async fn ordinary_device_request_omits_binding(#[case] dpop: bool, #[case] scopes: Vec<&str>) {
    let http = DeviceHttp {
        requests: Arc::default(),
        id_token: String::new(),
    };
    let mut grant = DeviceAuthorizationGrant::builder()
        .client_id("client")
        .client_auth(NoAuth)
        .http_client(http.clone())
        .token_endpoint("https://as.example/token".parse().unwrap())
        .device_authorization_endpoint("https://as.example/device".parse().unwrap())
        .build();
    if dpop {
        grant.dpop = Arc::new(
            DPoP::builder()
                .signer(PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap())
                .build(),
        );
    }
    let start = grant
        .start(StartInput::scope(
            scopes.into_iter().map(String::from).collect(),
        ))
        .await
        .unwrap();
    assert!(!start.pending_state.openid_bound_key_requested);
    assert!(start.pending_state.dpop_jkt.is_none());
    let requests = http.requests.lock().unwrap();
    let form: std::collections::HashMap<String, String> =
        crate::core::oauth_form::from_str(std::str::from_utf8(requests[0].body()).unwrap())
            .unwrap();
    assert!(!form.contains_key("dpop_jkt"));
}

#[tokio::test]
async fn bound_device_poll_requires_original_key_before_http() {
    let http = DeviceHttp {
        requests: Arc::default(),
        id_token: String::new(),
    };
    let mut grant = DeviceAuthorizationGrant::builder()
        .client_id("client")
        .client_auth(NoAuth)
        .http_client(http.clone())
        .dpop(
            DPoP::builder()
                .signer(PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap())
                .build(),
        )
        .token_endpoint("https://as.example/token".parse().unwrap())
        .device_authorization_endpoint("https://as.example/device".parse().unwrap())
        .build();
    let mut pending = grant
        .start(StartInput::scope(bon::vec!["openid", "bound_key"]))
        .await
        .unwrap()
        .pending_state;
    grant.dpop = Arc::new(
        DPoP::builder()
            .signer(PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap())
            .build(),
    );
    let error = grant.poll(&mut pending, None).await.unwrap_err();
    assert_eq!(error.retry_advice(), RetryAdvice::No);
    grant.dpop = Arc::new(NoDPoP);
    let error = grant.poll(&mut pending, None).await.unwrap_err();
    assert_eq!(error.retry_advice(), RetryAdvice::No);
    assert_eq!(http.requests.lock().unwrap().len(), 1);
}
