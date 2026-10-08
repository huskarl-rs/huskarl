use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::Request;
use huskarl_crypto_native::{
    NativeVerifierPlatform,
    asymmetric::signer::{GenerateAlgorithm, PrivateKey},
};
use huskarl_resource_server::validator::dpop_proof::DPoPProofValidator;

use super::*;
use crate::{
    core::{
        RetryAdvice,
        client_auth::{ClientSecret, NoAuth},
        crypto::signer::{AsymmetricJwsSignerSelector, MultiKeySigner, RefreshableSigner},
        dpop::DPoP,
        http::{HttpResponse, Idempotency},
        platform::MaybeSendBoxFuture,
        secrets::ProvidedSecret,
    },
    grant::jwt_bearer::{JwtBearerGrant, JwtBearerGrantParameters},
};

#[derive(Clone)]
struct RecordingHttp {
    requests: Arc<Mutex<Vec<Request<Bytes>>>>,
    token_type: &'static str,
    mtls: bool,
}

impl RecordingHttp {
    fn new(token_type: &'static str, mtls: bool) -> Self {
        Self {
            requests: Arc::default(),
            token_type,
            mtls,
        }
    }
}

impl HttpClient for RecordingHttp {
    fn uses_mtls(&self) -> bool {
        self.mtls
    }

    fn execute(
        &self,
        request: Request<Bytes>,
        _idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async move {
            let mut requests = self
                .requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            requests.push(request);
            Ok(HttpResponse {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: serde_json::json!({
                    "access_token": "access",
                    "token_type": self.token_type,
                    "refresh_token": format!("refresh-{}", requests.len()),
                })
                .to_string()
                .into(),
            })
        })
    }
}

#[rstest::rstest]
#[case::anonymous_bearer(None, false, "Bearer")]
#[case::public_bearer(Some(false), false, "Bearer")]
#[case::secret_bearer(Some(true), false, "Bearer")]
#[case::mtls_bearer(Some(false), true, "Bearer")]
#[case::anonymous_dpop(None, false, "DPoP")]
#[case::public_dpop(Some(false), false, "DPoP")]
#[case::secret_dpop(Some(true), false, "DPoP")]
#[case::mtls_dpop(Some(false), true, "DPoP")]
#[tokio::test]
async fn acquisition_and_refresh_keep_only_public_clients_pinned(
    #[case] authenticate: Option<bool>,
    #[case] mtls: bool,
    #[case] token_type: &'static str,
) {
    let original = PrivateKey::generate(GenerateAlgorithm::Es256, None)
        .unwrap()
        .select_asymmetric_signer()
        .await;
    let original_jkt = original.public_key_jwk().thumbprint();
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
    let http = RecordingHttp::new(token_type, mtls);
    let auth: Option<Arc<dyn ClientAuthentication>> = authenticate.map(|confidential| {
        if confidential {
            Arc::new(ClientSecret::new(ProvidedSecret::new(SecretString::new(
                "secret",
            )))) as Arc<dyn ClientAuthentication>
        } else {
            Arc::new(NoAuth) as Arc<dyn ClientAuthentication>
        }
    });
    let grant = JwtBearerGrant::builder()
        .client_id("client")
        .maybe_client_auth(auth)
        .token_endpoint("https://as.example/token".parse().unwrap())
        .http_client(http.clone())
        .dpop(DPoP::builder().signer(signer.clone()).build())
        .build();
    let public = authenticate != Some(true) && !mtls;
    assert_eq!(grant.is_public_client(), public);
    let response = grant
        .exchange(
            JwtBearerGrantParameters::builder()
                .assertion("assertion")
                .build(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.access_token().dpop_jkt(),
        (token_type == "DPoP").then_some(original_jkt.as_str()),
    );
    let mut refresh = response.refresh_token().unwrap().clone();
    assert_eq!(refresh.dpop_jkt(), public.then_some(original_jkt.as_str()));

    // Public clients retain the old key; confidential clients can retire it.
    *keys.lock().unwrap() =
        MultiKeySigner::new(replacement, if public { vec![original] } else { vec![] });
    signer.refresh().await.unwrap();
    let refresh_grant = grant.to_refresh_grant();
    let expected_key = if public {
        &original_jkt
    } else {
        &replacement_jkt
    };
    for _ in 0..2 {
        // Persistence must preserve the public client's binding.
        refresh = serde_json::from_str(&serde_json::to_string(&refresh).unwrap()).unwrap();
        let response = refresh_grant
            .exchange(RefreshGrantParameters::refresh_token(refresh))
            .await
            .unwrap();
        assert_eq!(
            response.access_token().dpop_jkt(),
            (token_type == "DPoP").then_some(expected_key.as_str()),
        );
        refresh = response.refresh_token().unwrap().clone();
        assert_eq!(refresh.dpop_jkt(), public.then_some(original_jkt.as_str()));
    }
    let requests = std::mem::take(&mut *http.requests.lock().unwrap());
    assert_eq!(requests.len(), 3);
    let validator = DPoPProofValidator::builder()
        .jws_verifier_platform(Arc::new(NativeVerifierPlatform))
        .build();
    let mut previous_jti = None;
    for (index, request) in requests.into_iter().enumerate() {
        let proof = validator
            .validate(request.headers()["DPoP"].to_str().unwrap())
            .await
            .unwrap();
        let expected_key = if index == 0 {
            &original_jkt
        } else {
            expected_key
        };
        assert_eq!(proof.thumbprint.as_deref(), Some(expected_key.as_str()));
        assert_eq!(proof.htm.as_deref(), Some("POST"));
        assert_eq!(proof.htu.as_deref(), Some("https://as.example/token"));
        assert!(proof.jti.is_some());
        assert_ne!(proof.jti, previous_jti);
        previous_jti = proof.jti;
        if index > 0 {
            let body = std::str::from_utf8(request.body()).unwrap();
            assert!(body.contains(&format!("refresh_token=refresh-{index}")));
        }
    }
}

#[rstest::rstest]
#[case::secret_bearer(false, "Bearer")]
#[case::mtls_bearer(true, "Bearer")]
#[case::secret_dpop(false, "DPoP")]
#[case::mtls_dpop(true, "DPoP")]
#[tokio::test]
async fn confidential_refresh_preserves_stored_binding(
    #[case] mtls: bool,
    #[case] token_type: &'static str,
) {
    let original = PrivateKey::generate(GenerateAlgorithm::Es256, None)
        .unwrap()
        .select_asymmetric_signer()
        .await;
    let original_jkt = original.public_key_jwk().thumbprint();
    let current = PrivateKey::generate(GenerateAlgorithm::Es256, None)
        .unwrap()
        .select_asymmetric_signer()
        .await;
    let http = RecordingHttp::new(token_type, mtls);
    let auth: Arc<dyn ClientAuthentication> = if mtls {
        Arc::new(NoAuth)
    } else {
        Arc::new(ClientSecret::new(ProvidedSecret::new(SecretString::new(
            "secret",
        ))))
    };
    let grant = RefreshGrant::builder()
        .token_endpoint("https://as.example/token".parse().unwrap())
        .client_id("client")
        .client_auth(auth)
        .http_client(http.clone())
        .dpop(
            DPoP::builder()
                .signer(MultiKeySigner::new(current, vec![original]))
                .build(),
        )
        .build();
    // An explicit or persisted binding is authoritative, even for a confidential
    // client, and must survive replacement refresh tokens.
    let mut refresh = RefreshToken::new("refresh".into(), Some(original_jkt.clone()));
    for _ in 0..2 {
        refresh = serde_json::from_str(&serde_json::to_string(&refresh).unwrap()).unwrap();
        let response = grant
            .exchange(RefreshGrantParameters::refresh_token(refresh))
            .await
            .unwrap();
        assert_eq!(
            response.access_token().dpop_jkt(),
            (token_type == "DPoP").then_some(original_jkt.as_str())
        );
        refresh = response.refresh_token().unwrap().clone();
        assert_eq!(refresh.dpop_jkt(), Some(original_jkt.as_str()));
    }
    let requests = std::mem::take(&mut *http.requests.lock().unwrap());
    assert_eq!(requests.len(), 2);
    let validator = DPoPProofValidator::builder()
        .jws_verifier_platform(Arc::new(NativeVerifierPlatform))
        .build();
    for request in requests {
        let proof = validator
            .validate(request.headers()["DPoP"].to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(proof.thumbprint.as_deref(), Some(original_jkt.as_str()));
    }
}

#[tokio::test]
async fn public_refresh_without_original_key_fails_before_http() {
    let http = RecordingHttp::new("Bearer", false);
    let unconfigured = RefreshGrant::builder()
        .token_endpoint("https://as.example/token".parse().unwrap())
        .http_client(http.clone())
        .build();
    let wrong_key = RefreshGrant::builder()
        .token_endpoint("https://as.example/token".parse().unwrap())
        .client_id("public-client")
        .client_auth(NoAuth)
        .http_client(http.clone())
        .dpop(
            DPoP::builder()
                .signer(PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap())
                .build(),
        )
        .build();
    for grant in [unconfigured, wrong_key] {
        let err = grant
            .exchange(RefreshGrantParameters::refresh_token(RefreshToken::new(
                "refresh".into(),
                Some("original-key".into()),
            )))
            .await
            .unwrap_err();
        assert_eq!(err.retry_advice(), RetryAdvice::No);
    }
    assert!(http.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn confidential_refresh_without_dpop_rejects_stored_binding() {
    let http = RecordingHttp::new("Bearer", false);
    let grant = RefreshGrant::builder()
        .token_endpoint("https://as.example/token".parse().unwrap())
        .client_id("client")
        .client_auth(ClientSecret::new(ProvidedSecret::new(SecretString::new(
            "secret",
        ))))
        .http_client(http.clone())
        .build();
    let err = grant
        .exchange(RefreshGrantParameters::refresh_token(RefreshToken::new(
            "refresh".into(),
            Some("retired-key".into()),
        )))
        .await
        .unwrap_err();
    assert_eq!(err.retry_advice(), RetryAdvice::No);
    assert!(http.requests.lock().unwrap().is_empty());
}
