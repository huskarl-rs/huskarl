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
#[case::anonymous_bearer(None, false, "Bearer", false)]
#[case::public_bearer(Some(false), false, "Bearer", false)]
#[case::secret_bearer(Some(true), false, "Bearer", false)]
#[case::mtls_bearer(Some(false), true, "Bearer", false)]
#[case::anonymous_dpop(None, false, "DPoP", false)]
#[case::public_dpop(Some(false), false, "DPoP", false)]
#[case::secret_dpop(Some(true), false, "DPoP", false)]
#[case::mtls_dpop(Some(false), true, "DPoP", false)]
#[cfg_attr(
    feature = "experimental-oidc-key-binding",
    case::openid_public_bearer(Some(false), false, "Bearer", true)
)]
#[cfg_attr(
    feature = "experimental-oidc-key-binding",
    case::openid_secret_bearer(Some(true), false, "Bearer", true)
)]
#[cfg_attr(
    feature = "experimental-oidc-key-binding",
    case::openid_mtls_bearer(Some(false), true, "Bearer", true)
)]
#[cfg_attr(
    feature = "experimental-oidc-key-binding",
    case::openid_public_dpop(Some(false), false, "DPoP", true)
)]
#[cfg_attr(
    feature = "experimental-oidc-key-binding",
    case::openid_secret_dpop(Some(true), false, "DPoP", true)
)]
#[cfg_attr(
    feature = "experimental-oidc-key-binding",
    case::openid_mtls_dpop(Some(false), true, "DPoP", true)
)]
#[tokio::test]
async fn acquisition_and_refresh_preserve_required_binding(
    #[case] authenticate: Option<bool>,
    #[case] mtls: bool,
    #[case] token_type: &'static str,
    #[case] bound_key: bool,
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
        .maybe_client_auth(auth.clone())
        .token_endpoint("https://as.example/token".parse().unwrap())
        .http_client(http.clone())
        .dpop(DPoP::builder().signer(signer.clone()).build())
        .build();
    let public = authenticate != Some(true) && !mtls;
    assert_eq!(grant.is_public_client(), public);
    let ordinary = async {
        let response = grant
            .exchange(
                JwtBearerGrantParameters::builder()
                    .assertion("assertion")
                    .build(),
            )
            .await
            .unwrap();
        (response, grant.to_refresh_grant())
    };
    #[cfg(not(feature = "experimental-oidc-key-binding"))]
    let (response, refresh_grant) = ordinary.await;
    #[cfg(feature = "experimental-oidc-key-binding")]
    let (response, refresh_grant) = if bound_key {
        use crate::grant::authorization_code::{
            AuthorizationCodeGrant, AuthorizationCodeGrantParameters,
        };

        let oidc = AuthorizationCodeGrant::builder()
            .client_id("client")
            .client_auth(auth.unwrap())
            .token_endpoint("https://as.example/token".parse().unwrap())
            .authorization_endpoint("https://as.example/authorize".parse().unwrap())
            .redirect_uri("https://client.example/callback")
            .http_client(http.clone())
            .dpop(DPoP::builder().signer(signer.clone()).build())
            .build()
            .await
            .unwrap();
        let response = oidc
            .exchange(
                AuthorizationCodeGrantParameters::builder()
                    .code("code")
                    .openid_bound_key_requested(true)
                    .build(),
            )
            .await
            .unwrap();
        (response, oidc.to_refresh_grant())
    } else {
        ordinary.await
    };
    let pinned = public || bound_key;
    assert_eq!(
        response.access_token().dpop_jkt(),
        (token_type == "DPoP").then_some(original_jkt.as_str()),
    );
    let mut refresh = response.refresh_token().unwrap().clone();
    assert_eq!(refresh.dpop_jkt(), pinned.then_some(original_jkt.as_str()));

    // Retain the original key when required, even after the default key rotates.
    *keys.lock().unwrap() =
        MultiKeySigner::new(replacement, if pinned { vec![original] } else { vec![] });
    signer.refresh().await.unwrap();
    let expected_key = if pinned {
        &original_jkt
    } else {
        &replacement_jkt
    };
    for _ in 0..2 {
        #[cfg(feature = "experimental-oidc-key-binding")]
        assert_eq!(refresh.openid_bound_key_requested(), bound_key);
        // Persistence must preserve both the key and the OIDC request flag.
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
        assert_eq!(refresh.dpop_jkt(), pinned.then_some(original_jkt.as_str()));
    }
    let requests = std::mem::take(&mut *http.requests.lock().unwrap());
    assert_eq!(requests.len(), 3);
    let validator = DPoPProofValidator::builder()
        .jws_verifier_platform(Arc::new(NativeVerifierPlatform))
        .build();
    let mut previous_jti = None;
    for (index, request) in requests.into_iter().enumerate() {
        use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};

        let compact = request.headers()["DPoP"].to_str().unwrap();
        let claims: serde_json::Value = serde_json::from_slice(
            &BASE64_URL_SAFE_NO_PAD
                .decode(compact.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claims.get("c_s256").is_some(), bound_key && index == 0);
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

#[rstest::rstest]
#[case::public(false, false)]
#[cfg_attr(
    feature = "experimental-oidc-key-binding",
    case::openid_public(false, true)
)]
#[cfg_attr(
    feature = "experimental-oidc-key-binding",
    case::openid_confidential(true, true)
)]
#[tokio::test]
async fn bound_refresh_without_original_key_fails_before_http(
    #[case] confidential: bool,
    #[case] bound_key: bool,
) {
    #[cfg(not(feature = "experimental-oidc-key-binding"))]
    assert!(!bound_key);
    let auth: Arc<dyn ClientAuthentication> = if confidential {
        Arc::new(ClientSecret::new(ProvidedSecret::new(SecretString::new(
            "secret",
        ))))
    } else {
        Arc::new(NoAuth)
    };
    let http = RecordingHttp::new("Bearer", false);
    let unconfigured = RefreshGrant::builder()
        .client_id("client")
        .client_auth(auth.clone())
        .token_endpoint("https://as.example/token".parse().unwrap())
        .http_client(http.clone())
        .build();
    let wrong_key = RefreshGrant::builder()
        .token_endpoint("https://as.example/token".parse().unwrap())
        .client_id("client")
        .client_auth(auth)
        .http_client(http.clone())
        .dpop(
            DPoP::builder()
                .signer(PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap())
                .build(),
        )
        .build();
    for grant in [unconfigured, wrong_key] {
        let refresh = RefreshToken::new("refresh".into(), Some("original-key".into()));
        #[cfg(feature = "experimental-oidc-key-binding")]
        let refresh = {
            let mut refresh = refresh;
            refresh.openid_bound_key_requested = bound_key;
            refresh
        };
        let err = grant
            .exchange(RefreshGrantParameters::refresh_token(refresh))
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
