//! Default builds must not opt into draft behavior merely because of scopes.
#![allow(clippy::unwrap_used)]
use std::sync::{Arc, Mutex};

use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::Request;
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

use super::OAuth2ExchangeGrant;
use crate::{
    core::{
        Error,
        client_auth::ClientSecret,
        dpop::DPoP,
        http::{HttpClient, HttpResponse, Idempotency},
        platform::MaybeSendBoxFuture,
        secrets::{ProvidedSecret, SecretString},
    },
    grant::{
        authorization_code::{AuthorizationCodeGrant, CompleteInput, StartInput},
        device_authorization::{self, DeviceAuthorizationGrant, PollResult},
    },
};

#[derive(Clone, Default)]
struct RecordingHttp(Arc<Mutex<Vec<Request<Bytes>>>>);
impl HttpClient for RecordingHttp {
    fn execute(
        &self,
        request: Request<Bytes>,
        _: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        let body = if request.uri().path() == "/device" {
            r#"{"device_code":"code","user_code":"user","verification_uri":"https://as.example/verify","expires_in":600}"#
        } else {
            r#"{"access_token":"access","token_type":"Bearer","refresh_token":"refresh"}"#
        };
        self.0.lock().unwrap().push(request);
        Box::pin(async move {
            Ok(HttpResponse {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: Bytes::from_static(body.as_bytes()),
            })
        })
    }
}

fn dpop() -> DPoP {
    DPoP::builder()
        .signer(PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap())
        .build()
}
fn auth() -> ClientSecret {
    ClientSecret::new(ProvidedSecret::new(SecretString::new("secret")))
}

#[tokio::test]
async fn draft_scopes_do_not_enable_binding() {
    let http = RecordingHttp::default();
    let code = AuthorizationCodeGrant::builder()
        .client_id("client")
        .client_auth(auth())
        .http_client(http.clone())
        .dpop(dpop())
        .token_endpoint("https://as.example/token".parse().unwrap())
        .authorization_endpoint("https://as.example/authorize".parse().unwrap())
        .redirect_uri("https://client.example/callback")
        .oidc(false)
        .build()
        .await
        .unwrap();
    let start = code
        .start(StartInput::scope(bon::vec!["openid", "bound_key"]))
        .await
        .unwrap();
    assert!(
        serde_json::to_value(&start.pending_state)
            .unwrap()
            .get("openid_bound_key_requested")
            .is_none()
    );
    let response = code
        .complete(
            &start.pending_state,
            CompleteInput::builder()
                .code("code")
                .state(start.pending_state.state.clone())
                .build(),
        )
        .await
        .unwrap();
    let refresh = response.token_response.refresh_token().unwrap();
    assert!(refresh.dpop_jkt().is_none());
    assert!(
        serde_json::to_value(refresh)
            .unwrap()
            .get("openid_bound_key_requested")
            .is_none()
    );
    code.to_refresh_grant()
        .exchange(crate::grant::refresh::RefreshGrantParameters::refresh_token(refresh.clone()))
        .await
        .unwrap();

    let device = DeviceAuthorizationGrant::builder()
        .client_id("client")
        .client_auth(auth())
        .http_client(http.clone())
        .dpop(dpop())
        .token_endpoint("https://as.example/token".parse().unwrap())
        .device_authorization_endpoint("https://as.example/device".parse().unwrap())
        .build();
    let mut pending = device
        .start(device_authorization::StartInput::scope(bon::vec![
            "openid",
            "bound_key"
        ]))
        .await
        .unwrap()
        .pending_state;
    let saved = serde_json::to_value(&pending).unwrap();
    assert!(saved.get("openid_bound_key_requested").is_none());
    assert!(saved.get("dpop_jkt").is_none());
    let PollResult::Complete(response) = device.poll(&mut pending, None).await.unwrap() else {
        panic!("expected token")
    };
    assert!(response.refresh_token().unwrap().dpop_jkt().is_none());

    let requests = http.0.lock().unwrap();
    assert_eq!(requests.len(), 4);
    for request in requests.iter() {
        let compact = request.headers()["DPoP"].to_str().unwrap();
        let claims: serde_json::Value = serde_json::from_slice(
            &BASE64_URL_SAFE_NO_PAD
                .decode(compact.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert!(claims.get("c_s256").is_none());
        if request.uri().path() == "/device" {
            let form: std::collections::HashMap<String, String> =
                crate::core::oauth_form::from_str(std::str::from_utf8(request.body()).unwrap())
                    .unwrap();
            assert_eq!(form["scope"], "openid bound_key");
            assert!(!form.contains_key("dpop_jkt"));
        }
    }
}
