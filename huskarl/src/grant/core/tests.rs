use bytes::Bytes;
use rstest::rstest;

use crate::{
    core::{
        Error, RetryAdvice,
        client_auth::NoAuth,
        http::{HttpClient, HttpResponse, Idempotency},
        platform::{MaybeSendBoxFuture, SystemTime},
        time::{Clock, Duration, ManualTime},
    },
    grant::{authorization_code, device_authorization},
};

/// Time passes while awaiting the endpoint, before its response is available.
struct DelayedResponse {
    time: ManualTime,
    body: String,
    status: http::StatusCode,
}

impl HttpClient for DelayedResponse {
    fn execute(
        &self,
        _: http::Request<Bytes>,
        _: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async move {
            self.time.advance(Duration::from_secs(7)).unwrap();
            Ok(HttpResponse {
                status: self.status,
                headers: http::HeaderMap::from_iter([(
                    http::header::RETRY_AFTER,
                    http::HeaderValue::from_static("Thu, 01 Jan 1970 00:17:40 GMT"),
                )]),
                body: Bytes::copy_from_slice(self.body.as_bytes()),
            })
        })
    }
}

async fn start(par: bool, time: &ManualTime, expires_in: u64) -> Result<SystemTime, Error> {
    let response = DelayedResponse {
        time: time.clone(),
        status: http::StatusCode::OK,
        body: if par {
            serde_json::json!({"request_uri": "urn:example:request", "expires_in": expires_in})
        } else {
            serde_json::json!({
                "device_code": "device", "user_code": "user",
                "verification_uri": "https://as.example/verify", "expires_in": expires_in
            })
        }
        .to_string(),
    };
    if par {
        let grant = authorization_code::AuthorizationCodeGrant::builder()
            .client_id("client")
            .client_auth(NoAuth)
            .http_client(response)
            .clock(time.clone())
            .token_endpoint("https://as.example/token".parse().unwrap())
            .authorization_endpoint("https://as.example/authorize".parse().unwrap())
            .pushed_authorization_request_endpoint("https://as.example/par".parse().unwrap())
            .prefer_pushed_authorization_requests(true)
            .redirect_uri("https://client.example/callback")
            .build()
            .await?;
        Ok(grant
            .start(authorization_code::StartInput::builder().build())
            .await?
            .expires_at
            .expect("PAR must set an expiry"))
    } else {
        let grant = device_authorization::DeviceAuthorizationGrant::builder()
            .client_id("client")
            .client_auth(NoAuth)
            .http_client(response)
            .clock(time.clone())
            .token_endpoint("https://as.example/token".parse().unwrap())
            .device_authorization_endpoint("https://as.example/device".parse().unwrap())
            .build();
        Ok(grant
            .start(device_authorization::StartInput::builder().build())
            .await?
            .expires_at)
    }
}

#[rstest]
#[case::par(true)]
#[case::device(false)]
#[tokio::test]
async fn expiry_is_anchored_at_receipt(#[case] par: bool, #[values(0, 90)] expires_in: u64) {
    let initial = jiff::Timestamp::new(1_000, 123_456_789).unwrap();
    let time = ManualTime::new(initial);
    let expiry = start(par, &time, expires_in).await.unwrap();
    let received = initial.checked_add(Duration::from_secs(7)).unwrap();
    assert_eq!(time.now(), received);
    assert_eq!(
        expiry,
        huskarl_core::time::system_time_from_timestamp(
            received
                .checked_add(Duration::from_secs(expires_in))
                .unwrap()
        )
        .unwrap()
    );
}

#[rstest]
#[case::par(true)]
#[case::device(false)]
#[tokio::test]
async fn maximum_receipt_time_returns_error(#[case] par: bool) {
    let time = ManualTime::new(
        jiff::Timestamp::MAX
            .checked_sub(Duration::from_secs(7))
            .unwrap(),
    );
    let err = start(par, &time, 90).await.unwrap_err();
    assert_eq!(time.now(), jiff::Timestamp::MAX);
    assert_eq!(err.retry_advice(), RetryAdvice::No);
    assert!(format!("{err:#}").contains("outside the representable range"));
}

#[tokio::test]
async fn oversized_par_lifetime_returns_error() {
    let time = ManualTime::new(jiff::Timestamp::UNIX_EPOCH);
    let err = start(true, &time, u64::MAX).await.unwrap_err();
    assert_eq!(err.retry_advice(), RetryAdvice::No);
    assert!(format!("{err:#}").contains("outside the representable range"));
}

#[rstest]
#[case::throttled(http::StatusCode::TOO_MANY_REQUESTS)]
#[case::unavailable(http::StatusCode::SERVICE_UNAVAILABLE)]
#[case::oauth(http::StatusCode::BAD_REQUEST)]
#[tokio::test]
async fn retry_after_is_anchored_at_receipt(#[case] status: http::StatusCode) {
    let time = ManualTime::new(jiff::Timestamp::new(1_000, 250_000_000).unwrap());
    let grant = device_authorization::DeviceAuthorizationGrant::builder()
        .client_id("client")
        .client_auth(NoAuth)
        .clock(time.clone())
        .http_client(DelayedResponse {
            time: time.clone(),
            status,
            body: r#"{"error":"temporarily_unavailable"}"#.into(),
        })
        .token_endpoint("https://as.example/token".parse().unwrap())
        .device_authorization_endpoint("https://as.example/device".parse().unwrap())
        .build();
    let error = grant
        .start(device_authorization::StartInput::builder().build())
        .await
        .unwrap_err();
    time.advance(Duration::from_secs(100)).unwrap();
    assert_eq!(
        error.retry_advice(),
        RetryAdvice::retry_after(Duration::from_millis(52_750))
    );
    assert_eq!(
        error.verdict().is_some(),
        status == http::StatusCode::BAD_REQUEST
    );
}

// A downstream grant written against the old authentication hook must still
// control authentication when exchange calls the new timestamp-aware hook.
struct LegacyGrant(crate::grant::client_credentials::ClientCredentialsGrant);

impl super::OAuth2ExchangeGrant for LegacyGrant {
    type Parameters = <crate::grant::client_credentials::ClientCredentialsGrant as super::OAuth2ExchangeGrant>::Parameters;
    type Form<'a> = <crate::grant::client_credentials::ClientCredentialsGrant as super::OAuth2ExchangeGrant>::Form<'a>;

    fn client_id(&self) -> Option<&str> {
        self.0.client_id()
    }
    fn issuer(&self) -> Option<&str> {
        self.0.issuer()
    }
    fn client_auth(&self) -> Option<&dyn crate::core::client_auth::ClientAuthentication> {
        self.0.client_auth()
    }
    fn token_endpoint(&self) -> &crate::core::EndpointUrl {
        self.0.token_endpoint()
    }
    fn dpop(&self) -> &dyn crate::core::dpop::AuthorizationServerDPoP {
        self.0.dpop()
    }
    fn http_client(&self) -> &dyn HttpClient {
        self.0.http_client()
    }
    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        self.0.build_form(params)
    }
    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.0.allowed_auth_methods()
    }
    fn to_refresh_grant(&self) -> crate::grant::refresh::RefreshGrant {
        self.0.to_refresh_grant()
    }
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "fixture tests a legacy async authentication override"
    )]
    async fn authentication_params(
        &self,
    ) -> Result<crate::core::client_auth::AuthenticationParams<'_>, Error> {
        Err(Error::new(
            RetryAdvice::No,
            "legacy authentication override",
        ))
    }
}

#[tokio::test]
async fn exchange_preserves_legacy_authentication_override() {
    use super::OAuth2ExchangeGrant;
    let time = ManualTime::default();
    let grant = LegacyGrant(
        crate::grant::client_credentials::ClientCredentialsGrant::builder()
            .client_id("client")
            .client_auth(NoAuth)
            .token_endpoint("https://as.example/token".parse().unwrap())
            .http_client(DelayedResponse {
                time: time.clone(),
                body: String::new(),
                status: http::StatusCode::OK,
            })
            .build(),
    );
    let err = grant
        .exchange(crate::grant::client_credentials::ClientCredentialsGrantParameters::default())
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("legacy authentication override"));
    assert_eq!(time.now(), jiff::Timestamp::UNIX_EPOCH);
}
