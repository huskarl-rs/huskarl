//! Okta-backed [`TestProvider`] (hosted — no Docker).
//!
//! Nothing is provisioned per test: one shared user and long-lived clients (one
//! per auth-code variant, each on a distinct loopback port) are ensured
//! idempotently. Scoped to the authorization-code family.
//!
//! Config (env): `OKTA_DOMAIN`, `OKTA_API_TOKEN` (SSWS token with users/apps/
//! clients/trustedOrigins/policies manage scopes), `OKTA_NO_MFA_GROUP_ID`
//! (password-only global sign-on group), `OKTA_AUTH_POLICY_ID` (password-only
//! app auth policy), `OKTA_AUTH_SERVER_ID` (default `default`). Both policies
//! must be password-only or the headless login hits MFA.

use std::env;

use async_trait::async_trait;
use huskarl_core::jwk::PublicJwk;
use serde::Deserialize;

use crate::{
    provider::{Error, TestProvider, ensure_success},
    spec::{ClientSpec, Features, ProvisionedClient, Transport},
};

/// A [`TestProvider`] backed by a hosted Okta tenant.
pub struct OktaProvider {
    /// Tenant base URL, no trailing slash.
    base_url: String,
    auth_server_id: String,
    api_token: String,
    no_mfa_group_id: String,
    auth_policy_id: String,
    http: reqwest::Client,
    name: String,
}

/// Maps an auth-code variant to a stable client name and distinct loopback port.
fn client_slot(features: Features) -> (&'static str, u16) {
    if features.contains(Features::JAR) {
        ("huskarl-authcode-jar", 17853)
    } else if features.contains(Features::PAR) {
        ("huskarl-authcode-par", 17852)
    } else {
        ("huskarl-authcode-direct", 17851)
    }
}

fn redirect_for_port(port: u16) -> String {
    format!("http://127.0.0.1:{port}/callback")
}

impl OktaProvider {
    pub const FEATURES: Features = Features::AUTH_CODE
        .union(Features::PAR)
        .union(Features::JAR);

    // Password shares no substring with the login (Okta rejects that).
    const TEST_USER_LOGIN: &'static str = "huskarl-shared-test@example.com";
    const TEST_USER_PASSWORD: &'static str = "Vb7Kq2Np9Xz!";

    /// Builds a provider from the `OKTA_*` environment (see module docs).
    pub async fn local() -> Result<Self, Error> {
        let base_url = env::var("OKTA_DOMAIN")
            .map_err(|_| "OKTA_DOMAIN is not set")?
            .trim_end_matches('/')
            .to_owned();
        let api_token = env::var("OKTA_API_TOKEN").map_err(|_| "OKTA_API_TOKEN is not set")?;
        let no_mfa_group_id = env::var("OKTA_NO_MFA_GROUP_ID")
            .map_err(|_| "OKTA_NO_MFA_GROUP_ID is not set (password-only global sign-on)")?;
        let auth_policy_id = env::var("OKTA_AUTH_POLICY_ID").map_err(
            |_| "OKTA_AUTH_POLICY_ID is not set (password-only app authentication policy)",
        )?;
        let auth_server_id =
            env::var("OKTA_AUTH_SERVER_ID").unwrap_or_else(|_| "default".to_owned());

        Ok(Self {
            name: format!("okta[{auth_server_id}]"),
            base_url,
            auth_server_id,
            api_token,
            no_mfa_group_id,
            auth_policy_id,
            http: reqwest::Client::new(),
        })
    }

    fn ssws(&self) -> String {
        format!("SSWS {}", self.api_token)
    }

    /// Ensures a long-lived OIDC client exists, returning `(client_id, secret)`.
    /// When `jwks` is given (JAR), the client's key set is refreshed to it.
    async fn ensure_client(
        &self,
        name: &str,
        redirect_uri: &str,
        jwks: Option<&PublicJwk>,
    ) -> Result<(String, String), Error> {
        if let Some((client_id, secret)) = self.find_client(name).await? {
            if let Some(jwk) = jwks {
                self.update_client_jwks(&client_id, jwk).await?;
            }
            return Ok((client_id, secret));
        }
        self.create_client(name, redirect_uri, jwks).await
    }

    /// Finds a confidential client by its exact label, returning `(client_id, secret)`.
    async fn find_client(&self, name: &str) -> Result<Option<(String, String)>, Error> {
        #[derive(Deserialize)]
        struct App {
            label: String,
            credentials: Credentials,
        }
        #[derive(Deserialize)]
        struct Credentials {
            #[serde(rename = "oauthClient")]
            oauth_client: OauthClient,
        }
        #[derive(Deserialize)]
        struct OauthClient {
            client_id: String,
            client_secret: Option<String>,
        }
        let resp = self
            .http
            .get(format!("{}/api/v1/apps?q={name}&limit=5", self.base_url))
            .header("Authorization", self.ssws())
            .send()
            .await?;
        let apps: Vec<App> = ensure_success(resp, "list apps").await?.json().await?;
        Ok(apps.into_iter().find(|a| a.label == name).and_then(|a| {
            a.credentials
                .oauth_client
                .client_secret
                .map(|s| (a.credentials.oauth_client.client_id, s))
        }))
    }

    /// Creates a confidential auth-code client via DCR.
    async fn create_client(
        &self,
        name: &str,
        redirect_uri: &str,
        jwks: Option<&PublicJwk>,
    ) -> Result<(String, String), Error> {
        #[derive(Deserialize)]
        struct DcrResponse {
            client_id: String,
            client_secret: Option<String>,
        }
        let mut body = serde_json::json!({
            "client_name": name,
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            // Confidential web app so Okta returns a secret.
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",
        });
        if let Some(jwk) = jwks {
            body["jwks"] = serde_json::json!({ "keys": [jwk] });
            body["request_object_signing_alg"] = serde_json::Value::from("ES256");
        }
        let resp = self
            .http
            .post(format!("{}/oauth2/v1/clients", self.base_url))
            .header("Authorization", self.ssws())
            .json(&body)
            .send()
            .await?;
        let r: DcrResponse = ensure_success(resp, &format!("create client {name}"))
            .await?
            .json()
            .await?;
        let secret = r
            .client_secret
            .ok_or("created client has no secret (registered as public?)")?;
        Ok((r.client_id, secret))
    }

    /// Refreshes a client's JWKS via a GET-modify-PUT round-trip.
    async fn update_client_jwks(&self, client_id: &str, jwk: &PublicJwk) -> Result<(), Error> {
        let url = format!("{}/oauth2/v1/clients/{client_id}", self.base_url);
        let resp = self
            .http
            .get(&url)
            .header("Authorization", self.ssws())
            .send()
            .await?;
        let mut client: serde_json::Value =
            ensure_success(resp, "get client").await?.json().await?;
        client["jwks"] = serde_json::json!({ "keys": [jwk] });
        client["request_object_signing_alg"] = serde_json::Value::from("ES256");
        ensure_success(
            self.http
                .put(&url)
                .header("Authorization", self.ssws())
                .json(&client)
                .send()
                .await?,
            "update client jwks",
        )
        .await?;
        Ok(())
    }

    /// Assigns the shared user to a client so it's authorized at `/authorize`.
    async fn assign_user_to_app(&self, app_id: &str, user_id: &str) -> Result<(), Error> {
        let resp = self
            .http
            .post(format!("{}/api/v1/apps/{app_id}/users", self.base_url))
            .header("Authorization", self.ssws())
            .json(&serde_json::json!({ "id": user_id, "scope": "USER" }))
            .send()
            .await?;
        ensure_success(resp, "assign_user_to_app").await?;
        Ok(())
    }

    /// Maps an app to the password-only auth policy so `/authorize` skips MFA.
    async fn assign_app_to_policy(&self, app_id: &str) -> Result<(), Error> {
        ensure_success(
            self.http
                .put(format!(
                    "{}/api/v1/apps/{app_id}/policies/{}",
                    self.base_url, self.auth_policy_id
                ))
                .header("Authorization", self.ssws())
                .send()
                .await?,
            "assign_app_to_policy",
        )
        .await?;
        Ok(())
    }

    /// Ensures a loopback `origin` is a Trusted Origin so Okta will 302 to it.
    /// Idempotent and race-safe across parallel tests.
    async fn ensure_trusted_origin(&self, origin: &str) -> Result<(), Error> {
        if self.trusted_origin_exists(origin).await? {
            return Ok(());
        }
        let body = serde_json::json!({
            "name": format!("huskarl loopback {origin}"),
            "origin": origin,
            "scopes": [ { "type": "REDIRECT" }, { "type": "CORS" } ],
        });
        let resp = self
            .http
            .post(format!("{}/api/v1/trustedOrigins", self.base_url))
            .header("Authorization", self.ssws())
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            // A parallel test may have just created it.
            if self.trusted_origin_exists(origin).await? {
                return Ok(());
            }
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("create trusted origin {origin} failed ({status}): {text}").into());
        }
        Ok(())
    }

    async fn trusted_origin_exists(&self, origin: &str) -> Result<bool, Error> {
        #[derive(Deserialize)]
        struct TrustedOrigin {
            origin: String,
        }
        let resp = self
            .http
            .get(format!("{}/api/v1/trustedOrigins?limit=200", self.base_url))
            .header("Authorization", self.ssws())
            .send()
            .await?;
        let origins: Vec<TrustedOrigin> = ensure_success(resp, "list trusted origins")
            .await?
            .json()
            .await?;
        Ok(origins.iter().any(|t| t.origin == origin))
    }

    /// Ensures the shared test user exists and returns its id. Idempotent: on
    /// create-failure (Okta reports duplicate as 400, not 409) look up by login.
    async fn ensure_user(&self) -> Result<String, Error> {
        #[derive(Deserialize)]
        struct UserResponse {
            id: String,
        }
        let body = serde_json::json!({
            "profile": {
                "firstName": "Test",
                "lastName": "User",
                "email": Self::TEST_USER_LOGIN,
                "login": Self::TEST_USER_LOGIN,
            },
            "credentials": { "password": { "value": Self::TEST_USER_PASSWORD } },
        });
        let resp = self
            .http
            .post(format!("{}/api/v1/users?activate=true", self.base_url))
            .header("Authorization", self.ssws())
            .json(&body)
            .send()
            .await?;
        if resp.status().is_success() {
            return Ok(resp.json::<UserResponse>().await?.id);
        }
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if let Ok(id) = self.user_id_by_login(Self::TEST_USER_LOGIN).await {
            return Ok(id);
        }
        Err(format!("ensure_user create failed ({status}): {text}").into())
    }

    async fn user_id_by_login(&self, login: &str) -> Result<String, Error> {
        #[derive(Deserialize)]
        struct UserResponse {
            id: String,
        }
        let resp = self
            .http
            .get(format!("{}/api/v1/users/{login}", self.base_url))
            .header("Authorization", self.ssws())
            .send()
            .await?;
        let resp = ensure_success(resp, &format!("lookup user {login}")).await?;
        Ok(resp.json::<UserResponse>().await?.id)
    }

    async fn add_user_to_no_mfa_group(&self, user_id: &str) -> Result<(), Error> {
        ensure_success(
            self.http
                .put(format!(
                    "{}/api/v1/groups/{}/users/{user_id}",
                    self.base_url, self.no_mfa_group_id
                ))
                .header("Authorization", self.ssws())
                .send()
                .await?,
            "add_user_to_no_mfa_group",
        )
        .await?;
        Ok(())
    }

    /// Primary auth (`POST /api/v1/authn`) → one-time `sessionToken`.
    async fn primary_auth(&self, login: &str, password: &str) -> Result<String, Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct AuthnResponse {
            status: String,
            session_token: Option<String>,
        }
        let body = serde_json::json!({
            "username": login,
            "password": password,
            "options": {
                "multiOptionalFactorEnroll": false,
                "warnBeforePasswordExpired": false,
            },
        });
        let resp = self
            .http
            .post(format!("{}/api/v1/authn", self.base_url))
            .json(&body)
            .send()
            .await?;
        let resp = ensure_success(resp, "primary auth").await?;
        let authn: AuthnResponse = resp.json().await?;
        authn.session_token.ok_or_else(|| {
            format!(
                "primary auth returned status {:?} without a sessionToken \
                 (expected SUCCESS — is the user under a password-only policy?)",
                authn.status
            )
            .into()
        })
    }
}

#[async_trait]
impl TestProvider for OktaProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn issuer(&self, _transport: Transport) -> String {
        format!("{}/oauth2/{}", self.base_url, self.auth_server_id)
    }

    fn auth_code_redirect_uri(&self, features: Features) -> Option<String> {
        Some(redirect_for_port(client_slot(features).1))
    }

    async fn provision_client(&self, spec: ClientSpec) -> Result<ProvisionedClient, Error> {
        let (name, port) = client_slot(spec.features);
        let redirect_uri = redirect_for_port(port);
        let (client_id, secret) = self
            .ensure_client(name, &redirect_uri, spec.signing_jwk.as_ref())
            .await?;

        // /authorize requires the loopback be a Trusted Origin and the app's
        // policy not demand a second factor.
        self.ensure_trusted_origin(&format!("http://127.0.0.1:{port}"))
            .await?;
        self.assign_app_to_policy(&client_id).await?;

        // Authorize the shared user up front, not at login time, to avoid a race.
        let user_id = self.ensure_user().await?;
        self.add_user_to_no_mfa_group(&user_id).await?;
        self.assign_user_to_app(&client_id, &user_id).await?;

        Ok(ProvisionedClient {
            client_id,
            secret: Some(secret),
            redirect_uris: vec![redirect_uri],
        })
    }

    async fn authenticate(&self, authorize_url: &str) -> Result<(), Error> {
        // OIE ignores a sessionToken passed straight to /authorize, so: primary
        // auth → sessionToken → /login/sessionCookieRedirect (sets the cookie,
        // redirects to /authorize) → cookie-authenticated /authorize issues the
        // code to the loopback. We follow the redirect chain by hand.
        let session_token = self
            .primary_auth(Self::TEST_USER_LOGIN, Self::TEST_USER_PASSWORD)
            .await?;

        let browser = reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15))
            .build()?;

        let mut start =
            reqwest::Url::parse(&format!("{}/login/sessionCookieRedirect", self.base_url))?;
        start
            .query_pairs_mut()
            .append_pair("token", &session_token)
            .append_pair("redirectUrl", authorize_url);
        let mut next = start.to_string();

        for _ in 0..8 {
            let resp = browser.get(&next).send().await?;
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|l| l.to_str().ok())
                .map(ToOwned::to_owned);
            match location {
                // Match by prefix: /authorize embeds the loopback as a query
                // param, so `contains` would mis-fire.
                Some(loc) if loc.starts_with("http://127.0.0.1") => {
                    browser.get(&loc).send().await?;
                    return Ok(());
                }
                Some(loc) => next = loc,
                None => {
                    return Err(format!(
                        "Okta did not redirect to the loopback (status {}); the user may \
                         not be authorized for the client, or a second factor was required",
                        resp.status()
                    )
                    .into());
                }
            }
        }
        Err("Okta /authorize exceeded the redirect-hop budget without reaching the loopback".into())
    }
}
