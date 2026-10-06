//! Authentik-backed [`TestProvider`], configured by a local blueprint.
//!
//! Tokens use the client ID as their audience. The shared clients are immutable,
//! so independent test processes can safely exercise it concurrently.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use async_trait::async_trait;
use reqwest::cookie::CookieStore;
use serde_json::{Value, json};

use crate::{
    provider::{Error, TestProvider, ensure_success},
    spec::{ClientSpec, Features, ProvisionedClient, Transport},
};

pub struct AuthentikProvider {
    auth_code: AtomicBool,
}

impl AuthentikProvider {
    // The generic refresh flow requires refresh tokens from client credentials,
    // which Authentik does not issue.
    pub const FEATURES: Features = Features::CLIENT_CREDENTIALS
        .union(Features::INTROSPECTION)
        .union(Features::AUTH_CODE);
    const CLIENT_ID: &str = "huskarl-rs";

    const REDIRECT_URI: &str = "http://127.0.0.1:9001/callback";
    const BASE: &str = "http://127.0.0.1:9000";

    pub async fn local() -> Result<Self, Error> {
        Ok(Self {
            auth_code: AtomicBool::new(false),
        })
    }
}

#[async_trait]
impl TestProvider for AuthentikProvider {
    fn name(&self) -> &str {
        "authentik"
    }

    fn issuer(&self, _transport: Transport) -> String {
        let slug = if self.auth_code.load(Ordering::Relaxed) {
            "huskarl-authcode"
        } else {
            "huskarl"
        };
        format!("{}/application/o/{slug}/", Self::BASE)
    }

    fn uses_oidc_discovery(&self) -> bool {
        true
    }

    fn auth_code_redirect_uri(&self, _features: Features) -> Option<String> {
        Some(Self::REDIRECT_URI.to_owned())
    }

    async fn provision_client(&self, spec: ClientSpec) -> Result<ProvisionedClient, Error> {
        if !Self::FEATURES.contains(spec.features) {
            return Err(format!(
                "Authentik static client does not support requested features {:?}",
                spec.features
            )
            .into());
        }
        if spec.features == Features::AUTH_CODE {
            if spec.redirect_uris != [Self::REDIRECT_URI]
                || spec.signing_jwk.is_some()
                || spec.audience.is_some()
            {
                return Err("Authentik auth-code client requires its fixed redirect and no custom audience or key".into());
            }
            self.auth_code.store(true, Ordering::Relaxed);
            return Ok(ProvisionedClient {
                client_id: "huskarl-authcode".to_owned(),
                secret: Some("huskarl-authcode-secret".into()),
                redirect_uris: spec.redirect_uris,
            });
        }
        if spec.features.contains(Features::AUTH_CODE) {
            return Err("Authentik uses separate auth-code and client-credentials clients".into());
        }
        if spec
            .audience
            .as_deref()
            .is_some_and(|aud| aud != Self::CLIENT_ID)
        {
            return Err("Authentik static client audience must equal huskarl-rs".into());
        }
        if !spec.redirect_uris.is_empty() || spec.signing_jwk.is_some() {
            return Err("Authentik static client does not support redirects or client keys".into());
        }
        self.auth_code.store(false, Ordering::Relaxed);
        Ok(ProvisionedClient {
            client_id: Self::CLIENT_ID.to_owned(),
            secret: Some("huskarl-authentik-secret".into()),
            redirect_uris: vec![],
        })
    }

    async fn authenticate(&self, authorize_url: &str) -> Result<(), Error> {
        // Each login gets an isolated session. Drive the same challenge API as
        // Authentik's browser UI, preserving its original query and CSRF cookie.
        let cookies = Arc::new(reqwest::cookie::Jar::default());
        let browser = reqwest::Client::builder()
            .cookie_provider(cookies.clone())
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        let origin = reqwest::Url::parse(Self::BASE)?;
        let mut page = ensure_success(
            browser.get(authorize_url).send().await?,
            "start Authentik login",
        )
        .await?;
        for _ in 0..4 {
            let page_url = page.url().clone();
            if page_url.as_str().split('?').next() == Some(Self::REDIRECT_URI) {
                return Ok(());
            }
            if page_url.origin() != origin.origin() {
                return Err("Authentik login redirected to an unexpected origin".into());
            }
            let slug = page_url
                .path()
                .strip_prefix("/if/flow/")
                .and_then(|path| path.strip_suffix('/'))
                .filter(|slug| !slug.is_empty() && !slug.contains('/'))
                .ok_or("Authentik login did not reach a flow page")?;
            let mut executor = origin.join(&format!("/api/v3/flows/executor/{slug}/"))?;
            executor
                .query_pairs_mut()
                .append_pair("query", page_url.query().unwrap_or_default());
            let mut challenge: Value = ensure_success(
                browser
                    .get(executor.clone())
                    .header("Accept", "application/json")
                    .send()
                    .await?,
                "get Authentik challenge",
            )
            .await?
            .json()
            .await?;
            let mut redirect = None;
            for _ in 0..8 {
                if let Some(errors) = challenge.get("response_errors")
                    && errors.as_object().is_none_or(|errors| !errors.is_empty())
                {
                    return Err(format!("Authentik login challenge rejected: {errors}").into());
                }
                let component = challenge["component"]
                    .as_str()
                    .ok_or("Authentik challenge missing component")?;
                let answer = match component {
                    "ak-stage-identification" => {
                        json!({"component": component, "uid_field": "huskarl-test-user"})
                    }
                    "ak-stage-password" => {
                        json!({"component": component, "password": "huskarl-test-password"})
                    }
                    "xak-flow-redirect" => {
                        redirect = Some(
                            origin.join(
                                challenge["to"]
                                    .as_str()
                                    .ok_or("Authentik redirect missing target")?,
                            )?,
                        );
                        break;
                    }
                    _ => {
                        return Err(
                            format!("Unexpected Authentik login challenge: {component}").into()
                        );
                    }
                };
                let mut request = browser
                    .post(executor.clone())
                    .header("Accept", "application/json")
                    .header("Referer", page_url.as_str())
                    .json(&answer);
                // Anonymous challenges may not set a CSRF cookie. Echo it once
                // Authentik supplies one, including after the session logs in.
                if let Some(cookie_header) = cookies.cookies(&executor)
                    && let Some(csrf) = cookie_header
                        .to_str()?
                        .split(';')
                        .find_map(|cookie| cookie.trim().strip_prefix("authentik_csrf="))
                {
                    request = request.header("X-authentik-CSRF", csrf);
                }
                challenge = ensure_success(request.send().await?, "answer Authentik challenge")
                    .await?
                    .json()
                    .await?;
            }
            let redirect = redirect.ok_or("Authentik login exceeded challenge limit")?;
            if redirect.origin() != origin.origin()
                && redirect.as_str().split('?').next() != Some(Self::REDIRECT_URI)
            {
                return Err("Authentik flow redirected to an unexpected origin".into());
            }
            page = ensure_success(
                browser.get(redirect).send().await?,
                "follow Authentik flow redirect",
            )
            .await?;
        }
        Err("Authentik login exceeded flow limit".into())
    }
}
