//! Dex-backed [`TestProvider`]. Uses a static client from `integration/dex/config.yaml`.

use async_trait::async_trait;

use crate::{
    provider::{Error, TestProvider},
    spec::{ClientSpec, Features, ProvisionedClient, Transport},
};

pub struct DexProvider {
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    name: String,
}

impl DexProvider {
    pub const FEATURES: Features = Features::AUTH_CODE;

    pub async fn local() -> Result<Self, Error> {
        Ok(Self {
            issuer: "http://127.0.0.1:5556/dex".to_owned(),
            client_id: "huskarl-authcode".to_owned(),
            client_secret: "huskarl-authcode-secret".to_owned(),
            redirect_uri: "http://127.0.0.1:5557/callback".to_owned(),
            name: "dex".to_owned(),
        })
    }
}

#[async_trait]
impl TestProvider for DexProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn issuer(&self, _transport: Transport) -> String {
        self.issuer.clone()
    }

    fn auth_code_redirect_uri(&self, _features: Features) -> Option<String> {
        Some(self.redirect_uri.clone())
    }

    async fn provision_client(&self, spec: ClientSpec) -> Result<ProvisionedClient, Error> {
        if !Self::FEATURES.contains(spec.features) {
            return Err(format!(
                "Dex static client does not support requested features {:?}",
                spec.features
            )
            .into());
        }
        Ok(ProvisionedClient {
            client_id: self.client_id.clone(),
            secret: Some(self.client_secret.clone()),
            redirect_uris: vec![self.redirect_uri.clone()],
        })
    }

    async fn authenticate(&self, authorize_url: &str) -> Result<(), Error> {
        // Mock connector auto-authenticates; the whole login is a redirect chain.
        let browser = reqwest::Client::builder().cookie_store(true).build()?;
        browser.get(authorize_url).send().await?;
        Ok(())
    }
}
