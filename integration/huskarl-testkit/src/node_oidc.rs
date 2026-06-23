//! node-oidc-provider-backed [`TestProvider`]. Clients via RFC 7591 dynamic
//! registration; login via the built-in `devInteractions` UI.

use async_trait::async_trait;

use crate::{
    provider::{Error, TestProvider, ensure_success},
    spec::{ClientSpec, Features, ProvisionedClient, Transport},
};

pub struct NodeOidcProvider {
    issuer: String,
    name: String,
}

impl NodeOidcProvider {
    pub const FEATURES: Features = Features::AUTH_CODE
        .union(Features::PAR)
        .union(Features::JAR);

    pub async fn local() -> Result<Self, Error> {
        Ok(Self {
            issuer: "http://127.0.0.1:3000".to_owned(),
            name: "node-oidc-provider".to_owned(),
        })
    }

    /// Prefixes a root-relative form action with the issuer origin.
    fn absolute(&self, action: &str) -> String {
        if action.starts_with('/') {
            format!("{}{action}", self.issuer)
        } else {
            action.to_owned()
        }
    }
}

#[async_trait]
impl TestProvider for NodeOidcProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn issuer(&self, _transport: Transport) -> String {
        self.issuer.clone()
    }

    fn auth_code_redirect_uri(&self, _features: Features) -> Option<String> {
        None
    }

    async fn provision_client(&self, spec: ClientSpec) -> Result<ProvisionedClient, Error> {
        let http = reqwest::Client::new();

        let metadata: serde_json::Value = http
            .get(format!("{}/.well-known/openid-configuration", self.issuer))
            .send()
            .await?
            .json()
            .await?;
        let registration_endpoint = metadata["registration_endpoint"]
            .as_str()
            .ok_or("node-oidc-provider discovery is missing registration_endpoint")?;

        let mut body = serde_json::json!({
            "redirect_uris": spec.redirect_uris,
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
        });
        // JAR: register the client's public key and pin the signing algorithm.
        if let Some(jwk) = &spec.signing_jwk {
            body["jwks"] = serde_json::json!({ "keys": [jwk] });
            body["request_object_signing_alg"] = serde_json::Value::from("ES256");
        }

        let response = ensure_success(
            http.post(registration_endpoint).json(&body).send().await?,
            "dynamic client registration",
        )
        .await?;

        let registered: serde_json::Value = response.json().await?;
        let client_id = registered["client_id"]
            .as_str()
            .ok_or("registration response missing client_id")?
            .to_owned();
        let secret = registered["client_secret"].as_str().map(ToOwned::to_owned);

        Ok(ProvisionedClient {
            client_id,
            secret,
            redirect_uris: spec.redirect_uris,
        })
    }

    async fn authenticate(&self, authorize_url: &str) -> Result<(), Error> {
        // devInteractions accepts any username and ignores the password.
        let browser = reqwest::Client::builder().cookie_store(true).build()?;
        let account = "huskarl-test-user";

        // Drive each interaction page (login, then consent) until one has no
        // interaction form — that's the redirect to the loopback callback.
        let mut page = browser.get(authorize_url).send().await?.text().await?;
        for _ in 0..4 {
            let Some(action) = extract_action_containing(&page, "/interaction/") else {
                return Ok(());
            };
            let prompt =
                extract_hidden_value(&page, "prompt").unwrap_or_else(|| "login".to_owned());

            let mut form: Vec<(&str, &str)> = vec![("prompt", &prompt)];
            if prompt == "login" {
                form.push(("login", account));
                form.push(("password", "huskarl"));
            }

            page = browser
                .post(self.absolute(&action))
                .form(&form)
                .send()
                .await?
                .text()
                .await?;
        }

        Err("devInteractions did not complete within the expected number of prompts".into())
    }
}

/// First form `action="..."` whose value contains `needle`, `&amp;`-unescaped.
fn extract_action_containing(html: &str, needle: &str) -> Option<String> {
    for fragment in html.split("action=\"").skip(1) {
        let end = fragment.find('"')?;
        let action = &fragment[..end];
        if action.contains(needle) {
            return Some(action.replace("&amp;", "&"));
        }
    }
    None
}

/// Reads the `value="..."` of a hidden `<input name="field" ...>`.
fn extract_hidden_value(html: &str, field: &str) -> Option<String> {
    let marker = format!("name=\"{field}\"");
    let at = html.find(&marker)?;
    let tag_start = html[..at].rfind('<')?;
    let tag_end = html[at..].find('>')? + at;
    let tag = &html[tag_start..tag_end];
    let value_at = tag.find("value=\"")? + "value=\"".len();
    let rest = &tag[value_at..];
    let value_end = rest.find('"')?;
    Some(rest[..value_end].to_owned())
}
