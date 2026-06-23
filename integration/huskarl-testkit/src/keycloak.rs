//! Keycloak-backed [`TestProvider`] and its low-level Admin REST API client.
//!
//! Each provider owns a fresh ephemeral realm, deleted by [`TestProvider::teardown`].

use std::{collections::HashMap, ops::Deref, path::PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    provider::{Error, TestProvider, ensure_success},
    spec::{ClientSpec, Features, MtlsMaterial, ProvisionedClient, Transport},
};

/// A [`TestProvider`] backed by a real Keycloak instance.
pub struct KeycloakProvider {
    realm: TestRealm,
    name: String,
}

impl KeycloakProvider {
    pub const FEATURES: Features = Features::all();

    /// Provider on a fresh realm of the local integration Keycloak.
    pub async fn local() -> Result<Self, Error> {
        Self::with_admin(KeycloakAdmin::local()).await
    }

    /// Provider on a fresh realm of the given admin endpoint.
    pub async fn with_admin(admin: KeycloakAdmin) -> Result<Self, Error> {
        let realm = admin.create_realm().await?;
        let name = format!("keycloak[{}]", realm.name);
        Ok(Self { realm, name })
    }

    pub fn realm(&self) -> &TestRealm {
        &self.realm
    }
}

/// Directory holding the committed test mTLS PKI.
fn certs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../keycloak/certs")
}

#[async_trait]
impl TestProvider for KeycloakProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn issuer(&self, transport: Transport) -> String {
        match transport {
            Transport::Plain => self.realm.issuer(),
            Transport::Mtls => self.realm.mtls_issuer(),
        }
    }

    fn mtls_material(&self) -> Option<MtlsMaterial> {
        let certs = certs_dir();
        Some(MtlsMaterial {
            ca_pem: std::fs::read(certs.join("ca.pem")).ok()?,
            client_identity_pem: std::fs::read_to_string(certs.join("client-identity.pem")).ok()?,
            client_cert_pem: std::fs::read_to_string(certs.join("client.pem")).ok()?,
        })
    }

    async fn provision_client(&self, spec: ClientSpec) -> Result<ProvisionedClient, Error> {
        let client_id = format!("client-{}", Uuid::new_v4());
        let secret = format!("secret-{}", Uuid::new_v4());
        let body = ClientRepresentation::build(&spec, &client_id, &secret);

        self.realm.create_client(&body).await?;

        Ok(ProvisionedClient {
            client_id,
            secret: Some(secret),
            redirect_uris: spec.redirect_uris,
        })
    }

    async fn teardown(&self) -> Result<(), Error> {
        self.realm.delete().await
    }

    async fn authenticate(&self, authorize_url: &str) -> Result<(), Error> {
        // A complete, verified profile avoids Keycloak's VERIFY_PROFILE action
        // that would block the redirect back to the loopback.
        let username = format!("user-{}", Uuid::new_v4());
        let password = "test-password-123";
        let user = UserRepresentation {
            username: username.clone(),
            enabled: true,
            email: Some(format!("{username}@example.test")),
            first_name: Some("Test".to_owned()),
            last_name: Some("User".to_owned()),
            email_verified: Some(true),
            credentials: vec![CredentialRepresentation {
                credential_type: "password",
                value: password.to_owned(),
                temporary: false,
            }],
        };
        self.realm.create_user(&user).await?;

        let browser = reqwest::Client::builder().cookie_store(true).build()?;

        let login_html = browser.get(authorize_url).send().await?.text().await?;
        let action = extract_login_action(&login_html)
            .ok_or("could not locate the Keycloak login form action")?;

        // POST credentials; Keycloak 302s to the loopback redirect URI.
        browser
            .post(&action)
            .form(&[
                ("username", username.as_str()),
                ("password", password),
                ("credentialId", ""),
            ])
            .send()
            .await?;

        Ok(())
    }
}

/// Extracts the POST action URL from the `kc-form-login` form, `&amp;`-unescaped.
fn extract_login_action(html: &str) -> Option<String> {
    let anchor = html.find("kc-form-login")?;
    let after = &html[anchor..];
    let start = after.find("action=\"")? + "action=\"".len();
    let tail = &after[start..];
    let end = tail.find('"')?;
    Some(tail[..end].replace("&amp;", "&"))
}

/// Client for the Keycloak Admin REST API (master realm).
#[derive(Clone)]
pub struct KeycloakAdmin {
    http: reqwest::Client,
    base_url: String,
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RealmRepresentation {
    realm: String,
    enabled: bool,
}

impl KeycloakAdmin {
    pub fn new(
        base_url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
            username: username.into(),
            password: password.into(),
        }
    }

    /// Admin client for the local integration test environment.
    pub fn local() -> Self {
        Self::new("http://localhost:8080", "admin", "admin")
    }

    async fn bearer_token(&self) -> Result<String, Error> {
        let token_endpoint = format!(
            "{}/realms/master/protocol/openid-connect/token",
            self.base_url
        );

        let response = self
            .http
            .post(&token_endpoint)
            .form(&[
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", self.username.as_str()),
                ("password", self.password.as_str()),
            ])
            .send()
            .await?;

        let response = ensure_success(response, "admin token exchange").await?;
        Ok(response.json::<TokenResponse>().await?.access_token)
    }

    /// Creates a fresh realm with a random name.
    pub async fn create_realm(&self) -> Result<TestRealm, Error> {
        let name = format!("huskarl-test-{}", Uuid::new_v4());
        let token = self.bearer_token().await?;

        let body = RealmRepresentation {
            realm: name.clone(),
            enabled: true,
        };

        let response = self
            .http
            .post(format!("{}/admin/realms", self.base_url))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;

        ensure_success(response, "create_realm").await?;

        Ok(TestRealm {
            admin: self.clone(),
            name,
        })
    }

    async fn delete_realm(&self, name: &str) -> Result<(), Error> {
        let token = self.bearer_token().await?;

        let response = self
            .http
            .delete(format!("{}/admin/realms/{name}", self.base_url))
            .bearer_auth(&token)
            .send()
            .await?;

        ensure_success(response, "delete_realm").await?;
        Ok(())
    }
}

/// A Keycloak realm created for a single test, deleted by [`Self::delete`].
pub struct TestRealm {
    admin: KeycloakAdmin,
    pub name: String,
}

impl Deref for TestRealm {
    type Target = KeycloakAdmin;
    fn deref(&self) -> &KeycloakAdmin {
        &self.admin
    }
}

impl TestRealm {
    /// Issuer URL for this realm (`{base_url}/realms/{name}`).
    pub fn issuer(&self) -> String {
        format!("{}/realms/{}", self.base_url, self.name)
    }

    /// HTTPS issuer URL for mTLS flows. Keycloak computes `iss` from the request
    /// URL, so mTLS tokens carry this HTTPS issuer. Host 8444 maps to container 8443.
    pub fn mtls_issuer(&self) -> String {
        format!("https://localhost:8444/realms/{}", self.name)
    }

    async fn create_user(&self, body: &UserRepresentation) -> Result<(), Error> {
        let token = self.bearer_token().await?;

        let response = self
            .http
            .post(format!(
                "{}/admin/realms/{}/users",
                self.base_url, self.name
            ))
            .bearer_auth(&token)
            .json(body)
            .send()
            .await?;

        ensure_success(response, "create_user").await?;
        Ok(())
    }

    async fn create_client(&self, body: &ClientRepresentation) -> Result<(), Error> {
        let token = self.bearer_token().await?;

        let response = self
            .http
            .post(format!(
                "{}/admin/realms/{}/clients",
                self.base_url, self.name
            ))
            .bearer_auth(&token)
            .json(body)
            .send()
            .await?;

        ensure_success(response, "create_client").await?;
        Ok(())
    }

    /// Deletes this realm. Called by [`KeycloakProvider::teardown`].
    pub async fn delete(&self) -> Result<(), Error> {
        self.admin.delete_realm(&self.name).await
    }
}

/// Keycloak `ClientRepresentation` for `POST /admin/realms/{realm}/clients`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientRepresentation {
    client_id: String,
    secret: String,
    enabled: bool,
    protocol: &'static str,
    public_client: bool,
    /// `client-secret` or `client-jwt` (for `private_key_jwt`).
    client_authenticator_type: &'static str,
    service_accounts_enabled: bool,
    standard_flow_enabled: bool,
    direct_access_grants_enabled: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    attributes: HashMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    protocol_mappers: Vec<ProtocolMapperRepresentation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProtocolMapperRepresentation {
    name: String,
    protocol: &'static str,
    protocol_mapper: &'static str,
    config: HashMap<String, String>,
}

impl ClientRepresentation {
    fn build(spec: &ClientSpec, client_id: &str, secret: &str) -> Self {
        let f = spec.features;
        let mut attributes = HashMap::new();

        let service_accounts_enabled = f.contains(Features::CLIENT_CREDENTIALS);
        let standard_flow_enabled = f.contains(Features::AUTH_CODE);
        let redirect_uris = if standard_flow_enabled {
            spec.redirect_uris.clone()
        } else {
            vec![]
        };

        if service_accounts_enabled && f.contains(Features::REFRESH) {
            attributes.insert(
                "client_credentials.use_refresh_token".to_owned(),
                "true".to_owned(),
            );
        }

        if f.contains(Features::DEVICE) {
            attributes.insert(
                "oauth2.device.authorization.grant.enabled".to_owned(),
                "true".to_owned(),
            );
        }

        if f.contains(Features::DPOP) {
            attributes.insert("dpop.bound.access.tokens".to_owned(), "true".to_owned());
        }

        if f.contains(Features::MTLS) {
            attributes.insert(
                "tls.client.certificate.bound.access.tokens".to_owned(),
                "true".to_owned(),
            );
        }

        // Register the client's public key (JAR request objects and
        // private_key_jwt assertions both verify against it).
        if let Some(jwk) = &spec.signing_jwk {
            let jwks = serde_json::json!({ "keys": [jwk] });
            attributes.insert("use.jwks.string".to_owned(), "true".to_owned());
            attributes.insert(
                "jwks.string".to_owned(),
                serde_json::to_string(&jwks).expect("serialize client JWKS"),
            );
            attributes.insert(
                "request.object.signature.alg".to_owned(),
                "ES256".to_owned(),
            );
        }

        let client_authenticator_type = if f.contains(Features::PRIVATE_KEY_JWT) {
            "client-jwt"
        } else {
            "client-secret"
        };

        let protocol_mappers = if let Some(aud) = &spec.audience {
            vec![ProtocolMapperRepresentation {
                name: "audience".to_owned(),
                protocol: "openid-connect",
                protocol_mapper: "oidc-audience-mapper",
                config: [
                    ("included.custom.audience".to_owned(), aud.clone()),
                    ("id.token.claim".to_owned(), "false".to_owned()),
                    ("access.token.claim".to_owned(), "true".to_owned()),
                ]
                .into(),
            }]
        } else {
            vec![]
        };

        Self {
            client_id: client_id.to_owned(),
            secret: secret.to_owned(),
            enabled: true,
            protocol: "openid-connect",
            public_client: false,
            client_authenticator_type,
            service_accounts_enabled,
            standard_flow_enabled,
            direct_access_grants_enabled: false,
            redirect_uris,
            attributes,
            protocol_mappers,
        }
    }
}

/// Keycloak `UserRepresentation` for `POST /admin/realms/{realm}/users`. A
/// complete, verified profile avoids a `VERIFY_PROFILE` step that blocks login.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserRepresentation {
    username: String,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    credentials: Vec<CredentialRepresentation>,
}

#[derive(Serialize)]
struct CredentialRepresentation {
    #[serde(rename = "type")]
    credential_type: &'static str,
    value: String,
    temporary: bool,
}
