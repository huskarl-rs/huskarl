use std::ops::Deref;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::client_config::{ClientConfig, ClientRepresentation};
use crate::user_config::{UserConfig, UserRepresentation};

/// Opaque error type for admin operations.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// The result of a successful [`TestRealm::create_user`] call.
pub struct CreatedUser {
    /// The username (as given in [`UserConfig`]).
    pub username: String,
    /// The password (as given in [`UserConfig`]).
    pub password: String,
    /// The Keycloak-internal UUID.
    pub internal_id: String,
}

/// The result of a successful [`TestRealm::create_client`] call.
pub struct CreatedClient {
    /// The OAuth2 client ID (as given in [`ClientConfig`]).
    pub client_id: String,
    /// The client secret (as given in [`ClientConfig`]).
    pub secret: String,
    /// The Keycloak-internal UUID — used internally for client management.
    pub internal_id: String,
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
    /// Creates a new admin client for the given Keycloak base URL.
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

    /// Creates an admin client preconfigured for the local integration test environment.
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

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("admin token exchange failed ({status}): {body}").into());
        }

        Ok(response.json::<TokenResponse>().await?.access_token)
    }

    /// Creates a fresh Keycloak realm with a random name, returning a [`TestRealm`]
    /// that deletes the realm automatically when dropped.
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

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("create_realm failed ({status}): {body}").into());
        }

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

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("delete_realm failed ({status}): {body}").into());
        }

        Ok(())
    }
}

/// A Keycloak realm created for a single test, deleted automatically on drop.
pub struct TestRealm {
    admin: KeycloakAdmin,
    /// The realm name (a UUID-based unique identifier).
    pub name: String,
}

impl Deref for TestRealm {
    type Target = KeycloakAdmin;
    fn deref(&self) -> &KeycloakAdmin {
        &self.admin
    }
}

impl TestRealm {
    /// Returns the issuer URL for this realm (`{base_url}/realms/{name}`).
    ///
    /// All standard OIDC endpoints are relative to this:
    /// - Token: `{issuer}/protocol/openid-connect/token`
    /// - Auth: `{issuer}/protocol/openid-connect/auth`
    /// - JWKS: `{issuer}/protocol/openid-connect/certs`
    pub fn issuer(&self) -> String {
        format!("{}/realms/{}", self.base_url, self.name)
    }

    /// Returns the token endpoint URL for this realm.
    pub fn token_endpoint(&self) -> String {
        format!("{}/protocol/openid-connect/token", self.issuer())
    }

    /// Returns the HTTPS issuer URL for mTLS flows (`https://localhost:8443/realms/{name}`).
    ///
    /// Use this instead of [`Self::issuer`] when making mTLS token requests. Keycloak computes
    /// the `iss` claim from the incoming request URL, so tokens obtained via the HTTPS
    /// endpoint carry an HTTPS issuer and must be validated against it.
    pub fn mtls_issuer(&self) -> String {
        format!("https://localhost:8443/realms/{}", self.name)
    }

    /// Creates a user in this realm.
    pub async fn create_user(&self, config: &UserConfig) -> Result<CreatedUser, Error> {
        let token = self.bearer_token().await?;
        let body = UserRepresentation::from(config);

        let response = self
            .http
            .post(format!(
                "{}/admin/realms/{}/users",
                self.base_url, self.name
            ))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("create_user failed ({status}): {body}").into());
        }

        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .ok_or("create_user: missing Location header")?
            .to_str()?
            .to_owned();

        let internal_id = location
            .rsplit('/')
            .next()
            .ok_or("create_user: empty Location header")?
            .to_owned();

        Ok(CreatedUser {
            username: config.username.clone(),
            password: config.password.clone(),
            internal_id,
        })
    }

    /// Creates a client in this realm.
    pub async fn create_client(&self, config: &ClientConfig) -> Result<CreatedClient, Error> {
        let token = self.bearer_token().await?;
        let body = ClientRepresentation::from(config);

        let response = self
            .http
            .post(format!(
                "{}/admin/realms/{}/clients",
                self.base_url, self.name
            ))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("create_client failed ({status}): {body}").into());
        }

        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .ok_or("create_client: missing Location header")?
            .to_str()?
            .to_owned();

        let internal_id = location
            .rsplit('/')
            .next()
            .ok_or("create_client: empty Location header")?
            .to_owned();

        Ok(CreatedClient {
            client_id: config.client_id.clone(),
            secret: config.secret.clone(),
            internal_id,
        })
    }
}

impl Drop for TestRealm {
    fn drop(&mut self) {
        let admin = self.admin.clone();
        let name = self.name.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(e) = admin.delete_realm(&name).await {
                    eprintln!("huskarl-testkit: failed to delete realm {name}: {e}");
                }
            });
        }
    }
}
