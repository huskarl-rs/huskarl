use bon::Builder;
use serde::Serialize;

/// Configuration for creating a Keycloak user in integration tests.
#[derive(Debug, Clone, Builder)]
pub struct UserConfig {
    /// The username.
    #[builder(into)]
    pub username: String,

    /// The initial password (set as non-temporary).
    #[builder(into)]
    pub password: String,
}

/// Minimal Keycloak `UserRepresentation` sent to `POST /admin/realms/{realm}/users`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UserRepresentation {
    username: String,
    enabled: bool,
    credentials: Vec<CredentialRepresentation>,
}

#[derive(Serialize)]
struct CredentialRepresentation {
    #[serde(rename = "type")]
    credential_type: &'static str,
    value: String,
    temporary: bool,
}

impl From<&UserConfig> for UserRepresentation {
    fn from(config: &UserConfig) -> Self {
        Self {
            username: config.username.clone(),
            enabled: true,
            credentials: vec![CredentialRepresentation {
                credential_type: "password",
                value: config.password.clone(),
                temporary: false,
            }],
        }
    }
}
