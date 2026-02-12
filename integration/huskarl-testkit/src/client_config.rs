use std::collections::HashMap;

use bon::Builder;
use serde::Serialize;

/// Configures the OAuth2 flows and token-binding settings for a test client.
///
/// Use the constructor methods rather than constructing variants directly:
///
/// ```rust,no_run
/// use huskarl_testkit::GrantConfig;
/// let _ = GrantConfig::client_credentials();
/// let _ = GrantConfig::client_credentials_with_refresh();
/// let _ = GrantConfig::authorization_code(["http://localhost:8080/callback"]);
/// let _ = GrantConfig::device_authorization();
/// ```
#[derive(Debug, Clone)]
pub enum GrantConfig {
    /// Machine-to-machine via service accounts (RFC 6749 §4.4).
    ClientCredentials {
        /// Issue a refresh token alongside the access token.
        refresh_token: bool,
    },
    /// Authorization code with PKCE (RFC 7636).
    AuthorizationCode { redirect_uris: Vec<String> },
    /// Device authorization grant (RFC 8628).
    DeviceAuthorization,
}

impl GrantConfig {
    /// Service account client; no refresh token issued.
    pub fn client_credentials() -> Self {
        Self::ClientCredentials {
            refresh_token: false,
        }
    }

    /// Service account client; issues a refresh token alongside the access token.
    pub fn client_credentials_with_refresh() -> Self {
        Self::ClientCredentials {
            refresh_token: true,
        }
    }

    /// Authorization code flow with PKCE.
    pub fn authorization_code(redirect_uris: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::AuthorizationCode {
            redirect_uris: redirect_uris.into_iter().map(Into::into).collect(),
        }
    }

    /// Device authorization grant.
    pub fn device_authorization() -> Self {
        Self::DeviceAuthorization
    }
}

/// Configuration for creating a Keycloak client in integration tests.
///
/// # Examples
///
/// ```rust
/// use huskarl_testkit::{ClientConfig, GrantConfig};
///
/// // Simple client credentials
/// let config = ClientConfig::builder()
///     .client_id("test-cc")
///     .secret("test-secret")
///     .grant(GrantConfig::client_credentials())
///     .build();
///
/// // Client credentials + DPoP-bound tokens
/// let config = ClientConfig::builder()
///     .client_id("test-dpop")
///     .secret("test-secret")
///     .grant(GrantConfig::client_credentials())
///     .dpop_bound(true)
///     .build();
///
/// // Authorization code
/// let config = ClientConfig::builder()
///     .client_id("test-ac")
///     .secret("test-secret")
///     .grant(GrantConfig::authorization_code(["http://localhost:8080/callback"]))
///     .build();
/// ```
#[derive(Debug, Clone, Builder)]
pub struct ClientConfig {
    /// The OAuth2 client ID.
    #[builder(into)]
    pub client_id: String,

    /// The client secret.
    #[builder(into)]
    pub secret: String,

    /// The grant type / flow configuration.
    pub grant: GrantConfig,

    /// Require DPoP-bound access tokens (RFC 9449).
    #[builder(default)]
    pub dpop_bound: bool,

    /// Bind access tokens to the mTLS client certificate (RFC 8705).
    #[builder(default)]
    pub mtls_bound: bool,

    /// Add an audience protocol mapper so `aud` contains this value.
    ///
    /// Required when validating tokens with a resource server that checks `aud`.
    #[builder(into)]
    pub audience: Option<String>,
}

/// Minimal Keycloak `ClientRepresentation` sent to `POST /admin/realms/{realm}/clients`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClientRepresentation {
    client_id: String,
    secret: String,
    enabled: bool,
    protocol: &'static str,
    public_client: bool,
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

impl From<&ClientConfig> for ClientRepresentation {
    fn from(config: &ClientConfig) -> Self {
        let mut attributes = HashMap::new();

        let (service_accounts_enabled, standard_flow_enabled, redirect_uris) = match &config.grant {
            GrantConfig::ClientCredentials { refresh_token } => {
                if *refresh_token {
                    attributes.insert(
                        "client_credentials.use_refresh_token".to_owned(),
                        "true".to_owned(),
                    );
                }
                (true, false, vec![])
            }
            GrantConfig::AuthorizationCode { redirect_uris } => {
                (false, true, redirect_uris.clone())
            }
            GrantConfig::DeviceAuthorization => {
                attributes.insert(
                    "oauth2.device.authorization.grant.enabled".to_owned(),
                    "true".to_owned(),
                );
                (false, false, vec![])
            }
        };

        if config.dpop_bound {
            attributes.insert("dpop.bound.access.tokens".to_owned(), "true".to_owned());
        }

        if config.mtls_bound {
            attributes.insert(
                "tls.client.certificate.bound.access.tokens".to_owned(),
                "true".to_owned(),
            );
        }

        let protocol_mappers = if let Some(aud) = &config.audience {
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
            client_id: config.client_id.clone(),
            secret: config.secret.clone(),
            enabled: true,
            protocol: "openid-connect",
            public_client: false,
            service_accounts_enabled,
            standard_flow_enabled,
            direct_access_grants_enabled: false,
            redirect_uris,
            attributes,
            protocol_mappers,
        }
    }
}
