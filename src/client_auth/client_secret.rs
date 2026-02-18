use base64::prelude::*;
use http::{HeaderMap, Uri, header::InvalidHeaderValue};
use secrecy::ExposeSecret as _;
use snafu::prelude::*;

use crate::{
    client_auth::{AuthenticationParams, ClientAuthentication},
    secrecy::SecretString,
    secrets::Secret,
};

/// Client Secret authentication (RFC 6749 §2.3.1)
///
///
#[derive(Debug, Clone)]
pub struct ClientSecret<Sec: Secret<Output = SecretString>> {
    client_secret: Sec,
}

impl<Sec: Secret<Output = SecretString>> ClientSecret<Sec> {
    /// Creates a client secret which uses the underlying secret.
    pub fn new(secret: Sec) -> ClientSecret<Sec> {
        ClientSecret {
            client_secret: secret,
        }
    }

    /// Selects the authentication method to use from a set of allowed methods.
    fn basic_authentication_params<'a>(
        client_id: &'a str,
        client_secret: &SecretString,
    ) -> Result<AuthenticationParams<'a>, ClientSecretError<Sec::Error>> {
        use url::form_urlencoded::byte_serialize;
        let client_id: String = byte_serialize(client_id.as_bytes()).collect();
        let client_secret: String =
            byte_serialize(client_secret.expose_secret().as_bytes()).collect();

        let credentials = format!("{client_id}:{client_secret}");
        let auth_header = format!("Basic {}", BASE64_STANDARD.encode(credentials.as_bytes()));

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            auth_header.parse().context(InvalidHeaderSnafu)?,
        );

        Ok(AuthenticationParams::builder().headers(headers).build())
    }

    fn post_authentication_params(
        client_id: &str,
        client_secret: SecretString,
    ) -> AuthenticationParams<'_> {
        AuthenticationParams::builder()
            .form_params(bon::map! {
                "client_id": client_id,
                "client_secret": client_secret
            })
            .build()
    }
}

impl<Sec: Secret<Output = SecretString>> ClientAuthentication for ClientSecret<Sec> {
    type Error = ClientSecretError<Sec::Error>;

    async fn authentication_params<'a>(
        &'a self,
        client_id: &'a str,
        _issuer: Option<&'a str>,
        _token_endpoint: &'a Uri,
        allowed_methods: Option<&'a [String]>,
    ) -> Result<super::AuthenticationParams<'a>, Self::Error> {
        let client_secret = self
            .client_secret
            .get_secret_value()
            .await
            .context(FetchSecretSnafu)?;

        match select_method(allowed_methods) {
            ClientSecretMethod::Basic => {
                Self::basic_authentication_params(client_id, &client_secret)
            }
            ClientSecretMethod::Post => {
                Ok(Self::post_authentication_params(client_id, client_secret))
            }
        }
    }
}

/// Errors that may occur when calculating client credentials.
#[derive(Debug, Snafu)]
pub enum ClientSecretError<SecErr: crate::Error> {
    /// There was an error when fetching a secret.
    #[snafu(display("Error fetching secret"))]
    FetchSecret {
        /// The underlying error.
        source: SecErr,
    },
    /// The calculated header value was invalid.
    #[snafu(display("Invalid header value"))]
    InvalidHeader {
        /// The underlying error.
        source: InvalidHeaderValue,
    },
}

impl<SecErr: crate::Error + 'static> crate::Error for ClientSecretError<SecErr> {
    fn is_retryable(&self) -> bool {
        match self {
            ClientSecretError::FetchSecret { source } => source.is_retryable(),
            ClientSecretError::InvalidHeader { .. } => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ClientSecretMethod {
    Basic,
    Post,
}

impl ClientSecretMethod {
    /// The OIDC discovery value for this method.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            ClientSecretMethod::Basic => "client_secret_basic",
            ClientSecretMethod::Post => "client_secret_post",
        }
    }

    /// Default priority order for method selection.
    ///
    /// Basic is preferred (see RFC 6749 section 2.3.1).
    pub const PRIORITY: &'static [Self] = &[Self::Basic, Self::Post];
}

fn select_method(allowed_methods: Option<&[String]>) -> ClientSecretMethod {
    match allowed_methods {
        None => ClientSecretMethod::Basic,
        Some(allowed) => ClientSecretMethod::PRIORITY
            .iter()
            .find(|m| allowed.iter().any(|a| a == m.as_str()))
            .copied()
            .unwrap_or(ClientSecretMethod::Basic),
    }
}
