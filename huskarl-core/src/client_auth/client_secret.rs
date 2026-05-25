use base64::prelude::*;
use http::{HeaderMap, Uri, header::InvalidHeaderValue};
use snafu::prelude::*;

use crate::{
    client_auth::{AuthenticationParams, ClientAuthentication},
    secrets::{Secret, SecretString},
};

/// Client Secret authentication (RFC 6749 §2.3.1)
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
        use form_urlencoded::byte_serialize;
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
                Self::basic_authentication_params(client_id, &client_secret.value)
            }
            ClientSecretMethod::Post => Ok(Self::post_authentication_params(
                client_id,
                client_secret.value,
            )),
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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;
    use crate::{
        client_auth::ClientAuthentication,
        secrets::{Secret, SecretOutput, SecretString},
    };

    #[derive(Clone)]
    struct MockSecret(SecretString);

    impl Secret for MockSecret {
        type Output = SecretString;
        type Error = Infallible;

        async fn get_secret_value(&self) -> Result<SecretOutput<Self::Output>, Self::Error> {
            Ok(SecretOutput {
                value: self.0.clone(),
                identity: None,
            })
        }
    }

    // --- select_method ---

    #[test]
    fn select_method_none_returns_basic() {
        assert_eq!(select_method(None), ClientSecretMethod::Basic);
    }

    #[test]
    fn select_method_empty_returns_basic() {
        assert_eq!(select_method(Some(&[])), ClientSecretMethod::Basic);
    }

    #[test]
    fn select_method_post_only() {
        let methods = vec!["client_secret_post".to_string()];
        assert_eq!(select_method(Some(&methods)), ClientSecretMethod::Post);
    }

    #[test]
    fn select_method_basic_and_post_prefers_basic() {
        let methods = vec![
            "client_secret_basic".to_string(),
            "client_secret_post".to_string(),
        ];
        assert_eq!(select_method(Some(&methods)), ClientSecretMethod::Basic);
    }

    #[test]
    fn select_method_post_and_basic_prefers_basic() {
        let methods = vec![
            "client_secret_post".to_string(),
            "client_secret_basic".to_string(),
        ];
        assert_eq!(select_method(Some(&methods)), ClientSecretMethod::Basic);
    }

    // --- authentication_params ---

    #[tokio::test]
    async fn authentication_params_basic() {
        let secret = ClientSecret::new(MockSecret(SecretString::new("my-secret")));
        let uri: Uri = "https://auth.example.com/token".parse().unwrap();
        let params = secret
            .authentication_params("my-client", None, &uri, None)
            .await
            .unwrap();

        let headers = params.headers.unwrap();
        let auth = headers.get(http::header::AUTHORIZATION).unwrap();
        let auth_str = auth.to_str().unwrap();
        assert!(auth_str.starts_with("Basic "));

        // Decode and verify: "my-client:my-secret"
        let decoded = String::from_utf8(
            base64::prelude::BASE64_STANDARD
                .decode(&auth_str[6..])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(decoded, "my-client:my-secret");
    }

    #[tokio::test]
    async fn authentication_params_post() {
        let secret = ClientSecret::new(MockSecret(SecretString::new("s3cret")));
        let uri: Uri = "https://auth.example.com/token".parse().unwrap();
        let methods = vec!["client_secret_post".to_string()];
        let params = secret
            .authentication_params("cid", None, &uri, Some(&methods))
            .await
            .unwrap();

        assert!(params.headers.is_none());
        let form = params.form_params.unwrap();
        assert!(form.iter().any(|(k, _)| *k == "client_id"));
        assert!(form.iter().any(|(k, _)| *k == "client_secret"));
    }

    #[tokio::test]
    async fn basic_percent_encodes_special_chars() {
        let secret = ClientSecret::new(MockSecret(SecretString::new("p&ss=w:rd")));
        let uri: Uri = "https://auth.example.com/token".parse().unwrap();
        let params = secret
            .authentication_params("cl&ent", None, &uri, None)
            .await
            .unwrap();

        let headers = params.headers.unwrap();
        let auth = headers.get(http::header::AUTHORIZATION).unwrap();
        let auth_str = auth.to_str().unwrap();
        let decoded = String::from_utf8(
            base64::prelude::BASE64_STANDARD
                .decode(&auth_str[6..])
                .unwrap(),
        )
        .unwrap();
        // Percent-encoded form: cl%26ent:p%26ss%3Dw%3Ard
        assert!(decoded.contains("%26"));
        assert!(decoded.contains("%3D"));
        assert!(decoded.contains("%3A"));
    }
}
