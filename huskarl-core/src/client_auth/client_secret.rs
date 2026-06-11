use std::sync::Arc;

use base64::prelude::*;
use http::{HeaderMap, Uri};

use crate::{
    client_auth::{AuthenticationParams, ClientAuthentication},
    error::{Error, ErrorKind},
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretString},
};

/// Client Secret authentication (RFC 6749 §2.3.1)
#[derive(Clone)]
pub struct ClientSecret {
    client_secret: Arc<dyn Secret<Output = SecretString>>,
}

impl std::fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSecret").finish_non_exhaustive()
    }
}

impl ClientSecret {
    /// Creates a client secret which uses the underlying secret.
    pub fn new(secret: impl Secret<Output = SecretString> + 'static) -> ClientSecret {
        ClientSecret {
            client_secret: Arc::new(secret),
        }
    }

    /// Selects the authentication method to use from a set of allowed methods.
    fn basic_authentication_params<'a>(
        client_id: &'a str,
        client_secret: &SecretString,
    ) -> Result<AuthenticationParams<'a>, Error> {
        use form_urlencoded::byte_serialize;
        let client_id: String = byte_serialize(client_id.as_bytes()).collect();
        let client_secret: String =
            byte_serialize(client_secret.expose_secret().as_bytes()).collect();

        let credentials = format!("{client_id}:{client_secret}");
        let auth_header = format!("Basic {}", BASE64_STANDARD.encode(credentials.as_bytes()));

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            auth_header.parse().map_err(|source| {
                Error::new(ErrorKind::Auth, source)
                    .with_context("building Basic Authorization header")
            })?,
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

impl ClientAuthentication for ClientSecret {
    fn authentication_params<'a>(
        &'a self,
        client_id: &'a str,
        _issuer: Option<&'a str>,
        _endpoint: &'a Uri,
        allowed_methods: Option<&'a [String]>,
    ) -> MaybeSendBoxFuture<'a, Result<AuthenticationParams<'a>, Error>> {
        Box::pin(async move {
            let client_secret = self
                .client_secret
                .get_secret_value()
                .await
                .map_err(|err| err.with_context("fetching client secret"))?;

            match select_method(allowed_methods) {
                ClientSecretMethod::Basic => {
                    Self::basic_authentication_params(client_id, &client_secret.value)
                }
                ClientSecretMethod::Post => Ok(Self::post_authentication_params(
                    client_id,
                    client_secret.value,
                )),
            }
        })
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
    use super::*;
    use crate::{
        client_auth::ClientAuthentication,
        secrets::{Secret, SecretOutput, SecretString},
    };

    struct MockSecret(SecretString);

    impl Secret for MockSecret {
        type Output = SecretString;

        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
            Box::pin(async move {
                Ok(SecretOutput {
                    value: self.0.clone(),
                    identity: None,
                })
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
