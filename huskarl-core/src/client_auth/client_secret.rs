use std::sync::Arc;

use base64::prelude::*;
use bon::Builder;
use http::{HeaderMap, HeaderValue};
use snafu::ResultExt as _;

use crate::{
    client_auth::{AuthenticationContext, AuthenticationParams, ClientAuthentication},
    error::Error,
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretString},
};

/// The cause of a client-secret authentication failure.
#[derive(Debug, snafu::Snafu, huskarl_macros::Classify)]
#[non_exhaustive]
pub(crate) enum ClientSecretError {
    /// The Basic credentials are not a valid HTTP header value.
    #[snafu(display("building Basic Authorization header"))]
    #[classify(no)]
    BuildingBasicHeader {
        /// The underlying error.
        source: http::header::InvalidHeaderValue,
    },
    /// The configured secret provider failed.
    #[snafu(display("fetching client secret"))]
    FetchingSecret {
        /// The underlying error.
        source: Error,
    },
}

/// Client Secret authentication (RFC 6749 §2.3.1)
///
/// Use [`ClientSecret::new`] for the common case (`client_secret_post`, the
/// OAuth 2.1 default). To change the auth method, use [`ClientSecret::builder`]:
/// `ClientSecret::builder().client_secret(secret).prefer_basic_auth(true).build()`.
#[derive(Clone, Builder)]
pub struct ClientSecret {
    #[builder(with = |secret: impl Secret<Output = SecretString> + 'static| Arc::new(secret) as Arc<dyn Secret<Output = SecretString>>)]
    client_secret: Arc<dyn Secret<Output = SecretString>>,
    /// Prefer `client_secret_basic` over `client_secret_post` when the server
    /// advertises both. Defaults to `false` (post-preferred, tracking OAuth 2.1).
    #[builder(default)]
    prefer_basic_auth: bool,
}

impl std::fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSecret").finish_non_exhaustive()
    }
}

impl ClientSecret {
    /// Creates a client secret which uses the underlying secret, authenticating
    /// with `client_secret_post` (the OAuth 2.1 default).
    ///
    /// To prefer `client_secret_basic` instead, use [`ClientSecret::builder`]
    /// with `.prefer_basic_auth(true)`.
    pub fn new(secret: impl Secret<Output = SecretString> + 'static) -> ClientSecret {
        ClientSecret {
            client_secret: Arc::new(secret),
            prefer_basic_auth: false,
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

        let mut auth_value: HeaderValue = auth_header.parse().context(BuildingBasicHeaderSnafu)?;
        // The base64 blob is the client secret; keep it out of the HPACK/QPACK
        // dynamic table and out of `AuthenticationParams`' derived `Debug`.
        auth_value.set_sensitive(true);

        let mut headers = HeaderMap::new();
        headers.insert(http::header::AUTHORIZATION, auth_value);

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
    fn authentication_context<'a>(
        &'a self,
        ctx: AuthenticationContext<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<AuthenticationParams<'a>, Error>> {
        Box::pin(async move {
            let client_secret = self
                .client_secret
                .get_secret_value()
                .await
                .context(FetchingSecretSnafu)?;

            match select_method(ctx.allowed_methods, self.prefer_basic_auth) {
                ClientSecretMethod::Basic => {
                    Self::basic_authentication_params(ctx.client_id, &client_secret.value)
                }
                ClientSecretMethod::Post => Ok(Self::post_authentication_params(
                    ctx.client_id,
                    client_secret.value,
                )),
            }
        })
    }
}

// `AsRef<str>` yields the RFC 8414 / OIDC discovery value for the method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::AsRefStr)]
enum ClientSecretMethod {
    #[strum(serialize = "client_secret_basic")]
    Basic,
    #[strum(serialize = "client_secret_post")]
    Post,
}

impl ClientSecretMethod {
    /// Method preference order. Post-first by default (OAuth 2.1 makes
    /// `client_secret_post` mandatory-to-support); Basic-first when the client
    /// opts in via [`ClientSecret::prefer_basic_auth`].
    fn priority(prefer_basic: bool) -> [Self; 2] {
        if prefer_basic {
            [Self::Basic, Self::Post]
        } else {
            [Self::Post, Self::Basic]
        }
    }
}

fn select_method(allowed_methods: Option<&[String]>, prefer_basic: bool) -> ClientSecretMethod {
    let priority = ClientSecretMethod::priority(prefer_basic);
    match allowed_methods {
        None => priority[0],
        Some(allowed) => priority
            .iter()
            .find(|m| allowed.iter().any(|a| a == m.as_ref()))
            .copied()
            .unwrap_or(priority[0]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EndpointUrl,
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
    fn select_method_none_defaults_to_post() {
        assert_eq!(select_method(None, false), ClientSecretMethod::Post);
        assert_eq!(select_method(None, true), ClientSecretMethod::Basic);
    }

    #[test]
    fn select_method_empty_defaults_to_post() {
        assert_eq!(select_method(Some(&[]), false), ClientSecretMethod::Post);
        assert_eq!(select_method(Some(&[]), true), ClientSecretMethod::Basic);
    }

    #[test]
    fn select_method_post_only() {
        let methods = vec!["client_secret_post".to_string()];
        // Only post advertised → post, regardless of preference.
        assert_eq!(
            select_method(Some(&methods), false),
            ClientSecretMethod::Post
        );
        assert_eq!(
            select_method(Some(&methods), true),
            ClientSecretMethod::Post
        );
    }

    #[test]
    fn select_method_basic_only() {
        let methods = vec!["client_secret_basic".to_string()];
        // Only basic advertised → basic, even when post is preferred.
        assert_eq!(
            select_method(Some(&methods), false),
            ClientSecretMethod::Basic
        );
        assert_eq!(
            select_method(Some(&methods), true),
            ClientSecretMethod::Basic
        );
    }

    #[test]
    fn select_method_both_defaults_to_post() {
        let methods = vec![
            "client_secret_basic".to_string(),
            "client_secret_post".to_string(),
        ];
        // List order doesn't matter — the client's preference does.
        assert_eq!(
            select_method(Some(&methods), false),
            ClientSecretMethod::Post
        );
    }

    #[test]
    fn select_method_both_prefer_basic() {
        let methods = vec![
            "client_secret_post".to_string(),
            "client_secret_basic".to_string(),
        ];
        assert_eq!(
            select_method(Some(&methods), true),
            ClientSecretMethod::Basic
        );
    }

    // --- authentication_context ---

    #[tokio::test]
    async fn authentication_context_basic() {
        // No advertised methods → defaults to post, so opt into basic explicitly.
        let secret = ClientSecret::builder()
            .client_secret(MockSecret(SecretString::new("my-secret")))
            .prefer_basic_auth(true)
            .build();
        let uri: EndpointUrl = "https://auth.example.com/token".parse().unwrap();
        let params = secret
            .authentication_context(
                AuthenticationContext::builder()
                    .client_id("my-client")
                    .target_endpoint(&uri)
                    .token_endpoint(&uri)
                    .build(),
            )
            .await
            .unwrap();

        let headers = params.headers.as_ref().unwrap();
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

        // The header carries the client secret: it must be sensitive, so that
        // neither HPACK nor `AuthenticationParams`' `Debug` leaks it.
        assert!(auth.is_sensitive());
        assert!(!format!("{params:?}").contains("Basic "));
    }

    #[tokio::test]
    async fn authentication_context_post() {
        let secret = ClientSecret::new(MockSecret(SecretString::new("s3cret")));
        let uri: EndpointUrl = "https://auth.example.com/token".parse().unwrap();
        let methods = vec!["client_secret_post".to_string()];
        let params = secret
            .authentication_context(
                AuthenticationContext::builder()
                    .client_id("cid")
                    .target_endpoint(&uri)
                    .token_endpoint(&uri)
                    .allowed_methods(&methods)
                    .build(),
            )
            .await
            .unwrap();

        assert!(params.headers.is_none());
        let form = params.form_params.unwrap();
        assert!(form.iter().any(|(k, _)| *k == "client_id"));
        assert!(form.iter().any(|(k, _)| *k == "client_secret"));
    }

    #[tokio::test]
    async fn basic_percent_encodes_special_chars() {
        let secret = ClientSecret::builder()
            .client_secret(MockSecret(SecretString::new("p&ss=w:rd")))
            .prefer_basic_auth(true)
            .build();
        let uri: EndpointUrl = "https://auth.example.com/token".parse().unwrap();
        let params = secret
            .authentication_context(
                AuthenticationContext::builder()
                    .client_id("cl&ent")
                    .target_endpoint(&uri)
                    .token_endpoint(&uri)
                    .build(),
            )
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
