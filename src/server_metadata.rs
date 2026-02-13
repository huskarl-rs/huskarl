//! RFC 8414 - OAuth 2.0 Authorization Server Metadata.
//!
//! This implements support for RFC 8414 - metadata about an authorization
//! server.

use bon::bon;
use http::{HeaderMap, Uri};
use serde::Deserialize;
use snafu::prelude::*;

use crate::{
    EndpointUrl,
    http::{HttpClient, HttpResponse},
};

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: Option<EndpointUrl>,
    /// Token endpoint. Required when supporting grants other than the implicit grant.
    pub token_endpoint: EndpointUrl,
    pub jwks_uri: Option<EndpointUrl>,
    pub registration_endpoint: Option<EndpointUrl>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    #[serde(default = "default_response_modes_supported")]
    pub response_modes_supported: Vec<String>,
    #[serde(default = "default_grant_types_supported")]
    pub grant_types_supported: Vec<String>,
    #[serde(default = "default_auth_methods_supported")]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub service_documentation: Option<String>,
    pub ui_locales_supported: Option<Vec<String>>,
    pub op_policy_uri: Option<EndpointUrl>,
    pub op_tos_uri: Option<EndpointUrl>,
    pub revocation_endpoint: Option<EndpointUrl>,
    #[serde(default = "default_auth_methods_supported")]
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub introspection_endpoint: Option<EndpointUrl>,
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default = "Vec::new")]
    pub code_challenge_methods_supported: Vec<String>,
    /**
     * RFC 8628 - OAuth 2.0 Device Authorization Grant
     */
    pub device_authorization_endpoint: Option<EndpointUrl>,
    /**
     * RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
     */
    #[serde(default)]
    pub tls_client_certificate_bound_access_tokens: bool,
    /**
     * RFC 9126 - OAuth 2.0 Pushed Authorization Requests
     */
    // Specifies the URL of the pushed authorization request endpoint (RFC 9126 §5).
    pub pushed_authorization_request_endpoint: Option<EndpointUrl>,
    // If true, indicates that pushed authorization requests are required (RFC 9126 §5).
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    /**
     * RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification
     */
    // Indicates support for an `iss` identifier in the authorization endpoint response (RFC 9207 §3).
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

#[bon]
impl AuthorizationServerMetadata {
    #[builder]
    pub async fn from_issuer<C: HttpClient>(
        #[builder(start_fn, into)] issuer: String,
        #[builder(finish_fn)] http_client: &C,
        #[builder(into, default = "/.well-known/oauth-authorization-server")] well_known_path: &str,
        #[builder(default = false)] use_legacy_transformation: bool,
    ) -> Result<
        Self,
        AuthorizationServerMetadataFetchError<C::Error, <C::Response as HttpResponse>::Error>,
    > {
        let configuration_endpoint =
            add_issuer_to_known_path(&issuer, well_known_path, use_legacy_transformation)
                .context(BadIssuerSnafu)?;

        crate::http::get(http_client, configuration_endpoint, HeaderMap::new())
            .await
            .context(GetSnafu)
    }
}

#[derive(Debug, Snafu)]
pub enum AuthorizationServerMetadataFetchError<
    HttpErr: crate::Error + 'static,
    HttpRespErr: crate::Error + 'static,
> {
    BadIssuer {
        /// The underlying error when parsing the issuer as a URL.
        source: http::Error,
    },
    Get {
        /// The underlying error when attempting to make the HTTP request.
        source: crate::http::GetError<HttpErr, HttpRespErr>,
    },
}

fn default_response_modes_supported() -> Vec<String> {
    vec!["query".to_string(), "fragment".to_string()]
}

fn default_grant_types_supported() -> Vec<String> {
    vec!["authorization_code".to_string(), "implicit".to_string()]
}

fn default_auth_methods_supported() -> Vec<String> {
    vec!["client_secret_basic".to_string()]
}

fn add_issuer_to_known_path(
    issuer: &str,
    uri_suffix: &str,
    use_legacy_transformation: bool,
) -> Result<Uri, http::Error> {
    let issuer_as_uri = Uri::try_from(issuer)?;
    let path = issuer_as_uri.path();
    let cleaned_path = path.strip_suffix('/').unwrap_or(path);
    let new_path = if use_legacy_transformation {
        format!("{uri_suffix}{cleaned_path}")
    } else {
        format!("{cleaned_path}{uri_suffix}")
    };
    let mut parts = issuer_as_uri.into_parts();
    parts.path_and_query = Some(new_path.try_into()?);
    Ok(Uri::from_parts(parts)?)
}

#[cfg(test)]
mod tests {
    use crate::IntoEndpointUrl;

    use super::*;

    /// Test the document from OIDC Discovery §4.2.
    #[test]
    fn test_oidc_spec() {
        let source = r#"
            {
             "issuer":
               "https://server.example.com",
             "authorization_endpoint":
               "https://server.example.com/connect/authorize",
             "token_endpoint":
               "https://server.example.com/connect/token",
             "token_endpoint_auth_methods_supported":
               ["client_secret_basic", "private_key_jwt"],
             "token_endpoint_auth_signing_alg_values_supported":
               ["RS256", "ES256"],
             "userinfo_endpoint":
               "https://server.example.com/connect/userinfo",
             "check_session_iframe":
               "https://server.example.com/connect/check_session",
             "end_session_endpoint":
               "https://server.example.com/connect/end_session",
             "jwks_uri":
               "https://server.example.com/jwks.json",
             "registration_endpoint":
               "https://server.example.com/connect/register",
             "scopes_supported":
               ["openid", "profile", "email", "address",
                "phone", "offline_access"],
             "response_types_supported":
               ["code", "code id_token", "id_token", "id_token token"],
             "acr_values_supported":
               ["urn:mace:incommon:iap:silver",
                "urn:mace:incommon:iap:bronze"],
             "subject_types_supported":
               ["public", "pairwise"],
             "userinfo_signing_alg_values_supported":
               ["RS256", "ES256", "HS256"],
             "userinfo_encryption_alg_values_supported":
               ["RSA-OAEP-256", "A128KW"],
             "userinfo_encryption_enc_values_supported":
               ["A128CBC-HS256", "A128GCM"],
             "id_token_signing_alg_values_supported":
               ["RS256", "ES256", "HS256"],
             "id_token_encryption_alg_values_supported":
               ["RSA-OAEP-256", "A128KW"],
             "id_token_encryption_enc_values_supported":
               ["A128CBC-HS256", "A128GCM"],
             "request_object_signing_alg_values_supported":
               ["none", "RS256", "ES256"],
             "display_values_supported":
               ["page", "popup"],
             "claim_types_supported":
               ["normal", "distributed"],
             "claims_supported":
               ["sub", "iss", "auth_time", "acr",
                "name", "given_name", "family_name", "nickname",
                "profile", "picture", "website",
                "email", "email_verified", "locale", "zoneinfo",
                "http://example.info/claims/groups"],
             "claims_parameter_supported":
               true,
             "service_documentation":
               "http://server.example.com/connect/service_documentation.html",
             "ui_locales_supported":
               ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"]
            }
"#;
        let parsed = serde_json::from_str::<AuthorizationServerMetadata>(source).unwrap();
        assert_eq!(parsed.issuer, "https://server.example.com");
        assert_eq!(
            parsed.authorization_endpoint,
            "https://server.example.com/connect/authorize"
                .into_endpoint_url()
                .ok()
        );
    }
}
