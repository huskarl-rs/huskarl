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

/// Authorization server metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// The authorization server's issuer identifier.
    pub issuer: String,
    /// The URL of the authorization server's authorization endpoint.
    pub authorization_endpoint: Option<EndpointUrl>,
    /// The URL of the authorization server's authorization endpoint.
    ///
    /// Required unless the only the implicit grant is supported.
    pub token_endpoint: EndpointUrl,
    /// The URL of the authorization server's JWK Set.
    pub jwks_uri: Option<EndpointUrl>,
    /// The URL of the authorization server's OAuth 2.0 Dynamic Client Registration endpoint.
    pub registration_endpoint: Option<EndpointUrl>,
    /// Array containing a list of the OAuth 2.0 "scope" values that this authorization server supports.
    pub scopes_supported: Option<Vec<String>>,
    /// Array containing a list of the OAuth 2.0 "`response_type`" values that this authorization server supports.
    pub response_types_supported: Vec<String>,
    /// Array containing a list of the OAuth 2.0 "`response_mode`" values that this authorization server supports
    #[serde(default = "default_response_modes_supported")]
    pub response_modes_supported: Vec<String>,
    /// Array containing a list of the OAuth 2.0 grant type values that this authorization server supports.
    #[serde(default = "default_grant_types_supported")]
    pub grant_types_supported: Vec<String>,
    /// Array containing a list of client authentication methods supported by this token endpoint.
    #[serde(default = "default_auth_methods_supported")]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Array containing a list of the JWS signing algorithms ("alg" values) supported by the token endpoint
    /// for the signature on the JWT used to authenticate the client at the token endpoint for the
    /// "`private_key_jwt`" and "`client_secret_jwt`" authentication methods.
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// URL of a page containing human-readable information that developers might want or need to know when using the authorization server.
    pub service_documentation: Option<String>,
    /// Languages and scripts supported for the user interface.
    pub ui_locales_supported: Option<Vec<String>>,
    /// URL that the authorization server provides to the person registering the client to read about the authorization server's requirements on how the client can use the data provided by the authorization server.
    pub op_policy_uri: Option<EndpointUrl>,
    /// URL that the authorization server provides to the person registering the client to read about the authorization server's terms of service.
    pub op_tos_uri: Option<EndpointUrl>,
    /// URL of the authorization server's OAuth 2.0 revocation endpoint.
    pub revocation_endpoint: Option<EndpointUrl>,
    /// Array containing a list of client authentication methods supported by this revocation endpoint.
    #[serde(default = "default_auth_methods_supported")]
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    /// Array containing a list of the JWS signing algorithms ("alg" values) supported by the revocation endpoint for
    /// the signature on the JWT [JWT] used to authenticate the client at the revocation endpoint for the
    /// "`private_key_jwt`" and "`client_secret_jwt`" authentication methods.
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// URL of the authorization server's OAuth 2.0 introspection endpoint.
    pub introspection_endpoint: Option<EndpointUrl>,
    /// Array containing a list of client authentication methods supported by this introspection endpoint.
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// Array containing a list of the JWS signing algorithms ("alg" values) supported by the introspection
    /// endpoint for the signature on the JWT [JWT] used to authenticate the client at the introspection endpoint
    /// for the "`private_key_jwt`" and "`client_secret_jwt`" authentication methods.
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// Array containing a list of Proof Key for Code Exchange (PKCE) [RFC7636] code challenge methods supported
    /// by this authorization server.
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
    /// If true, indicates that pushed authorization requests are required (RFC 9126 §5).
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    /**
     * RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification
     */
    /// Indicates support for an `iss` identifier in the authorization endpoint response (RFC 9207 §3).
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

#[bon]
impl AuthorizationServerMetadata {
    /// Get the authorization server metadata for an issuer.
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

/// Errors that may occur when attempting to fetch authorization server metadata.
#[derive(Debug, Snafu)]
pub enum AuthorizationServerMetadataFetchError<
    HttpErr: crate::Error + 'static,
    HttpRespErr: crate::Error + 'static,
> {
    /// Error when parsing the issuer as a URL.
    BadIssuer {
        /// The underlying error.
        source: http::Error,
    },
    /// Error when attempting to make the HTTP request.
    Get {
        /// The underlying error.
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
