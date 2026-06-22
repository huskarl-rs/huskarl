//! RFC 8414 - OAuth 2.0 Authorization Server Metadata.
//!
//! This implements support for RFC 8414 - metadata about an authorization
//! server.

use bon::bon;
use http::{HeaderMap, Uri};
use serde::Deserialize;

use crate::{
    EndpointUrl,
    error::{Error, ErrorKind},
    http::HttpClient,
};

/// mTLS endpoint aliases from AS discovery metadata (RFC 8705 §5.1).
#[derive(Debug, Clone, Deserialize, bon::Builder)]
#[non_exhaustive]
pub struct MtlsEndpointAliases {
    /// The mTLS alias for the token endpoint.
    pub token_endpoint: Option<EndpointUrl>,
    /// The mTLS alias for the revocation endpoint.
    pub revocation_endpoint: Option<EndpointUrl>,
    /// The mTLS alias for the introspection endpoint.
    pub introspection_endpoint: Option<EndpointUrl>,
    /// The mTLS alias for the device authorization endpoint.
    pub device_authorization_endpoint: Option<EndpointUrl>,
    /// The mTLS alias for the pushed authorization request endpoint.
    pub pushed_authorization_request_endpoint: Option<EndpointUrl>,
    /// The mTLS alias for the registration endpoint.
    pub registration_endpoint: Option<EndpointUrl>,
    /// The mTLS alias for the userinfo endpoint.
    pub userinfo_endpoint: Option<EndpointUrl>,
}

/// Authorization server metadata (RFC 8414 / `OpenID` Connect Discovery).
///
/// Fetch it from the issuer's well-known endpoint with [`fetch`](Self::fetch),
/// or build it directly with the [`builder`](Self::builder) when discovery is
/// unavailable.
#[derive(Debug, Clone, Deserialize, bon::Builder)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)]
pub struct AuthorizationServerMetadata {
    /// The authorization server's issuer identifier.
    #[builder(into)]
    pub issuer: String,
    /// The URL of the authorization server's authorization endpoint.
    pub authorization_endpoint: Option<EndpointUrl>,
    /// The URL of the authorization server's token endpoint.
    ///
    /// Required unless only the implicit grant is supported.
    pub token_endpoint: EndpointUrl,
    /// The URL of the authorization server's JWK Set.
    pub jwks_uri: Option<EndpointUrl>,
    /// The URL of the authorization server's OAuth 2.0 Dynamic Client Registration endpoint.
    pub registration_endpoint: Option<EndpointUrl>,
    /// Array containing a list of the OAuth 2.0 "scope" values that this authorization server supports.
    pub scopes_supported: Option<Vec<String>>,
    /// Array containing a list of the RFC 9396 `authorization_details` type values
    /// that this authorization server supports (RFC 9396 §10).
    ///
    /// The `authorization_details` equivalent of [`scopes_supported`](Self::scopes_supported);
    /// a client can consult it to discover which types the server accepts.
    pub authorization_details_types_supported: Option<Vec<String>>,
    /// Array containing a list of the OAuth 2.0 "`response_type`" values that this authorization server supports.
    pub response_types_supported: Vec<String>,
    /// Array containing a list of the OAuth 2.0 "`response_mode`" values that this authorization server supports
    #[serde(default = "default_response_modes_supported")]
    #[builder(default = default_response_modes_supported())]
    pub response_modes_supported: Vec<String>,
    /// Array containing a list of the OAuth 2.0 grant type values that this authorization server supports.
    #[serde(default = "default_grant_types_supported")]
    #[builder(default = default_grant_types_supported())]
    pub grant_types_supported: Vec<String>,
    /// Array containing a list of client authentication methods supported by this token endpoint.
    #[serde(default = "default_auth_methods_supported")]
    #[builder(default = default_auth_methods_supported())]
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
    #[builder(default = default_auth_methods_supported())]
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    /// Array containing a list of the JWS signing algorithms ("alg" values) supported by the revocation
    /// endpoint for the signature on the JWT used to authenticate the client at the revocation endpoint for the
    /// "`private_key_jwt`" and "`client_secret_jwt`" authentication methods.
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// URL of the authorization server's OAuth 2.0 introspection endpoint.
    pub introspection_endpoint: Option<EndpointUrl>,
    /// Array containing a list of client authentication methods supported by this introspection endpoint.
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// Array containing a list of the JWS signing algorithms ("alg" values) supported by the introspection
    /// endpoint for the signature on the JWT used to authenticate the client at the introspection endpoint
    /// for the "`private_key_jwt`" and "`client_secret_jwt`" authentication methods.
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// Array containing a list of Proof Key for Code Exchange (PKCE) code challenge methods supported
    /// by this authorization server.
    #[serde(default = "Vec::new")]
    #[builder(default)]
    pub code_challenge_methods_supported: Vec<String>,
    /// RFC 8628 - OAuth 2.0 Device Authorization Grant
    pub device_authorization_endpoint: Option<EndpointUrl>,
    /// RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
    #[serde(default)]
    #[builder(default)]
    pub tls_client_certificate_bound_access_tokens: bool,
    /// mTLS endpoint aliases (RFC 8705 §5).
    pub mtls_endpoint_aliases: Option<MtlsEndpointAliases>,
    /// Specifies the URL of the pushed authorization request endpoint (RFC 9126 §5).
    ///
    /// RFC 9126 - OAuth 2.0 Pushed Authorization Requests
    pub pushed_authorization_request_endpoint: Option<EndpointUrl>,
    /// If true, indicates that pushed authorization requests are required (RFC 9126 §5).
    #[serde(default)]
    #[builder(default)]
    pub require_pushed_authorization_requests: bool,
    /// Array containing a list of the JWS algorithms supported for `DPoP` proof JWTs (RFC 9449 §5.1).
    ///
    /// RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (`DPoP`)
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// Indicates support for an `iss` identifier in the authorization endpoint response (RFC 9207 §3).
    ///
    /// RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification
    #[serde(default)]
    #[builder(default)]
    pub authorization_response_iss_parameter_supported: bool,
    /// The URL of the `OpenID` Connect userinfo endpoint.
    ///
    /// `OpenID` Connect Core 1.0
    pub userinfo_endpoint: Option<EndpointUrl>,
    /// URL of an OP iframe that supports cross-origin communications for session state information
    /// with the RP Client, using the HTML5 postMessage API.
    ///
    /// `OpenID` Connect Session Management 1.0
    pub check_session_iframe: Option<EndpointUrl>,
    /// URL at the OP to which an RP can perform a redirect to request that the End-User be logged out at the OP.
    ///
    /// `OpenID` Connect RP-Initiated Logout 1.0
    pub end_session_endpoint: Option<EndpointUrl>,
    /// Boolean value specifying whether the OP supports HTTP-based logout, with true indicating support.
    ///
    /// `OpenID` Connect Front-Channel Logout 1.0
    #[serde(default)]
    #[builder(default)]
    pub frontchannel_logout_supported: bool,
    /// Boolean value specifying whether the OP supports back-channel logout, with true indicating support.
    ///
    /// `OpenID` Connect Back-Channel Logout 1.0
    #[serde(default)]
    #[builder(default)]
    pub backchannel_logout_supported: bool,
    /// Boolean value specifying whether the OP can pass a `sid` (session ID) Claim in the Logout Token
    /// to identify the RP session with the OP.
    ///
    /// `OpenID` Connect Back-Channel Logout 1.0
    #[serde(default)]
    #[builder(default)]
    pub backchannel_logout_session_supported: bool,
}

#[bon]
impl AuthorizationServerMetadata {
    /// Get the authorization server metadata for an issuer.
    #[builder(on(String, into))]
    pub async fn fetch<C: HttpClient>(
        http_client: &C,
        issuer: String,
        #[builder(default = "/.well-known/oauth-authorization-server")] well_known_path: String,
        #[builder(default = false)] use_legacy_transformation: bool,
    ) -> Result<Self, Error> {
        let configuration_endpoint =
            add_issuer_to_known_path(&issuer, &well_known_path, use_legacy_transformation)
                .map_err(|source| {
                    Error::new(ErrorKind::Config, source)
                        .with_context(format!("invalid issuer {issuer:?}"))
                })?;

        let metadata: Self = crate::http::get(
            http_client,
            configuration_endpoint.clone(),
            HeaderMap::new(),
        )
        .await
        .map_err(|err| {
            err.with_context(format!(
                "fetching authorization server metadata from {configuration_endpoint}"
            ))
        })?;

        if metadata.issuer != issuer {
            return Err(Error::from(ErrorKind::Protocol).with_context(format!(
                "issuer mismatch (RFC 8414 §3.3): expected {issuer:?}, got {:?}",
                metadata.issuer
            )));
        }

        Ok(metadata)
    }
}

impl AuthorizationServerMetadata {
    /// Sets up appropriate fetch parameters via `OpenID` Connect Discovery (RFC 8414 / `OpenID` Connect Discovery 1.0).
    ///
    /// Equivalent to calling [`Self::fetch()`](Self::fetch) with
    /// `well_known_path = "/.well-known/openid-configuration"` and `use_legacy_transformation = true`.
    pub fn oidc_fetch<'c, C: HttpClient>() -> AuthorizationServerMetadataFetchBuilder<
        'c,
        C,
        authorization_server_metadata_fetch_builder::SetUseLegacyTransformation<
            authorization_server_metadata_fetch_builder::SetWellKnownPath,
        >,
    > {
        AuthorizationServerMetadata::fetch()
            .well_known_path("/.well-known/openid-configuration")
            .use_legacy_transformation(true)
    }
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
        format!("{cleaned_path}{uri_suffix}")
    } else {
        format!("{uri_suffix}{cleaned_path}")
    };
    let mut parts = issuer_as_uri.into_parts();
    parts.path_and_query = Some(new_path.try_into()?);
    Ok(Uri::from_parts(parts)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EndpointUrl;

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
             "authorization_details_types_supported":
               ["payment_initiation", "account_information"],
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
                .parse::<EndpointUrl>()
                .ok()
        );
        assert_eq!(
            parsed.authorization_details_types_supported,
            Some(vec![
                "payment_initiation".to_string(),
                "account_information".to_string(),
            ])
        );
    }
}
