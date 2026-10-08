//! Core grant exchange infrastructure.
//!
//! Contains the [`OAuth2ExchangeGrant`] trait that all concrete grant types
//! implement, along with the form serialization logic and token response
//! parsing shared across grants.

mod grant;
pub(crate) mod token_response;

pub(crate) mod form;

pub use grant::OAuth2ExchangeGrant;
pub use token_response::{
    InvalidTokenResponse, RawTokenResponse, RawTokenResponseBuilder, TokenResponse,
    TokenResponseContext, TokenResponseContextBuilder,
};

/// Resolves the endpoint used for client-authenticated requests at grant
/// build time: the RFC 8705 §5 mTLS alias when the HTTP client uses mTLS,
/// the primary endpoint otherwise.
pub(crate) fn resolve_mtls_alias(
    http_client: &dyn crate::core::http::HttpClient,
    primary: &crate::core::EndpointUrl,
    mtls_alias: Option<&crate::core::EndpointUrl>,
) -> crate::core::EndpointUrl {
    if http_client.uses_mtls() {
        mtls_alias.unwrap_or(primary).clone()
    } else {
        primary.clone()
    }
}

/// Joins a list of values into the single space-delimited string that the
/// OAuth/OIDC list parameters `scope`, `ui_locales`, and `acr_values` use on the
/// wire (RFC 6749 §3.3, OIDC Core §3.1.2.1). Empty and whitespace-only entries
/// are dropped; an absent or all-empty list yields `None` so the parameter is
/// omitted entirely.
pub(crate) fn join_space(items: Option<&[String]>) -> Option<String> {
    let joined = items?
        .iter()
        .map(String::as_str)
        .filter(|s| !s.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    (!joined.is_empty()).then_some(joined)
}

/// Whether `scopes` request OpenID Connect Key Binding: both `openid` and
/// `bound_key` must be present.
pub(crate) fn requests_openid_bound_key(scopes: Option<&[String]>) -> bool {
    scopes.is_some_and(|scopes| {
        scopes.iter().any(|scope| scope == "openid")
            && scopes.iter().any(|scope| scope == "bound_key")
    })
}

/// The OpenID Connect Key Binding `c_s256` proof claim: the SHA-256 hash of
/// the authorization `code` or `device_code`, base64url-encoded without padding.
pub(crate) fn openid_code_hash(code: &str) -> String {
    use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
    use sha2::{Digest as _, Sha256};

    BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(code.as_bytes()))
}
