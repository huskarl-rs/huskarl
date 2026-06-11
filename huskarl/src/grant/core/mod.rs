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

/// Standard implementation for converting a sequence of scopes into a scope string.
pub(crate) fn mk_scopes(scopes: impl IntoIterator<Item = impl Into<String>>) -> Option<String> {
    let maybe_scopes = scopes
        .into_iter()
        .filter_map(|s| {
            let s = s.into();
            (!s.trim().is_empty()).then_some(s)
        })
        .collect::<Vec<_>>();

    (!maybe_scopes.is_empty()).then(|| maybe_scopes.join(" "))
}
