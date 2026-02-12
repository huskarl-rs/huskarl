//! Core grant exchange infrastructure.
//!
//! Contains the [`OAuth2ExchangeGrant`] trait that all concrete grant types
//! implement, along with the form serialization logic and token response
//! parsing shared across grants.

mod grant;
mod token_response;

pub(crate) mod form;

pub use grant::{OAuth2ExchangeGrant, OAuth2ExchangeGrantError};
pub use token_response::TokenResponse;

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

/// Simplified type alias for [`OAuth2ExchangeGrantError`] with generic [`crate::core::http::HttpClient`] error types.
pub type ExchangeError<C, Grant> = OAuth2ExchangeGrantError<
    <C as crate::core::http::HttpClient>::Error,
    <C as crate::core::http::HttpClient>::ResponseError,
    <<Grant as OAuth2ExchangeGrant>::ClientAuth as crate::core::client_auth::ClientAuthentication>::Error,
    <<Grant as OAuth2ExchangeGrant>::DPoP as crate::core::dpop::AuthorizationServerDPoP>::Error,
>;
