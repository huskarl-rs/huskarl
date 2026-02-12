//! Core grant exchange infrastructure.
//!
//! Contains the [`OAuth2ExchangeGrant`] trait that all concrete grant types
//! implement, along with the form serialization logic and token response
//! parsing shared across grants.

mod form;
mod grant;
mod token_response;

pub use grant::OAuth2ExchangeGrant;
pub use grant::RefreshableGrant;
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
