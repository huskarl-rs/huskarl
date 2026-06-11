//! Authorizer for `OAuth2` grants.
//!
//! An authorizer returns headers for a request, including any
//! required `DPoP` headers, refreshing tokens as necessary using the
//! underlying `OAuth2` grant.

use std::sync::Arc;

use bon::Builder;
use http::{HeaderMap, HeaderName, Method, Uri, header::AUTHORIZATION};

use crate::{
    cache::TokenCache,
    core::{Error, ErrorKind},
    grant::core::TokenResponse,
    token::AccessToken,
};

/// An authorizer for `OAuth2` grants.
///
/// This can provide appropriate headers for a request, including any
/// required `DPoP` headers, refreshing tokens as necessary using the
/// underlying `OAuth2` grant.
#[derive(Builder)]
pub struct HttpAuthorizer {
    #[builder(with = |cache: impl TokenCache + 'static| Arc::new(cache) as Arc<dyn TokenCache>)]
    cache: Arc<dyn TokenCache>,
    #[builder(default = AUTHORIZATION)]
    authorization_header: HeaderName,
}

impl core::fmt::Debug for HttpAuthorizer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpAuthorizer")
            .field("authorization_header", &self.authorization_header)
            .finish_non_exhaustive()
    }
}

impl HttpAuthorizer {
    /// Get the authorization headers for this request, including any necessary `DPoP` headers.
    ///
    /// Token requests use the HTTP client held by the underlying grant. The
    /// method and URI are passed to the `DPoP` proof when used.
    ///
    /// # Errors
    ///
    /// Returns an error if the token cache was unable to return authenticated headers.
    pub async fn get_headers(&self, method: &Method, uri: &Uri) -> Result<HeaderMap, Error> {
        let token = self.cache.get_token_response().await?;

        let mut headers = HeaderMap::new();

        match token.access_token() {
            AccessToken::Dpop(dpop_access_token) => {
                let Some(proof) = self
                    .cache
                    .resource_server_dpop()
                    .proof(
                        method,
                        uri,
                        dpop_access_token.token(),
                        dpop_access_token.jkt(),
                    )
                    .await?
                else {
                    // A DPoP-bound token paired with a proof implementation
                    // that produces no proof indicates a logic bug in the
                    // cache configuration.
                    return Err(Error::from(ErrorKind::Dpop)
                        .with_context("received DPoP token but no DPoP configuration present"));
                };

                headers.insert(
                    "DPoP",
                    proof.expose_secret().parse().map_err(|source| {
                        Error::new(ErrorKind::Dpop, source)
                            .with_context("DPoP proof is not a valid header value")
                    })?,
                );
                headers.insert(
                    &self.authorization_header,
                    dpop_access_token.expose_header_value().map_err(|source| {
                        Error::new(ErrorKind::Protocol, source)
                            .with_context("access token is not a valid header value")
                    })?,
                );
            }
            AccessToken::Bearer(bearer_access_token) => {
                headers.insert(
                    &self.authorization_header,
                    bearer_access_token
                        .expose_header_value()
                        .map_err(|source| {
                            Error::new(ErrorKind::Protocol, source)
                                .with_context("access token is not a valid header value")
                        })?,
                );
            }
        }

        Ok(headers)
    }

    /// Returns a reference to the underlying token cache.
    pub fn cache(&self) -> &dyn TokenCache {
        self.cache.as_ref()
    }

    /// Primes the cache with an existing token response, e.g. after an initial authorization code exchange.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache fails to persist the response's refresh token.
    pub async fn prime(&self, response: Arc<TokenResponse>) -> Result<(), Error> {
        self.cache.prime(response).await
    }

    /// Invalidates the cached token, forcing a refresh on the next call to [`Self::get_headers`].
    pub fn invalidate(&self) {
        self.cache.invalidate();
    }

    /// Updates the `DPoP` nonce for the given URI.
    ///
    /// Call this when a resource server returns a `DPoP-Nonce` header. Use
    /// [`extract_dpop_nonce`] to extract the nonce value from the response headers,
    /// or prefer [`Self::update_from_response_headers`] to handle both in one call.
    pub fn set_nonce(&self, uri: &Uri, nonce: String) {
        self.cache.resource_server_dpop().update_nonce(uri, nonce);
    }

    /// Updates `DPoP` state from a resource server response.
    ///
    /// Extracts the `DPoP-Nonce` header (if present) and updates the nonce for the
    /// given URI. Call this after every authenticated request so that subsequent
    /// requests to the same resource server use the correct nonce.
    pub fn update_from_response_headers(&self, uri: &Uri, headers: &HeaderMap) {
        if let Some(nonce) = extract_dpop_nonce(headers) {
            self.cache.resource_server_dpop().update_nonce(uri, nonce);
        }
    }
}

/// Allows users to extract the `DPoP` nonce from a set of headers.
///
/// This is meant for use by users who are interacting with resource servers,
/// who can then call `dpop.update_nonce(uri, nonce)` to update the
/// bookkeeping for sending `DPoP` nonces.
#[must_use]
pub fn extract_dpop_nonce(headers: &HeaderMap) -> Option<String> {
    headers
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(std::borrow::ToOwned::to_owned)
}
