//! Authorizer for `OAuth2` grants.
//!
//! An authorizer returns headers for a request, including any
//! required `DPoP` headers, refreshing tokens as necessary using the
//! underlying `OAuth2` grant.

use bon::Builder;
use http::{
    HeaderMap, HeaderName, Method, Uri,
    header::{AUTHORIZATION, InvalidHeaderValue},
};
use snafu::prelude::*;

use crate::{
    cache::{GetTokenError, TokenCache},
    core::{dpop::ResourceServerDPoP, http::HttpClient},
    grant::core::TokenResponse,
};

/// An authorizer for `OAuth2` grants.
///
/// This can provide appropriate headers for a request, including any
/// required `DPoP` headers, refreshing tokens as necessary using the
/// underlying `OAuth2` grant.
#[derive(Builder)]
pub struct HttpAuthorizer<T: TokenCache> {
    cache: T,
    #[builder(default = AUTHORIZATION)]
    authorization_header: HeaderName,
}

impl<T: TokenCache> core::fmt::Debug for HttpAuthorizer<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpAuthorizer")
            .field("authorization_header", &self.authorization_header)
            .finish_non_exhaustive()
    }
}

/// Errors that can occur when getting headers for a request.
#[derive(Debug, Snafu)]
pub enum AuthorizerError<TcErr: crate::core::Error + 'static, DPoPErr: crate::core::Error + 'static>
{
    /// The token cache returned an error when attempting to return a token.
    TokenCache {
        /// The underlying token cache error.
        source: TcErr,
    },
    /// An error occurred when creating the `DPoP` proof.
    DPoP {
        /// The underlying `DPoP` error.
        source: DPoPErr,
    },
    /// The token could not be used as it was not a valid token value.
    InvalidTokenValue,
    /// A `DPoP` token was received, but no `DPoP` configuration for the proof was present.
    #[snafu(display("Received DPoP token but no DPoP configuration present"))]
    UnexpectedDPoPToken,
    /// The token could not be used as it was not a valid header value.
    InvalidHeader {
        /// The underlying error.
        source: InvalidHeaderValue,
    },
}

impl<TcErr: crate::core::Error + 'static, DPoPErr: crate::core::Error + 'static> crate::core::Error
    for AuthorizerError<TcErr, DPoPErr>
{
    fn is_retryable(&self) -> bool {
        match self {
            Self::TokenCache { source } => source.is_retryable(),
            Self::DPoP { source } => source.is_retryable(),
            Self::InvalidTokenValue | Self::UnexpectedDPoPToken | Self::InvalidHeader { .. } => {
                false
            }
        }
    }
}

impl<T: TokenCache> HttpAuthorizer<T> {
    /// Get the authorization headers for this request, including any necessary `DPoP` headers.
    ///
    /// The call uses the provided HTTP client for any calls that are necessary to get the
    /// headers. The method and URI are passed to the `DPoP` proof when used.
    ///
    /// # Errors
    ///
    /// Returns an error if the token cache was unable to return authenticated headers.
    pub async fn get_headers<C: HttpClient>(
        &self,
        http_client: &C,
        method: &Method,
        uri: &Uri,
    ) -> Result<
        HeaderMap,
        AuthorizerError<GetTokenError<T::Error<C>>, <T::DPoP as ResourceServerDPoP>::Error>,
    > {
        let token = self
            .cache
            .get_token(http_client)
            .await
            .context(TokenCacheSnafu)?;

        ensure!(
            is_header_safe(token.access_token.expose_token()),
            InvalidTokenValueSnafu
        );

        let mut headers = HeaderMap::new();

        if token.token_type.eq_ignore_ascii_case("dpop") {
            if let Some(proof) = self
                .cache
                .resource_server_dpop()
                .proof(method, uri, &token.access_token)
                .await
                .context(DPoPSnafu)?
            {
                headers.insert(
                    "DPoP",
                    proof.expose_secret().parse().context(InvalidHeaderSnafu)?,
                );
                headers.insert(
                    &self.authorization_header,
                    format!("DPoP {}", token.access_token.expose_token())
                        .parse()
                        .context(InvalidHeaderSnafu)?,
                );
            } else {
                return UnexpectedDPoPTokenSnafu.fail();
            }
        } else {
            headers.insert(
                &self.authorization_header,
                format!("Bearer {}", token.access_token.expose_token())
                    .parse()
                    .context(InvalidHeaderSnafu)?,
            );
        }

        Ok(headers)
    }

    /// Returns a reference to the underlying token cache.
    pub fn cache(&self) -> &T {
        &self.cache
    }

    /// Primes the cache with an existing token response, e.g. after an initial authorization code exchange.
    pub async fn prime(&self, response: TokenResponse) {
        self.cache.prime(response).await;
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

fn is_header_safe(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b == b'\t' || (0x20..0x7F).contains(&b))
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
