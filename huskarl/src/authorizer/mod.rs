//! Authorizer for `OAuth2` grants.
//!
//! [`HttpAuthorizer`] turns the token machinery (grant, cache, `DPoP`) into
//! request headers: [`get_headers`](HttpAuthorizer::get_headers) builds the
//! authorization headers for a request — exchanging or refreshing tokens as
//! needed — and [`process_response`](HttpAuthorizer::process_response) records
//! what each response reveals.
//!
//! See [making authenticated requests](crate::_docs::guide::authorizer) for the
//! full request loop, including handling `401`s and servers that don't emit a
//! spec-correct `invalid_token` challenge.

mod challenge;

use std::sync::Arc;

use bon::Builder;
pub use challenge::{Challenge, ChallengePayload, parse_challenges};
use http::{HeaderMap, HeaderName, Method, Uri, header::AUTHORIZATION};

use crate::{
    cache::TokenCache,
    core::{Error, ErrorKind},
    token::AccessToken,
};

/// Produces authenticated request headers from a [`TokenCache`].
///
/// Built with [`HttpAuthorizer::builder`]; the only required input is the
/// cache (typically an
/// [`InMemoryTokenCache`](crate::cache::InMemoryTokenCache) wrapping a
/// [`GrantTokenSource`](crate::cache::GrantTokenSource)). Carries no type
/// parameters, so it stores directly in application
/// state. See the [module docs](self) for the request loop.
#[derive(Builder)]
pub struct HttpAuthorizer {
    /// The token cache that supplies — and exchanges or refreshes — the
    /// access token.
    #[builder(with = |cache: impl TokenCache + 'static| Arc::new(cache) as Arc<dyn TokenCache>)]
    cache: Arc<dyn TokenCache>,
    /// The header that carries the access token. Defaults to
    /// `Authorization`; override when something else owns that header, e.g.
    /// `X-Forwarded-Authorization` behind a proxy that consumes the real
    /// one.
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
    /// Builds the authorization headers for a request: the access token in
    /// the configured header, plus a `DPoP` proof bound to `method` and
    /// `uri` when the token is `DPoP`-bound.
    ///
    /// Acquires or refreshes the token as needed, using the HTTP client held
    /// by the underlying grant.
    ///
    /// # Errors
    ///
    /// Errors follow the crate's three-signal contract — see
    /// [the error model](crate::core::error). In particular,
    /// [`ReauthRequired`](crate::core::ErrorKind::ReauthRequired) means the
    /// interactive flow must run again, while retryable transport failures
    /// keep their own classification.
    pub async fn get_headers(&self, method: &Method, uri: &Uri) -> Result<HeaderMap, Error> {
        let token = self.cache.token().await?;

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
            AccessToken::NotAccessToken(_) => {
                // RFC 8693 §2.2.1: an N_A issuance is not an access token and
                // must never be presented as an Authorization credential.
                return Err(Error::from(ErrorKind::Config).with_context(
                    "the cached grant issued a non-access token (token_type N_A); \
                     it cannot authorize resource-server requests",
                ));
            }
        }

        Ok(headers)
    }

    /// Returns a reference to the underlying token cache.
    ///
    /// This is the erased [`TokenCache`] surface only — it reaches
    /// [`token`](crate::cache::TokenSource::token),
    /// [`invalidate`](crate::cache::TokenSource::invalidate), and
    /// [`clear`](crate::cache::TokenSource::clear), but **not** source-specific
    /// methods like [`GrantTokenSource::prime`](crate::cache::GrantTokenSource::prime)
    /// or [`InMemoryTokenCache::state`](crate::cache::InMemoryTokenCache::state),
    /// which are not reachable through `dyn TokenCache`. To call those on a live
    /// instance, keep your own `Arc` clone of the concrete source/cache (as the
    /// [`source`](crate::cache::InMemoryTokenCache::source) docs describe) rather
    /// than going through here.
    pub fn cache(&self) -> &dyn TokenCache {
        self.cache.as_ref()
    }

    /// Invalidates the cached token, forcing a refresh on the next call to
    /// [`Self::get_headers`].
    ///
    /// This is the integration point for staleness signals only the
    /// application can see — a server that reports a bad token without a
    /// spec-correct challenge (see the [module docs](self)).
    pub fn invalidate(&self) {
        self.cache.invalidate();
    }

    /// Records a `DPoP` nonce for the given URI's server.
    ///
    /// Nonces are tracked per server origin, so a nonce recorded for one
    /// path applies to every request to that server. This is the manual
    /// escape hatch (paired with [`extract_dpop_nonce`]);
    /// [`Self::process_response`] does both steps in one call.
    pub fn set_nonce(&self, uri: &Uri, nonce: String) {
        self.cache.resource_server_dpop().update_nonce(uri, nonce);
    }

    /// Records what a resource server response teaches about authorization
    /// state. Call this with **every** response, success or failure.
    ///
    /// - Any `DPoP-Nonce` header is recorded for the URI's origin (RFC 9449
    ///   §8.1 — servers may rotate the nonce on any response, and the next
    ///   proof must carry the latest value).
    /// - An `invalid_token` challenge (RFC 6750 §3.1) invalidates the cached
    ///   token, so the next [`Self::get_headers`] acquires a fresh one.
    ///
    /// Bookkeeping only — it never re-sends, and only headers are inspected, not
    /// the status code. See the [module docs](self) for the request loop, when
    /// to call [`Self::invalidate`] yourself, and the caveat on relaying an
    /// upstream `WWW-Authenticate` onto a non-`401` response.
    pub fn process_response(&self, uri: &Uri, headers: &HeaderMap) {
        if let Some(nonce) = extract_dpop_nonce(headers) {
            self.set_nonce(uri, nonce);
        }

        if challenge::challenge_has_error(headers, "invalid_token") {
            self.invalidate();
        }
    }
}

/// Extracts the `DPoP-Nonce` header value from a response's headers.
///
/// The manual escape hatch, paired with [`HttpAuthorizer::set_nonce`];
/// [`HttpAuthorizer::process_response`] does both steps in one call.
#[must_use]
pub fn extract_dpop_nonce(headers: &HeaderMap) -> Option<String> {
    headers
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(std::borrow::ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::{core::platform::MaybeSendBoxFuture, grant::core::TokenResponse};

    /// A cache stub that records [`TokenCache::invalidate`] calls; the token
    /// acquisition methods are never exercised by these tests.
    #[derive(Clone, Default)]
    struct FakeCache {
        invalidated: Arc<AtomicBool>,
    }

    impl crate::cache::TokenSource for FakeCache {
        fn token(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, Error>> {
            Box::pin(async { Err(Error::from(ErrorKind::Config)) })
        }

        // Bearer fake: relies on the `NoDPoP` default for `resource_server_dpop`.

        fn invalidate(&self) {
            self.invalidated.store(true, Ordering::Relaxed);
        }
    }

    impl TokenCache for FakeCache {}

    fn authorizer() -> (HttpAuthorizer, Arc<AtomicBool>) {
        let cache = FakeCache::default();
        let invalidated = cache.invalidated.clone();
        (HttpAuthorizer::builder().cache(cache).build(), invalidated)
    }

    fn uri() -> Uri {
        "https://api.example.com/resource".parse().unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        headers
    }

    #[test]
    fn invalid_token_challenge_invalidates() {
        let (authorizer, invalidated) = authorizer();
        let headers = headers(&[(
            "www-authenticate",
            r#"Bearer error="invalid_token", error_description="The access token expired""#,
        )]);

        authorizer.process_response(&uri(), &headers);
        assert!(invalidated.load(Ordering::Relaxed));
    }

    #[test]
    fn unquoted_error_param_is_recognized() {
        let (authorizer, invalidated) = authorizer();
        // RFC 7235 auth-params may use the plain token form.
        let headers = headers(&[("www-authenticate", "Bearer error=invalid_token")]);

        authorizer.process_response(&uri(), &headers);
        assert!(invalidated.load(Ordering::Relaxed));
    }

    #[test]
    fn dpop_nonce_challenge_does_not_invalidate() {
        let (authorizer, invalidated) = authorizer();
        // A nonce demand does not mean the token is bad.
        let headers = headers(&[
            (
                "www-authenticate",
                r#"DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof""#,
            ),
            ("dpop-nonce", "eyJ7S_zG.eyJH0-Z.HX4w-7v"),
        ]);

        authorizer.process_response(&uri(), &headers);
        assert!(!invalidated.load(Ordering::Relaxed));
    }

    #[test]
    fn other_challenges_do_not_invalidate() {
        let (authorizer, invalidated) = authorizer();
        let headers = headers(&[(
            "www-authenticate",
            r#"Bearer error="insufficient_scope", scope="read write""#,
        )]);

        authorizer.process_response(&uri(), &headers);
        assert!(!invalidated.load(Ordering::Relaxed));
    }

    #[test]
    fn challenge_free_response_does_not_invalidate() {
        let (authorizer, invalidated) = authorizer();

        // E.g. a success response rotating the nonce: bookkeeping only.
        authorizer.process_response(&uri(), &headers(&[("dpop-nonce", "rotated")]));
        // And a response with no relevant headers at all.
        authorizer.process_response(&uri(), &headers(&[]));
        assert!(!invalidated.load(Ordering::Relaxed));
    }

    #[test]
    fn error_code_must_match_exactly() {
        // Prefix of a longer code, and an embedded `error=` inside another
        // parameter, must not count.
        for value in [
            r#"Bearer error="invalid_token_format""#,
            r#"Bearer error="invalid_request", error_uri="https://as.example.com/doc?error=invalid_token""#,
        ] {
            let (authorizer, invalidated) = authorizer();
            authorizer.process_response(&uri(), &headers(&[("www-authenticate", value)]));
            assert!(
                !invalidated.load(Ordering::Relaxed),
                "must not invalidate for: {value}"
            );
        }
    }

    #[test]
    fn error_inside_quoted_description_does_not_invalidate() {
        let (authorizer, invalidated) = authorizer();
        // `error=` inside a quoted value must not be read as a challenge
        // error code (commas and spaces are legal inside quoted-strings).
        let headers = headers(&[(
            "www-authenticate",
            r#"Bearer error="invalid_request", error_description="try again, error=invalid_token happens sometimes""#,
        )]);

        authorizer.process_response(&uri(), &headers);
        assert!(!invalidated.load(Ordering::Relaxed));
    }
}
