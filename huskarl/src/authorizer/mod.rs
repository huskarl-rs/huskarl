//! Authorizer for OAuth 2.0 grants.
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

pub(crate) mod challenge;

use std::sync::Arc;

use bon::Builder;
pub use challenge::{Challenge, ChallengePayload, parse_challenges};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header::AUTHORIZATION};
use snafu::prelude::*;

use crate::{cache::TokenCache, core::Error, token::AccessToken};

/// The cause of a request-authorization failure.
#[derive(Debug, snafu::Snafu, huskarl_macros::Classify)]
#[non_exhaustive]
pub(crate) enum AuthorizeError {
    /// A `DPoP`-bound token was cached but the authorizer has no `DPoP`
    /// configured to prove possession with — a cache wiring bug.
    #[snafu(display("received DPoP token but no DPoP configuration present"))]
    #[classify(no)]
    MissingDPoPConfiguration,
    /// The generated `DPoP` proof is not a valid HTTP header value.
    #[snafu(display("DPoP proof is not a valid header value"))]
    #[classify(no)]
    ProofNotAHeaderValue {
        /// The underlying error.
        source: http::header::InvalidHeaderValue,
    },
    /// The access token is not a valid HTTP header value.
    #[snafu(display("access token is not a valid header value"))]
    #[classify(no)]
    TokenNotAHeaderValue {
        /// The underlying error.
        source: http::header::InvalidHeaderValue,
    },
    /// RFC 8693 §2.2.1: an `N_A` issuance is not an access token and must never
    /// be presented as an `Authorization` credential.
    #[snafu(display(
        "the cached grant issued a non-access token (token_type N_A); \
         it cannot authorize resource-server requests"
    ))]
    #[classify(no)]
    NotAnAccessToken,
}

// Authorizer failures are local configuration errors without automatic recovery.
impl From<AuthorizeError> for crate::cache::TokenError {
    #[track_caller]
    fn from(source: AuthorizeError) -> Self {
        Error::from(source).into()
    }
}

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
    /// Pair **every** response with
    /// [`process_response`](Self::process_response) — success or failure.
    /// Skipping it silently breaks `DPoP` nonce rotation (the next proof
    /// carries a stale nonce, stranding the client in retry loops) and the
    /// automatic invalidation of tokens the server rejects. See the [module
    /// docs](self) for the full request loop.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`](crate::cache::TokenError) if token acquisition or
    /// header construction fails. Match
    /// [`TokenError::recovery`](crate::cache::TokenError::recovery) to distinguish
    /// retry, request adjustment, and reauthentication.
    pub async fn get_headers(
        &self,
        method: &Method,
        uri: &Uri,
    ) -> Result<HeaderMap, crate::cache::TokenError> {
        let token = self.cache.token().await?;

        let mut headers = HeaderMap::new();

        match token.access_token() {
            AccessToken::DPoP(dpop_access_token) => {
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
                    return Err(AuthorizeError::MissingDPoPConfiguration.into());
                };

                let mut proof_value: HeaderValue = proof
                    .expose_secret()
                    .parse()
                    .context(ProofNotAHeaderValueSnafu)?;
                // The DPoP proof is a short-lived signed credential; keep it out
                // of the HPACK/QPACK dynamic table and out of header debug output.
                proof_value.set_sensitive(true);
                headers.insert("DPoP", proof_value);

                let mut token_value = dpop_access_token
                    .expose_header_value()
                    .context(TokenNotAHeaderValueSnafu)?;
                token_value.set_sensitive(true);
                headers.insert(&self.authorization_header, token_value);
            }
            AccessToken::Bearer(bearer_access_token) => {
                let mut token_value = bearer_access_token
                    .expose_header_value()
                    .context(TokenNotAHeaderValueSnafu)?;
                token_value.set_sensitive(true);
                headers.insert(&self.authorization_header, token_value);
            }
            AccessToken::NotAccessToken(_) => {
                // RFC 8693 §2.2.1: an N_A issuance is not an access token and
                // must never be presented as an Authorization credential.
                return Err(AuthorizeError::NotAnAccessToken.into());
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

    /// Updates authorization state from response headers.
    ///
    /// Call this for every response, including successful responses.
    ///
    /// - Any `DPoP-Nonce` header is recorded for the URI's origin (RFC 9449
    ///   §8.1 — servers may rotate the nonce on any response, and the next
    ///   proof must carry the latest value).
    /// - An `invalid_token` challenge (RFC 6750 §3.1) invalidates the cached
    ///   token, so the next [`Self::get_headers`] acquires a fresh one.
    ///
    /// This method does not send a request and does not inspect the status code.
    /// See the [module docs](self) for the request loop, when
    /// to call [`Self::invalidate`] yourself, and the caveat on relaying an
    /// upstream `WWW-Authenticate` onto a non-`401` response.
    pub fn process_response(&self, uri: &Uri, headers: &HeaderMap) {
        if let Some(nonce) = extract_dpop_nonce(headers) {
            self.set_nonce(uri, nonce);
        }

        if challenge::challenge_has_error(headers, &crate::core::OAuthErrorCode::InvalidToken) {
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

/// Returns whether a response is the `DPoP` nonce failure a resend can fix: a
/// `401` with a `use_dpop_nonce` challenge that carries a fresh `DPoP-Nonce`
/// header (RFC 9449 §7.2). A challenge without the fresh nonce yields `false`
/// — a re-send cannot succeed.
///
/// Before rebuilding headers, record the nonce with
/// [`HttpAuthorizer::process_response`] or [`HttpAuthorizer::set_nonce`]. This
/// function does not determine whether resending the application request is
/// safe.
#[must_use]
pub fn dpop_resend_advised(status: StatusCode, headers: &HeaderMap) -> bool {
    status == StatusCode::UNAUTHORIZED
        && challenge::challenge_has_error(headers, &crate::core::OAuthErrorCode::UseDPoPNonce)
        && extract_dpop_nonce(headers).is_some()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::{
        core::{RetryAdvice, platform::MaybeSendBoxFuture},
        grant::core::TokenResponse,
    };

    /// A cache stub that records [`TokenCache::invalidate`] calls; the token
    /// acquisition methods are never exercised by these tests.
    #[derive(Clone, Default)]
    struct FakeCache {
        invalidated: Arc<AtomicBool>,
    }

    use crate::cache::TokenError;

    impl crate::cache::TokenSource for FakeCache {
        fn token(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, TokenError>> {
            Box::pin(async {
                Err(TokenError::from(Error::new(
                    RetryAdvice::No,
                    "config failure",
                )))
            })
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

    const NONCE_CHALLENGE: &str = r#"DPoP error="use_dpop_nonce""#;

    #[rstest::rstest]
    #[case::challenge_on_401(
        StatusCode::UNAUTHORIZED,
        &[("www-authenticate", NONCE_CHALLENGE), ("dpop-nonce", "fresh")],
        true
    )]
    // A nonce header alone (§8.1 rotation) is bookkeeping, not a challenge —
    // and a fresh nonce cannot fix a different failure like invalid_token.
    #[case::rotation_on_success(StatusCode::OK, &[("dpop-nonce", "rotated")], false)]
    #[case::rotation_on_bare_401(StatusCode::UNAUTHORIZED, &[("dpop-nonce", "rotated")], false)]
    #[case::rotation_on_invalid_token(
        StatusCode::UNAUTHORIZED,
        &[("www-authenticate", r#"DPoP error="invalid_token""#), ("dpop-nonce", "rotated")],
        false
    )]
    #[case::challenge_on_non_401(
        StatusCode::OK,
        &[("www-authenticate", NONCE_CHALLENGE), ("dpop-nonce", "fresh")],
        false
    )]
    // No fresh nonce to re-send with: a retry cannot succeed.
    #[case::challenge_without_nonce(
        StatusCode::UNAUTHORIZED,
        &[("www-authenticate", NONCE_CHALLENGE)],
        false
    )]
    #[case::no_signals(StatusCode::OK, &[], false)]
    fn dpop_resend_advised_classifies(
        #[case] status: StatusCode,
        #[case] header_pairs: &[(&str, &str)],
        #[case] expected: bool,
    ) {
        assert_eq!(
            dpop_resend_advised(status, &headers(header_pairs)),
            expected
        );
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
