//! An endpoint URL.
//!
//! [`EndpointUrl`] is a newtype over [`Uri`] that provides a convenient way to
//! construct and validate endpoint URLs. It can be constructed from common
//! string and URL types via [`TryFrom`] (and [`str::parse`] via [`FromStr`]).

use std::str::FromStr;

use http::Uri;
use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::error::Error;

/// The cause of an [`EndpointUrl`] validation failure.
#[derive(Debug, Snafu, huskarl_macros::Classify)]
#[non_exhaustive]
pub(crate) enum EndpointUrlError {
    /// The URL has no scheme, no authority, or neither.
    #[snafu(display("endpoint URL must be absolute (have a scheme and authority): {uri}"))]
    #[classify(no)]
    NotAbsolute {
        /// The rejected URL.
        uri: Uri,
    },
    /// The scheme is something other than `http` or `https`.
    #[snafu(display("endpoint URL scheme must be http or https: {uri}"))]
    #[classify(no)]
    UnsupportedScheme {
        /// The rejected URL.
        uri: Uri,
    },
    /// The authority carries userinfo credentials (RFC 9110 §4.2.4).
    #[snafu(display(
        "endpoint URL must not contain userinfo (credentials) in its authority: {uri}"
    ))]
    #[classify(no)]
    UserinfoInAuthority {
        /// The rejected URL.
        uri: Uri,
    },
    /// The URL contains a fragment, which OAuth endpoints forbid and
    /// [`Uri`] would silently discard.
    #[snafu(display("endpoint URL must not contain a fragment component: {url}"))]
    #[classify(no)]
    FragmentPresent {
        /// The rejected URL, as supplied.
        url: String,
    },
    /// The string is not a valid URI at all.
    #[snafu(display("invalid endpoint URL"))]
    #[classify(no)]
    InvalidUri {
        /// The underlying error.
        source: http::uri::InvalidUri,
    },
}

/// An endpoint URL.
///
/// This is a newtype over [`Uri`] which can be constructed from common string
/// and URL types via [`TryFrom`] — e.g. `EndpointUrl::try_from("https://…")`,
/// `"https://…".try_into()`, or `"https://…".parse()` ([`FromStr`]). Once
/// constructed, it can be freely cloned and passed between grants. It
/// implements [`Display`](std::fmt::Display) for formatting and logging, and
/// converts back to a [`Uri`] via [`as_uri`](Self::as_uri) / [`AsRef`] /
/// [`From`].
///
/// Construction validates that the URL is a plausible endpoint, rejecting
/// anything else with [`RetryAdvice::No`](crate::error::RetryAdvice::No):
///
/// - it must be **absolute** — have both a scheme and an authority; a relative
///   reference such as `/token` cannot be requested;
/// - the scheme must be **`http` or `https`** (`http` is allowed because
///   loopback and test servers use it);
/// - it must not carry a **fragment** (RFC 6749 §3.1, §3.2) — `http::Uri`
///   would silently drop it — nor **userinfo** credentials in the authority
///   (RFC 9110 §4.2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointUrl(Uri);

impl Serialize for EndpointUrl {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EndpointUrl {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl EndpointUrl {
    /// Wraps a [`Uri`] after checking it is a plausible endpoint.
    ///
    /// An endpoint URL must be absolute (have both a scheme and an authority —
    /// a relative reference such as `/token` cannot be requested), the scheme
    /// must be `http` or `https` (anything else fails later, deep in the HTTP
    /// client, with a far less pointed error), and the authority must not
    /// carry userinfo (RFC 9110 §4.2.4 forbids generating it in http(s) URIs;
    /// credentials embedded in an endpoint URL are a misconfiguration that
    /// would otherwise leak into requests and logs). This is the single
    /// validation point every conversion funnels through.
    fn from_uri(uri: Uri) -> Result<Self, Error> {
        let (Some(scheme), Some(authority)) = (uri.scheme(), uri.authority()) else {
            return Err(NotAbsoluteSnafu { uri }.build().into());
        };

        let unsupported_scheme =
            scheme != &http::uri::Scheme::HTTP && scheme != &http::uri::Scheme::HTTPS;
        // '@' in an authority is always the userinfo delimiter (RFC 3986
        // §3.2); it must be percent-encoded anywhere else.
        let has_userinfo = authority.as_str().contains('@');

        if unsupported_scheme {
            return Err(UnsupportedSchemeSnafu { uri }.build().into());
        }
        if has_userinfo {
            return Err(UserinfoInAuthoritySnafu { uri }.build().into());
        }

        Ok(Self(uri))
    }

    /// Returns the inner [`Uri`].
    #[must_use]
    pub fn as_uri(&self) -> &Uri {
        &self.0
    }

    /// Consumes the [`EndpointUrl`] and returns the inner [`Uri`].
    #[must_use]
    pub fn into_uri(self) -> Uri {
        self.0
    }
}

impl std::fmt::Display for EndpointUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<Uri> for EndpointUrl {
    fn as_ref(&self) -> &Uri {
        &self.0
    }
}

impl From<EndpointUrl> for Uri {
    fn from(endpoint: EndpointUrl) -> Self {
        endpoint.0
    }
}

#[track_caller]
fn invalid_uri(source: http::uri::InvalidUri) -> Error {
    Error::from(EndpointUrlError::InvalidUri { source })
}

impl TryFrom<Uri> for EndpointUrl {
    type Error = Error;

    fn try_from(uri: Uri) -> Result<Self, Error> {
        Self::from_uri(uri)
    }
}

#[cfg(feature = "url")]
impl TryFrom<url::Url> for EndpointUrl {
    type Error = Error;

    fn try_from(url: url::Url) -> Result<Self, Error> {
        // Through `FromStr` so the fragment check applies — `url::Url` preserves
        // the fragment in `as_str()`, unlike `http::Uri`.
        url.as_str().parse()
    }
}

impl FromStr for EndpointUrl {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        // A literal '#' is always the fragment delimiter (RFC 3986 §3.5) — it
        // cannot appear unescaped anywhere else in a URI. `http::Uri` silently
        // *drops* the fragment on parse, so we reject it here on the raw string
        // before parsing: failing loud beats silently mangling a misconfigured
        // endpoint. OAuth endpoint URLs MUST NOT carry a fragment (RFC 6749
        // §3.1, §3.2). A query component is still permitted (the authorization
        // endpoint may carry one per RFC 6749 §3.1).
        if s.contains('#') {
            return Err(FragmentPresentSnafu { url: s }.build().into());
        }
        s.parse::<Uri>()
            .map_err(invalid_uri)
            .and_then(Self::from_uri)
    }
}

impl TryFrom<&str> for EndpointUrl {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Error> {
        s.parse()
    }
}

impl TryFrom<String> for EndpointUrl {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Error> {
        s.parse()
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::error::RetryAdvice;

    #[test]
    fn accepts_absolute_https() {
        let e = EndpointUrl::try_from("https://as.example.com/token").unwrap();
        assert_eq!(e.as_uri().to_string(), "https://as.example.com/token");
    }

    #[test]
    fn parse_via_fromstr() {
        let e: EndpointUrl = "https://as.example.com/token".parse().unwrap();
        assert_eq!(e.as_uri().to_string(), "https://as.example.com/token");
    }

    #[test]
    fn accepts_absolute_http_for_loopback_and_test_servers() {
        // Scheme is not constrained to https: mock/loopback servers use http.
        assert!(EndpointUrl::try_from("http://127.0.0.1:8080/token").is_ok());
    }

    // An absolute URL needs both a scheme and an authority; anything missing
    // either is rejected as a configuration error.
    #[rstest]
    #[case::relative_reference("/token")]
    #[case::scheme_without_authority("mailto:ops@example.com")]
    #[case::authority_only_without_scheme("as.example.com/token")]
    fn rejects_invalid_endpoint(#[case] input: &str) {
        let err = EndpointUrl::try_from(input).unwrap_err();
        assert_eq!(err.retry_advice(), RetryAdvice::No);
    }

    // Only http and https endpoints can actually be requested; any other
    // scheme would fail much later, inside the HTTP client, with a far less
    // pointed error than a Config error naming the URL.
    #[rstest]
    #[case::ftp("ftp://as.example.com/token")]
    #[case::websocket("wss://as.example.com/token")]
    #[case::custom_scheme("custom-app://as.example.com/token")]
    fn rejects_non_http_scheme(#[case] input: &str) {
        let err = EndpointUrl::try_from(input).unwrap_err();
        assert_eq!(err.retry_advice(), RetryAdvice::No);
        assert!(format!("{err:#}").contains("http or https"), "{err:#}");
    }

    // RFC 9110 §4.2.4: a sender MUST NOT generate the userinfo subcomponent in
    // an http(s) URI. Credentials embedded in an endpoint URL are a
    // misconfiguration that would otherwise flow into requests and logs.
    #[rstest]
    #[case::credentials("https://user:pass@as.example.com/token")]
    #[case::bare_user("https://user@as.example.com/token")]
    fn rejects_userinfo(#[case] input: &str) {
        let err = EndpointUrl::try_from(input).unwrap_err();
        assert_eq!(err.retry_advice(), RetryAdvice::No);
        assert!(format!("{err:#}").contains("userinfo"), "{err:#}");
    }

    // The userinfo check guards the `Uri` funnel too, not just string parsing.
    #[test]
    fn rejects_userinfo_via_uri_conversion() {
        let uri: Uri = "https://user:pass@as.example.com/token".parse().unwrap();
        assert!(EndpointUrl::try_from(uri).is_err());
    }

    // OAuth endpoint URLs MUST NOT carry a fragment (RFC 6749 §3.1, §3.2).
    // `http::Uri` would silently drop it, so we reject it loudly instead.
    #[rstest]
    #[case::bare_fragment("https://as.example.com/token#frag")]
    #[case::query_then_fragment("https://as.example.com/authorize?foo=bar#frag")]
    #[case::empty_fragment("https://as.example.com/token#")]
    fn rejects_fragment(#[case] input: &str) {
        let err = EndpointUrl::try_from(input).unwrap_err();
        assert_eq!(err.retry_advice(), RetryAdvice::No);
    }

    // A query component is permitted (the authorization endpoint may carry one
    // per RFC 6749 §3.1) and must be preserved verbatim — no normalization.
    #[test]
    fn accepts_and_preserves_query() {
        let e = EndpointUrl::try_from("https://as.example.com/authorize?foo=bar&baz=1").unwrap();
        assert_eq!(
            e.as_uri().to_string(),
            "https://as.example.com/authorize?foo=bar&baz=1"
        );
    }

    #[test]
    fn uri_conversion_is_checked() {
        // The `Uri` impl validates rather than wrapping unconditionally.
        let relative: Uri = "/authorize".parse().unwrap();
        assert!(EndpointUrl::try_from(relative).is_err());
    }

    #[test]
    fn display_matches_inner_uri() {
        let e: EndpointUrl = "https://as.example.com/authorize?foo=bar".parse().unwrap();
        assert_eq!(e.to_string(), "https://as.example.com/authorize?foo=bar");
        assert_eq!(format!("{e}"), e.as_uri().to_string());
    }

    #[test]
    fn serde_round_trips_as_a_string() {
        let e: EndpointUrl = "https://as.example.com/authorize?foo=bar".parse().unwrap();
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, r#""https://as.example.com/authorize?foo=bar""#);
        let back: EndpointUrl = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn converts_back_to_uri() {
        let e: EndpointUrl = "https://as.example.com/token".parse().unwrap();
        let by_ref: &Uri = e.as_ref();
        assert_eq!(by_ref, e.as_uri());
        let owned: Uri = e.into();
        assert_eq!(owned.to_string(), "https://as.example.com/token");
    }
}
