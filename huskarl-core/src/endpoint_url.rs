//! An endpoint URL.
//!
//! [`EndpointUrl`] is a newtype over [`Uri`] that provides a convenient way to
//! construct and validate endpoint URLs. It can be constructed from common
//! string and URL types via [`TryFrom`] (and [`str::parse`] via [`FromStr`]).

use std::str::FromStr;

use http::Uri;
use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind};

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
/// Construction validates that the URL is **absolute** — it has both a scheme
/// and an authority. A relative reference such as `/token` cannot be requested,
/// so it is rejected with [`ErrorKind::Config`]. (Scheme is not constrained to
/// `https`: loopback and test servers use `http`.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointUrl(Uri);

impl Serialize for EndpointUrl {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for EndpointUrl {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl EndpointUrl {
    /// Wraps a [`Uri`] after checking it is absolute.
    ///
    /// An endpoint URL must have both a scheme and an authority — a relative
    /// reference such as `/token` cannot be requested. This is the single
    /// validation point every conversion funnels through.
    fn from_uri(uri: Uri) -> Result<Self, Error> {
        if uri.scheme().is_none() || uri.authority().is_none() {
            return Err(Error::from(ErrorKind::Config).with_context(format!(
                "endpoint URL must be absolute (have a scheme and authority): {uri}"
            )));
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

fn invalid_uri(source: http::uri::InvalidUri) -> Error {
    Error::new(ErrorKind::Config, source).with_context("invalid endpoint URL")
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
            return Err(Error::from(ErrorKind::Config).with_context(format!(
                "endpoint URL must not contain a fragment component: {s}"
            )));
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
        assert!(matches!(err.kind(), ErrorKind::Config));
    }

    // OAuth endpoint URLs MUST NOT carry a fragment (RFC 6749 §3.1, §3.2).
    // `http::Uri` would silently drop it, so we reject it loudly instead.
    #[rstest]
    #[case::bare_fragment("https://as.example.com/token#frag")]
    #[case::query_then_fragment("https://as.example.com/authorize?foo=bar#frag")]
    #[case::empty_fragment("https://as.example.com/token#")]
    fn rejects_fragment(#[case] input: &str) {
        let err = EndpointUrl::try_from(input).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::Config));
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
    fn uri_conversion_is_now_checked() {
        // The `Uri` impl no longer wraps unconditionally.
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
    fn converts_back_to_uri() {
        let e: EndpointUrl = "https://as.example.com/token".parse().unwrap();
        let by_ref: &Uri = e.as_ref();
        assert_eq!(by_ref, e.as_uri());
        let owned: Uri = e.into();
        assert_eq!(owned.to_string(), "https://as.example.com/token");
    }
}
