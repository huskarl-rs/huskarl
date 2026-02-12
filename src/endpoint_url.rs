//! A validated endpoint URL.
//!
//! [`EndpointUrl`] is a newtype over [`Uri`] that guarantees the URL has been
//! validated. It can be constructed from common string and URL types via
//! [`IntoEndpointUrl`].

use std::convert::Infallible;

use http::{Uri, uri::InvalidUri};
use serde::{Deserialize, Serialize};
use url::Url;

/// A validated endpoint URL.
///
/// This is a newtype over [`Uri`] which can be constructed from common
/// string and URL types via [`IntoEndpointUrl`]. Once constructed, it can be
/// freely cloned and passed between grants without re-validation.
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
        s.into_endpoint_url().map_err(serde::de::Error::custom)
    }
}

impl EndpointUrl {
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

/// Conversion trait for types that can be turned into an [`EndpointUrl`].
pub trait IntoEndpointUrl {
    /// The error type returned if the conversion fails.
    type Error;

    /// Attempts to convert this value into an [`EndpointUrl`].
    fn into_endpoint_url(self) -> Result<EndpointUrl, Self::Error>;
}

impl IntoEndpointUrl for EndpointUrl {
    type Error = Infallible;

    fn into_endpoint_url(self) -> Result<EndpointUrl, Self::Error> {
        Ok(self)
    }
}

impl IntoEndpointUrl for Uri {
    type Error = Infallible;

    fn into_endpoint_url(self) -> Result<EndpointUrl, Self::Error> {
        Ok(EndpointUrl(self))
    }
}

impl IntoEndpointUrl for Url {
    type Error = InvalidUri;

    fn into_endpoint_url(self) -> Result<EndpointUrl, Self::Error> {
        self.as_str().parse::<Uri>().map(EndpointUrl)
    }
}

impl IntoEndpointUrl for &str {
    type Error = InvalidUri;

    fn into_endpoint_url(self) -> Result<EndpointUrl, Self::Error> {
        self.parse::<Uri>().map(EndpointUrl)
    }
}

impl IntoEndpointUrl for String {
    type Error = InvalidUri;

    fn into_endpoint_url(self) -> Result<EndpointUrl, Self::Error> {
        self.parse::<Uri>().map(EndpointUrl)
    }
}
