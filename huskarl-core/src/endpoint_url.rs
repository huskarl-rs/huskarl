//! An endpoint URL.
//!
//! [`EndpointUrl`] is a newtype over [`Uri`] that provides a convenient way to
//! construct and validate endpoint URLs. It can be constructed from common
//! string and URL types via [`IntoEndpointUrl`].

use http::Uri;
use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind};

/// An endpoint URL.
///
/// This is a newtype over [`Uri`] which can be constructed from common
/// string and URL types via [`IntoEndpointUrl`]. Once constructed, it can be
/// freely cloned and passed between grants.
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
    /// Attempts to convert this value into an [`EndpointUrl`].
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`] if the value cannot be parsed into an
    /// [`EndpointUrl`].
    fn into_endpoint_url(self) -> Result<EndpointUrl, Error>;
}

fn invalid_uri(source: http::uri::InvalidUri) -> Error {
    Error::new(ErrorKind::Config, source).with_context("invalid endpoint URL")
}

impl IntoEndpointUrl for EndpointUrl {
    fn into_endpoint_url(self) -> Result<EndpointUrl, Error> {
        Ok(self)
    }
}

impl IntoEndpointUrl for Uri {
    fn into_endpoint_url(self) -> Result<EndpointUrl, Error> {
        Ok(EndpointUrl(self))
    }
}

#[cfg(feature = "url")]
impl IntoEndpointUrl for url::Url {
    fn into_endpoint_url(self) -> Result<EndpointUrl, Error> {
        self.as_str()
            .parse::<Uri>()
            .map(EndpointUrl)
            .map_err(invalid_uri)
    }
}

impl IntoEndpointUrl for &str {
    fn into_endpoint_url(self) -> Result<EndpointUrl, Error> {
        self.parse::<Uri>().map(EndpointUrl).map_err(invalid_uri)
    }
}

impl IntoEndpointUrl for String {
    fn into_endpoint_url(self) -> Result<EndpointUrl, Error> {
        self.parse::<Uri>().map(EndpointUrl).map_err(invalid_uri)
    }
}
