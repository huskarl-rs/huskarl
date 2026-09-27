//! Validated mapping between deployment ingress paths and public URLs.
//!
//! This mapping preserves escaped path bytes and queries. It neither normalizes
//! paths nor trusts request authorities. Adapters must still enforce their own
//! path-confusion and routing policies.

use http::Uri;
use snafu::prelude::*;

use crate::EndpointUrl;

/// A deployment's trusted public base and the prefix received at ingress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicUrlMapping {
    public_base: Uri,
    incoming_prefix: String,
}

/// Invalid configuration or a URL outside the configured mapping.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum MappingError {
    /// Public base must be an absolute HTTP(S) URL without credentials or fragment.
    #[snafu(display(
        "public base must be an absolute HTTP(S) URL without credentials or fragment"
    ))]
    InvalidPublicBase {
        /// The underlying validation or parsing error.
        source: crate::Error,
    },
    /// Public base must not contain a query.
    #[snafu(display("public base must not contain a query"))]
    PublicBaseQuery,
    /// Public base must not end in repeated slashes.
    #[snafu(display("public base must not end in repeated slashes"))]
    PublicBaseRepeatedSlashes,
    /// Incoming prefix must be an absolute path without query, fragment, or trailing slash.
    #[snafu(display(
        "incoming prefix must be an absolute path without query, fragment, or trailing slash"
    ))]
    InvalidIncomingPrefix,
    /// Invalid incoming prefix.
    #[snafu(display("invalid incoming prefix"))]
    IncomingPrefixParse {
        /// The underlying validation or parsing error.
        source: http::uri::InvalidUri,
    },
    /// Incoming prefix must be a path.
    #[snafu(display("incoming prefix must be a path"))]
    IncomingPrefixOrigin,
    /// Request path is outside the incoming prefix.
    #[snafu(display("request path is outside the incoming prefix"))]
    OutsideIncomingPrefix,
    /// Resource subpath must be an absolute path without a fragment.
    #[snafu(display("resource subpath must be an absolute path without a fragment"))]
    InvalidResourceSubpath,
    /// Invalid resource subpath.
    #[snafu(display("invalid resource subpath"))]
    ResourceSubpathParse {
        /// The underlying validation or parsing error.
        source: http::uri::InvalidUri,
    },
    /// Resource subpath must not contain an origin.
    #[snafu(display("resource subpath must not contain an origin"))]
    ResourceSubpathOrigin,
    /// Request path must be an absolute path.
    #[snafu(display("request path must be an absolute path"))]
    RelativeRequestPath,
    /// Invalid mapped public path.
    #[snafu(display("invalid mapped public path"))]
    MappedPublicPath {
        /// The underlying validation or parsing error.
        source: http::uri::InvalidUri,
    },
    /// Invalid mapped public URL.
    #[snafu(display("invalid mapped public URL"))]
    MappedPublicUrl {
        /// The underlying validation or parsing error.
        source: http::uri::InvalidUriParts,
    },
    /// Public URL is on another origin.
    #[snafu(display("public URL is on another origin"))]
    DifferentOrigin,
    /// Public URL is outside the public prefix.
    #[snafu(display("public URL is outside the public prefix"))]
    OutsidePublicPrefix,
    /// Invalid mapped incoming URI.
    #[snafu(display("invalid mapped incoming URI"))]
    MappedIncomingUri {
        /// The underlying validation or parsing error.
        source: http::uri::InvalidUri,
    },
    /// Public endpoint cannot round-trip through this mapping.
    #[snafu(display("public endpoint cannot round-trip through this mapping"))]
    RoundTripMismatch,
}

impl PublicUrlMapping {
    /// Constructs a mapping from trusted configuration. `/` means no ingress
    /// prefix. Prefixes must be paths without queries or trailing slashes.
    /// A single trailing slash on the public base is a separator; repeated
    /// trailing slashes are rejected rather than collapsed.
    ///
    /// # Errors
    /// Rejects invalid origins, queries on the base, and malformed ingress prefixes.
    pub fn new(public_base: &str, incoming_prefix: &str) -> Result<Self, MappingError> {
        let base = public_base
            .parse::<EndpointUrl>()
            .context(InvalidPublicBaseSnafu)?;
        if base.as_uri().query().is_some() {
            return Err(MappingError::PublicBaseQuery);
        }
        if base.as_uri().path().ends_with("//") {
            return Err(MappingError::PublicBaseRepeatedSlashes);
        }
        if !incoming_prefix.starts_with('/')
            || incoming_prefix.contains(['?', '#'])
            || (incoming_prefix.len() > 1 && incoming_prefix.ends_with('/'))
        {
            return Err(MappingError::InvalidIncomingPrefix);
        }
        let incoming = incoming_prefix
            .parse::<Uri>()
            .context(IncomingPrefixParseSnafu)?;
        if incoming.scheme().is_some() || incoming.authority().is_some() {
            return Err(MappingError::IncomingPrefixOrigin);
        }
        Ok(Self {
            public_base: base.as_uri().clone(),
            incoming_prefix: incoming_prefix.to_owned(),
        })
    }

    /// Trusted public base, including the externally visible prefix.
    pub fn public_base(&self) -> &Uri {
        &self.public_base
    }
    /// Prefix as received before framework router nesting.
    pub fn incoming_prefix(&self) -> &str {
        &self.incoming_prefix
    }

    /// Resolves a request path against the trusted public base. Any authority
    /// on the incoming request is ignored; it is not a public URL override.
    ///
    /// # Errors
    /// Rejects paths outside the configured incoming prefix or invalid mapped URIs.
    pub fn public_url(&self, incoming: &Uri) -> Result<Uri, MappingError> {
        let suffix = strip(incoming.path(), &self.incoming_prefix)
            .ok_or(MappingError::OutsideIncomingPrefix)?;
        self.map_path(suffix, incoming.query())
    }

    /// Resolves a resource subpath relative to the public base, independently
    /// of the ingress prefix. Queries and escaped bytes are retained.
    ///
    /// # Errors
    /// Rejects subpaths containing an origin, a fragment, or invalid URI syntax.
    pub fn resource_url(&self, subpath: &str) -> Result<Uri, MappingError> {
        if !subpath.starts_with('/') || subpath.contains('#') {
            return Err(MappingError::InvalidResourceSubpath);
        }
        let relative = subpath.parse::<Uri>().context(ResourceSubpathParseSnafu)?;
        if relative.scheme().is_some() || relative.authority().is_some() {
            return Err(MappingError::ResourceSubpathOrigin);
        }
        self.map_path(relative.path(), relative.query())
    }

    fn map_path(&self, suffix: &str, query: Option<&str>) -> Result<Uri, MappingError> {
        if !suffix.is_empty() && !suffix.starts_with('/') {
            return Err(MappingError::RelativeRequestPath);
        }
        let path = format!(
            "{}{}",
            self.public_base.path().trim_end_matches('/'),
            suffix
        );
        let path = if path.is_empty() { "/" } else { &path };
        let mut parts = self.public_base.clone().into_parts();
        parts.path_and_query = Some(
            with_query(path, query)
                .parse()
                .context(MappedPublicPathSnafu)?,
        );
        Uri::from_parts(parts).context(MappedPublicUrlSnafu)
    }

    /// Derives the ingress URI of a public endpoint. URLs on another origin
    /// or outside the public prefix fail instead of silently changing origin.
    ///
    /// # Errors
    /// Rejects other origins, paths outside the public prefix, and endpoints that cannot round-trip.
    pub fn incoming_uri(&self, public: &Uri) -> Result<Uri, MappingError> {
        if public.scheme() != self.public_base.scheme()
            || public.authority() != self.public_base.authority()
        {
            return Err(MappingError::DifferentOrigin);
        }
        let suffix = strip(public.path(), self.public_base.path().trim_end_matches('/'))
            .ok_or(MappingError::OutsidePublicPrefix)?;
        let prefix = self.incoming_prefix.trim_end_matches('/');
        let path = format!("{prefix}{suffix}");
        let path = if path.is_empty() { "/" } else { &path };
        let incoming = with_query(path, public.query())
            .parse()
            .context(MappedIncomingUriSnafu)?;
        if self.public_url(&incoming)? != *public {
            return Err(MappingError::RoundTripMismatch);
        }
        Ok(incoming)
    }
}

fn strip<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if prefix.is_empty() || prefix == "/" {
        return Some(path);
    }
    match path.strip_prefix(prefix) {
        Some("") => Some(""),
        Some(rest) if rest.starts_with('/') => Some(rest),
        _ => None,
    }
}
fn with_query(path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deployment_matrix_preserves_wire_bytes() {
        for (base, ingress, incoming, public) in [
            (
                "https://api.example",
                "/",
                "/items/a%2Fb?q=x%20y",
                "https://api.example/items/a%2Fb?q=x%20y",
            ),
            (
                "https://api.example/gateway",
                "/",
                "/app/items?x=1&x=2",
                "https://api.example/gateway/app/items?x=1&x=2",
            ),
            (
                "https://api.example/gateway",
                "/edge",
                "/edge/app/items?",
                "https://api.example/gateway/app/items?",
            ),
        ] {
            let mapping = PublicUrlMapping::new(base, ingress).unwrap();
            let input = incoming.parse().unwrap();
            let output = mapping.public_url(&input).unwrap();
            assert_eq!(output.to_string(), public);
            assert_eq!(mapping.incoming_uri(&output).unwrap(), input);
        }
    }
    #[test]
    fn rejects_wrong_origin_and_segment_collisions() {
        let m = PublicUrlMapping::new("https://api.example/gateway", "/edge").unwrap();
        for path in ["/edgeX/a", "/other"] {
            assert!(m.public_url(&path.parse().unwrap()).is_err());
        }
        for url in [
            "https://evil.example/gateway/a",
            "https://api.example/gatewayX/a",
        ] {
            assert!(m.incoming_uri(&url.parse().unwrap()).is_err());
        }
        assert_eq!(
            m.public_url(&"https://evil.example/edge/a".parse().unwrap())
                .unwrap(),
            "https://api.example/gateway/a"
        );
    }
    #[test]
    fn exact_prefix_and_trailing_slash_remain_distinct() {
        for base in [
            "https://api.example/gateway",
            "https://api.example/gateway/",
        ] {
            let mapping = PublicUrlMapping::new(base, "/edge").unwrap();
            for (incoming, public) in [
                ("/edge", "https://api.example/gateway"),
                ("/edge/", "https://api.example/gateway/"),
                ("/edge?", "https://api.example/gateway?"),
                ("/edge?q=a%2Fb", "https://api.example/gateway?q=a%2Fb"),
                ("/edge/?q=a%2Fb", "https://api.example/gateway/?q=a%2Fb"),
                ("/edge//items", "https://api.example/gateway//items"),
            ] {
                let incoming: Uri = incoming.parse().unwrap();
                let public: Uri = public.parse().unwrap();
                assert_eq!(mapping.public_url(&incoming).unwrap(), public);
                assert_eq!(mapping.incoming_uri(&public).unwrap(), incoming);
            }
        }
    }

    #[test]
    fn root_mapping_preserves_queries_and_rejects_asterisk_targets() {
        let mapping = PublicUrlMapping::new("https://api.example/", "/").unwrap();
        for path in ["/", "/?", "/?q=a%2Fb"] {
            let incoming: Uri = path.parse().unwrap();
            let public = mapping.public_url(&incoming).unwrap();
            assert_eq!(public.to_string(), format!("https://api.example{path}"));
            assert_eq!(mapping.incoming_uri(&public).unwrap(), incoming);
        }
        assert!(mapping.public_url(&"*".parse().unwrap()).is_err());
    }

    #[test]
    fn repeated_slashes_inside_paths_are_preserved() {
        let mapping = PublicUrlMapping::new("https://api.example/gateway//v1/", "/edge").unwrap();
        let public = mapping.resource_url("/items//a%2Fb?q=x%20y").unwrap();
        assert_eq!(
            public,
            "https://api.example/gateway//v1/items//a%2Fb?q=x%20y"
        );
        let incoming = mapping.incoming_uri(&public).unwrap();
        assert_eq!(incoming, "/edge/items//a%2Fb?q=x%20y");
        assert_eq!(mapping.public_url(&incoming).unwrap(), public);
    }

    #[test]
    fn rejects_invalid_configuration() {
        for base in [
            "/path",
            "ftp://api.example",
            "https://api.example?q",
            "https://api.example/#fragment",
            "https://user@api.example",
            "https://api.example//",
            "https://api.example/gateway//",
            "https://api.example/gateway///",
        ] {
            assert!(PublicUrlMapping::new(base, "/").is_err());
        }
        for prefix in [
            "edge",
            "/edge/",
            "/edge?q",
            "/edge#f",
            "https://api.example",
        ] {
            assert!(PublicUrlMapping::new("https://api.example", prefix).is_err());
        }
    }
}
