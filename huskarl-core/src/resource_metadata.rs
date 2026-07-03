//! RFC 9728 - OAuth 2.0 Protected Resource Metadata.
//!
//! Metadata about a protected resource — the resource-server counterpart of
//! [`server_metadata`](crate::server_metadata) (RFC 8414). This module
//! currently provides the well-known URL derivation ([`well_known_url`]);
//! both sides of the discovery flow need it: the resource server to decide
//! where to serve (and advertise) its metadata document, and a client to
//! locate the document from a resource identifier.

use crate::{
    EndpointUrl,
    error::{Error, ErrorKind},
    well_known::insert_well_known_path,
};

/// The default well-known URI string for protected resource metadata (RFC 9728 §3).
pub const WELL_KNOWN_PATH: &str = "/.well-known/oauth-protected-resource";

/// Derives the URL of a protected resource's metadata document from its
/// resource identifier (RFC 9728 §3.1).
///
/// [`WELL_KNOWN_PATH`] is inserted between the host and the path — not
/// appended — so a resource identifier with a path component keeps it *after*
/// the well-known segment:
///
/// - `https://api.example.com` → `https://api.example.com/.well-known/oauth-protected-resource`
/// - `https://api.example.com/v1` → `https://api.example.com/.well-known/oauth-protected-resource/v1`
///
/// A query component is preserved after the inserted path (RFC 9728 §3
/// inserts "between the host component and the path and/or query
/// components") — resource identifiers SHOULD NOT carry one (RFC 8707 §2),
/// but the spec recognizes that some deployments need it.
///
/// A client that fetches the document from the derived URL MUST verify that
/// the document's `resource` value is identical to the resource identifier
/// the URL was derived from (RFC 9728 §3.3).
///
/// # Errors
///
/// Returns [`ErrorKind::Config`] if `resource` is not a valid resource
/// identifier: an absolute http(s) URL without a fragment component (RFC
/// 9728 §1.2; `http` is tolerated for loopback and test servers).
pub fn well_known_url(resource: &str) -> Result<EndpointUrl, Error> {
    let resource_url: EndpointUrl = resource
        .parse()
        .map_err(|e: Error| e.with_context(format!("invalid resource identifier {resource:?}")))?;

    insert_well_known_path(resource_url.into_uri(), WELL_KNOWN_PATH)
        .map_err(|source| {
            Error::new(ErrorKind::Config, source)
                .with_context(format!("invalid resource identifier {resource:?}"))
        })?
        .try_into()
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    // RFC 9728 §3.1: the well-known segment goes between host and path, so a
    // path component survives *after* it; a terminating "/" is removed first.
    #[rstest]
    #[case::no_path(
        "https://resource.example.com",
        "https://resource.example.com/.well-known/oauth-protected-resource"
    )]
    #[case::with_path(
        "https://resource.example.com/resource1",
        "https://resource.example.com/.well-known/oauth-protected-resource/resource1"
    )]
    #[case::root_slash_is_no_path(
        "https://resource.example.com/",
        "https://resource.example.com/.well-known/oauth-protected-resource"
    )]
    #[case::trailing_slash_is_stripped(
        "https://resource.example.com/resource1/",
        "https://resource.example.com/.well-known/oauth-protected-resource/resource1"
    )]
    #[case::port_is_preserved(
        "https://resource.example.com:8443/v1",
        "https://resource.example.com:8443/.well-known/oauth-protected-resource/v1"
    )]
    #[case::http_for_test_servers(
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8080/.well-known/oauth-protected-resource"
    )]
    // RFC 9728 §3 inserts "between the host component and the path and/or
    // query components": a query survives, after the path.
    #[case::query_is_preserved(
        "https://resource.example.com/api?version=1",
        "https://resource.example.com/.well-known/oauth-protected-resource/api?version=1"
    )]
    #[case::query_without_path(
        "https://resource.example.com?tenant=a",
        "https://resource.example.com/.well-known/oauth-protected-resource?tenant=a"
    )]
    fn inserts_well_known_between_host_and_path(#[case] resource: &str, #[case] expected: &str) {
        assert_eq!(well_known_url(resource).unwrap().to_string(), expected);
    }

    // RFC 9728 §1.2: a resource identifier is an absolute http(s) URL with no
    // fragment component.
    #[rstest]
    #[case::fragment("https://resource.example.com/api#frag")]
    #[case::relative_reference("/api")]
    #[case::urn("urn:example:resource")]
    fn rejects_invalid_resource_identifiers(#[case] resource: &str) {
        let err = well_known_url(resource).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::Config), "{err}");
    }
}
