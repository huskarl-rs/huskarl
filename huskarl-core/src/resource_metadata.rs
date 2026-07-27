//! RFC 9728 - OAuth 2.0 Protected Resource Metadata.
//!
//! Metadata about a protected resource — the resource-server counterpart of
//! [`server_metadata`](crate::server_metadata) (RFC 8414). Both sides of the
//! discovery flow live here: a resource server builds and serializes a
//! [`ProtectedResourceMetadata`] document and serves it at the
//! [`well_known_url`] for its resource identifier; a client fetches and
//! validates the document with [`ProtectedResourceMetadata::fetch`].

use http::HeaderMap;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::{EndpointUrl, error::Error, http::HttpClient, well_known::insert_well_known_path};

/// The cause of a protected-resource metadata failure.
#[derive(Debug, snafu::Snafu, huskarl_macros::Classify)]
#[non_exhaustive]
pub(crate) enum ResourceMetadataError {
    /// The resource identifier is not a usable URL.
    #[snafu(display("invalid resource identifier {resource:?}"))]
    InvalidResource {
        /// The rejected identifier.
        resource: String,
        /// The underlying error.
        source: Error,
    },
    /// The well-known path could not be inserted into a valid resource URL.
    #[snafu(display("building the well-known metadata URL for {resource:?}"))]
    #[classify(no)]
    WellKnownUrl {
        /// The identifier the URL was being built from.
        resource: String,
        /// The underlying error.
        source: http::Error,
    },
    /// The metadata document could not be fetched.
    #[snafu(display("fetching protected resource metadata from {url}"))]
    Fetching {
        /// The metadata URL.
        url: String,
        /// The underlying error.
        source: Error,
    },
    /// RFC 9728 §3.3: the document's `resource` must equal the one requested.
    #[snafu(display("resource mismatch (RFC 9728 §3.3): expected {expected:?}, got {actual:?}"))]
    #[classify(no)]
    ResourceMismatch {
        /// The resource that was requested.
        expected: String,
        /// The resource the document declared.
        actual: String,
    },
}

/// Protected resource metadata (RFC 9728 §2).
///
/// Build one with the [`builder`](Self::builder) on the resource-server side
/// and serve its JSON serialization at the resource's [`well_known_url`];
/// obtain one on the client side with [`fetch`](Self::fetch), or by
/// deserializing a document retrieved another way.
#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
#[non_exhaustive]
pub struct ProtectedResourceMetadata {
    /// The protected resource's resource identifier: a URL using the `https`
    /// scheme without a fragment component (RFC 9728 §1.2).
    ///
    /// Kept as a string because consumers compare it byte-for-byte — RFC 9728
    /// §3.3 requires the value be *identical* to the resource identifier the
    /// metadata URL was derived from, with no normalization.
    pub resource: String,
    /// Issuer identifiers of the OAuth authorization servers that can be
    /// used with this protected resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<String>>,
    /// URL of the protected resource's JWK Set document.
    ///
    /// These are the *resource's* keys (e.g. for verifying
    /// [`signed_metadata`](Self::signed_metadata) or signed responses) — not
    /// an authorization server's JWKS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<EndpointUrl>,
    /// Scope values used in authorization requests to request access to this
    /// protected resource (recommended by RFC 9728).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// Supported methods of sending an OAuth 2.0 bearer token (RFC 6750):
    /// `"header"`, `"body"`, `"query"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_methods_supported: Option<Vec<String>>,
    /// JWS `alg` values the resource supports for signing content such as
    /// [`signed_metadata`](Self::signed_metadata); `"none"` is not permitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_signing_alg_values_supported: Option<Vec<String>>,
    /// Human-readable name of the protected resource for display to the end
    /// user (recommended by RFC 9728).
    ///
    /// Language-tagged variants (`resource_name#ja`, RFC 9728 §2.1) are not
    /// modeled; they are ignored on deserialization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    /// URL of developer documentation for using the protected resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<EndpointUrl>,
    /// URL of the protected resource's requirements on how clients can use
    /// the data it provides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_policy_uri: Option<EndpointUrl>,
    /// URL of the protected resource's terms of service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_tos_uri: Option<EndpointUrl>,
    /// Whether mutual-TLS certificate-bound access tokens (RFC 8705) are
    /// supported. The RFC default is `false`; the member is omitted from the
    /// serialized document when `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[builder(default)]
    pub tls_client_certificate_bound_access_tokens: bool,
    /// RFC 9396 `authorization_details` type values supported for requesting
    /// access to this protected resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details_types_supported: Option<Vec<String>>,
    /// JWS `alg` values supported for validating `DPoP` proof JWTs
    /// (RFC 9449).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// Whether the protected resource always requires DPoP-bound access
    /// tokens. The RFC default is `false`; the member is omitted from the
    /// serialized document when `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[builder(default)]
    pub dpop_bound_access_tokens_required: bool,
    /// A JWT asserting the metadata parameters as claims, signed with one of
    /// the [`resource_signing_alg_values_supported`] algorithms (RFC 9728
    /// §2.2).
    ///
    /// Per the RFC, claims in the signed metadata take precedence over the
    /// plain JSON members. This library does not yet verify the JWT or apply
    /// that precedence — [`fetch`](Self::fetch) returns the plain members
    /// as-is and carries the JWT through untouched.
    ///
    /// [`resource_signing_alg_values_supported`]: Self::resource_signing_alg_values_supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<String>,
}

#[bon::bon]
impl ProtectedResourceMetadata {
    /// Fetches the protected resource metadata for a resource identifier
    /// (RFC 9728 §3).
    ///
    /// Derives the metadata URL with [`well_known_url`], performs the GET,
    /// and verifies that the returned `resource` member is identical to the
    /// requested resource identifier — RFC 9728 §3.3 forbids using the
    /// response otherwise, and the check is what stops a compromised or
    /// misconfigured host from impersonating another resource.
    ///
    /// [`signed_metadata`](Self::signed_metadata) is carried through
    /// unverified and its claims are not merged into the plain members.
    ///
    /// # Errors
    ///
    /// Returns a non-retryable error for an invalid resource identifier or an
    /// unusable response. Connection failures retain the transport's
    /// classification.
    #[builder(on(String, into))]
    pub async fn fetch<C: HttpClient>(http_client: &C, resource: String) -> Result<Self, Error> {
        let metadata_url = well_known_url(&resource)?;

        let metadata: Self = crate::http::get(
            http_client,
            metadata_url.clone().into_uri(),
            HeaderMap::new(),
        )
        .await
        .with_context(|_| FetchingSnafu {
            url: metadata_url.to_string(),
        })?;

        if metadata.resource != resource {
            return Err(ResourceMetadataError::ResourceMismatch {
                expected: resource.clone(),
                actual: metadata.resource.clone(),
            }
            .into());
        }

        Ok(metadata)
    }
}

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
/// Returns a non-retryable error unless `resource` is an absolute HTTP(S) URL
/// without a fragment (RFC 9728 §1.2).
pub fn well_known_url(resource: &str) -> Result<EndpointUrl, Error> {
    let resource_url: EndpointUrl = resource
        .parse()
        .context(InvalidResourceSnafu { resource })?;

    insert_well_known_path(resource_url.into_uri(), WELL_KNOWN_PATH)
        .context(WellKnownUrlSnafu { resource })?
        .try_into()
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::error::RetryAdvice;

    #[test]
    fn deserializes_a_full_document() {
        // Modeled on the RFC 9728 §3.2 example, plus a language-tagged
        // variant and an unknown member, both of which must be ignored.
        let source = r#"
            {
             "resource": "https://resource.example.com",
             "authorization_servers": ["https://as1.example.com", "https://as2.example.net"],
             "jwks_uri": "https://resource.example.com/jwks.json",
             "scopes_supported": ["profile.read", "profile.write"],
             "bearer_methods_supported": ["header"],
             "resource_signing_alg_values_supported": ["ES256"],
             "resource_name": "Example Resource",
             "resource_name#ja": "リソース",
             "resource_documentation": "https://resource.example.com/docs",
             "resource_policy_uri": "https://resource.example.com/policy",
             "resource_tos_uri": "https://resource.example.com/tos",
             "tls_client_certificate_bound_access_tokens": true,
             "authorization_details_types_supported": ["payment_initiation"],
             "dpop_signing_alg_values_supported": ["ES256", "RS256"],
             "dpop_bound_access_tokens_required": true,
             "signed_metadata": "eyJhbGciOiJFUzI1NiJ9.e30.sig",
             "unknown_future_member": 42
            }
        "#;
        let parsed = serde_json::from_str::<ProtectedResourceMetadata>(source).unwrap();
        assert_eq!(parsed.resource, "https://resource.example.com");
        assert_eq!(
            parsed.authorization_servers.as_deref(),
            Some(
                &[
                    "https://as1.example.com".to_string(),
                    "https://as2.example.net".to_string()
                ][..]
            )
        );
        assert_eq!(
            parsed.jwks_uri,
            "https://resource.example.com/jwks.json".parse().ok()
        );
        assert_eq!(parsed.resource_name.as_deref(), Some("Example Resource"));
        assert!(parsed.tls_client_certificate_bound_access_tokens);
        assert!(parsed.dpop_bound_access_tokens_required);
        assert_eq!(
            parsed.signed_metadata.as_deref(),
            Some("eyJhbGciOiJFUzI1NiJ9.e30.sig")
        );
    }

    #[test]
    fn booleans_default_to_false_when_absent() {
        let parsed = serde_json::from_str::<ProtectedResourceMetadata>(
            r#"{"resource": "https://resource.example.com"}"#,
        )
        .unwrap();
        assert!(!parsed.tls_client_certificate_bound_access_tokens);
        assert!(!parsed.dpop_bound_access_tokens_required);
    }

    #[test]
    fn resource_is_required() {
        assert!(serde_json::from_str::<ProtectedResourceMetadata>(r"{}").is_err());
    }

    #[test]
    fn serializes_without_defaulted_or_absent_members() {
        // A minimal document is just the required `resource`: absent options
        // and RFC-default booleans are omitted, not emitted as null/false.
        let doc = ProtectedResourceMetadata::builder()
            .resource("https://resource.example.com")
            .build();
        assert_eq!(
            serde_json::to_value(&doc).unwrap(),
            serde_json::json!({"resource": "https://resource.example.com"})
        );
    }

    #[test]
    fn serializes_set_members_under_their_rfc_names() {
        let doc = ProtectedResourceMetadata::builder()
            .resource("https://resource.example.com")
            .authorization_servers(vec!["https://as.example.com".to_string()])
            .scopes_supported(vec!["profile.read".to_string()])
            .resource_name("Example Resource")
            .dpop_bound_access_tokens_required(true)
            .build();
        assert_eq!(
            serde_json::to_value(&doc).unwrap(),
            serde_json::json!({
                "resource": "https://resource.example.com",
                "authorization_servers": ["https://as.example.com"],
                "scopes_supported": ["profile.read"],
                "resource_name": "Example Resource",
                "dpop_bound_access_tokens_required": true,
            })
        );
    }

    /// An [`HttpClient`] double that captures the request URI and replies
    /// with a fixed body.
    struct FakeResourceClient {
        body: String,
        requested: std::sync::Mutex<Option<http::Uri>>,
    }

    impl FakeResourceClient {
        fn responding(body: impl Into<String>) -> Self {
            Self {
                body: body.into(),
                requested: std::sync::Mutex::new(None),
            }
        }
    }

    impl HttpClient for FakeResourceClient {
        fn execute(
            &self,
            request: http::Request<bytes::Bytes>,
            _idempotency: crate::http::Idempotency,
        ) -> crate::platform::MaybeSendBoxFuture<'_, Result<crate::http::HttpResponse, Error>>
        {
            *self.requested.lock().unwrap() = Some(request.uri().clone());
            Box::pin(async move {
                Ok(crate::http::HttpResponse {
                    status: http::StatusCode::OK,
                    headers: HeaderMap::new(),
                    body: bytes::Bytes::from(self.body.clone()),
                })
            })
        }
    }

    #[tokio::test]
    async fn fetch_gets_the_well_known_url_and_returns_the_document() {
        let client = FakeResourceClient::responding(
            r#"{"resource": "https://resource.example.com/api", "scopes_supported": ["read"]}"#,
        );

        let metadata = ProtectedResourceMetadata::fetch()
            .http_client(&client)
            .resource("https://resource.example.com/api")
            .call()
            .await
            .unwrap();

        assert_eq!(
            client
                .requested
                .lock()
                .unwrap()
                .as_ref()
                .map(ToString::to_string),
            Some(
                "https://resource.example.com/.well-known/oauth-protected-resource/api".to_string()
            )
        );
        assert_eq!(
            metadata.scopes_supported.as_deref(),
            Some(&["read".to_string()][..])
        );
    }

    #[tokio::test]
    async fn fetch_rejects_a_resource_mismatch() {
        // RFC 9728 §3.3: a document whose `resource` differs from the
        // identifier the URL was derived from must not be used.
        let client =
            FakeResourceClient::responding(r#"{"resource": "https://attacker.example.com"}"#);

        let err = ProtectedResourceMetadata::fetch()
            .http_client(&client)
            .resource("https://resource.example.com")
            .call()
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("RFC 9728"), "{err:#}");
    }

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
        assert_eq!(err.retry_advice(), RetryAdvice::No, "{err}");
    }
}
