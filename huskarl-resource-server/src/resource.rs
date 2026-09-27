//! Framework-independent protected-resource identity and metadata preparation.
//!
//! A definition can be constructed before its validator. Adapters bind it to
//! authentication and publish the prepared document separately at server scope.

use std::collections::BTreeSet;

use http::Uri;
use snafu::prelude::*;

use crate::{
    core::{resource_metadata::well_known_url, url_mapping::PublicUrlMapping},
    validator::metadata::{ProvideValidatorMetadata, ValidatorMetadata},
};

/// How a public resource identifier maps to token audience values.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AudienceBinding {
    /// Require the exact public resource identifier in `aud`.
    ResourceIdentifier,
    /// Accept one of the authorization server's explicitly mapped audiences.
    Mapped(Vec<String>),
}
impl AudienceBinding {
    /// Declares the audience values issued for this resource.
    #[must_use]
    pub fn mapped<I, T>(audiences: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        Self::Mapped(audiences.into_iter().map(Into::into).collect())
    }
    /// Resolves this binding against an exact resource identifier.
    #[must_use]
    pub fn into_audiences(self, resource: &str) -> Vec<String> {
        match self {
            Self::ResourceIdentifier => vec![resource.to_owned()],
            Self::Mapped(values) => values,
        }
    }
}

/// Validated identity, ingress mount, URL mapping, and audiences for a resource.
#[derive(Clone, Debug)]
pub struct ResourceDefinition {
    mapping: PublicUrlMapping,
    resource: String,
    incoming_mount: String,
    audiences: Vec<String>,
    endpoint: Uri,
}

/// Configuration error defining, preparing, or assembling protected resources.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ResourceError {
    /// Resources in one assembly have different public origins.
    #[snafu(display("resources in one assembly must share a public origin"))]
    MixedPublicOrigins,
    /// Authentication mounts overlap.
    #[snafu(display("authentication mounts overlap"))]
    OverlappingMounts,
    /// Metadata endpoints collide for the selected router.
    #[snafu(display("metadata endpoints collide for this router"))]
    MetadataEndpointCollision,
    /// Invalid deployment mapping or resource subpath.
    #[snafu(display("invalid resource URL mapping"))]
    Mapping {
        /// The underlying mapping error.
        source: crate::core::url_mapping::MappingError,
    },
    /// Protected resources require HTTPS.
    #[snafu(display("protected resources require HTTPS"))]
    HttpsRequired,
    /// The identifier cannot produce a protected-resource metadata URL.
    #[snafu(display("invalid protected-resource identifier"))]
    Identifier {
        /// The underlying identifier validation error.
        source: crate::core::Error,
    },
    /// No acceptable audiences were provided.
    #[snafu(display("a resource must accept at least one audience"))]
    EmptyAudiences,
    /// The validator advertises another metadata endpoint.
    #[snafu(display("metadata URL {configured:?} differs from {derived:?}"))]
    MetadataUrlMismatch {
        /// Configured URL.
        configured: String,
        /// Derived URL.
        derived: String,
    },
    /// The validator could not produce a metadata document.
    #[snafu(display("resource metadata document unavailable"))]
    DocumentUnavailable,
    /// Serialization failed.
    #[snafu(display("could not serialize resource metadata"))]
    Serialization {
        /// The underlying JSON serialization error.
        source: serde_json::Error,
    },
}

/// Prepared metadata and the corresponding challenge configuration.
#[derive(Clone, Debug)]
pub struct PreparedResource {
    /// The validated resource definition used to prepare this document.
    pub definition: ResourceDefinition,
    /// Metadata used to construct authentication challenges.
    pub validator_metadata: ValidatorMetadata,
    /// Serialized JSON document for adapter-specific HTTP publication.
    pub body: Vec<u8>,
}
/// Borrowed publication information for an independently owned HTTP publisher.
///
/// This is a prepared snapshot, not a route registration or refresh mechanism.
/// The consumer owns ingress routing and protocol-compliant HTTP serving.
#[derive(Clone, Copy, Debug)]
pub struct ResourcePublication<'a> {
    /// Canonical absolute public URL, including any query component.
    pub uri: &'a Uri,
    /// The exact serialized metadata served by the corresponding adapter.
    pub body: &'a [u8],
}

impl ResourcePublication<'_> {
    /// Media type of the prepared metadata representation.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        "application/json"
    }
}

impl PreparedResource {
    /// Exports metadata without installing a local HTTP endpoint.
    #[must_use]
    pub fn publication(&self) -> ResourcePublication<'_> {
        ResourcePublication {
            uri: self.definition.metadata_uri(),
            body: &self.body,
        }
    }
}

impl ResourceDefinition {
    /// Derives public identity and incoming mount from one mapping and subpath.
    ///
    /// # Errors
    /// Rejects invalid resource identifiers, subpaths, and empty audience bindings.
    pub fn new(
        mapping: PublicUrlMapping,
        subpath: &str,
        audience: AudienceBinding,
    ) -> Result<Self, ResourceError> {
        let uri = mapping.resource_url(subpath).context(MappingSnafu)?;
        if uri.scheme_str() != Some("https") {
            return Err(ResourceError::HttpsRequired);
        }
        let resource = uri.to_string();
        let endpoint = well_known_url(&resource)
            .context(IdentifierSnafu)?
            .as_uri()
            .clone();
        let incoming_mount = mapping
            .incoming_uri(&uri)
            .context(MappingSnafu)?
            .path()
            .to_owned();
        let audiences = audience.into_audiences(&resource);
        if audiences.is_empty() {
            return Err(ResourceError::EmptyAudiences);
        }
        Ok(Self {
            mapping,
            resource,
            incoming_mount,
            audiences,
            endpoint,
        })
    }
    /// Exact identifier supplied to authorization servers and metadata clients.
    pub fn resource(&self) -> &str {
        &self.resource
    }
    /// Framework-independent ingress mount (before router nesting).
    pub fn incoming_mount(&self) -> &str {
        &self.incoming_mount
    }
    /// Trusted deployment mapping.
    pub fn mapping(&self) -> &PublicUrlMapping {
        &self.mapping
    }
    /// Accepted token audiences.
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }
    /// Canonical public metadata URL; it may be outside the resource mapping.
    pub fn metadata_uri(&self) -> &Uri {
        &self.endpoint
    }
    /// Prepares a document and matching challenges without mounting a service.
    /// Advertised scopes are sorted and deduplicated; an empty list omits them.
    ///
    /// # Errors
    /// Rejects inconsistent metadata URLs or documents that cannot be serialized.
    pub fn prepare<V: ProvideValidatorMetadata>(
        &self,
        validator: &V,
        scopes: Vec<String>,
    ) -> Result<PreparedResource, ResourceError> {
        let (validator_metadata, body) = prepare_metadata(&self.resource, validator, scopes)?;
        Ok(PreparedResource {
            definition: self.clone(),
            validator_metadata,
            body,
        })
    }
}

/// Prepares consistent challenge metadata and JSON for an already selected resource.
/// Scopes describe capabilities, not access grants; empty lists omit the field.
///
/// # Errors
/// Rejects unusable resource identifiers, conflicting metadata URLs, and serialization failures.
pub fn prepare_metadata<V: ProvideValidatorMetadata>(
    resource: &str,
    validator: &V,
    scopes: Vec<String>,
) -> Result<(ValidatorMetadata, Vec<u8>), ResourceError> {
    let endpoint = well_known_url(resource).context(IdentifierSnafu)?;
    let mut metadata = validator.validator_metadata(Some(resource));
    let derived = endpoint.to_string();
    if let Some(configured) = metadata.resource_metadata.as_ref()
        && configured != &derived
    {
        return Err(ResourceError::MetadataUrlMismatch {
            configured: configured.clone(),
            derived,
        });
    }
    metadata.resource = Some(resource.to_owned());
    metadata.resource_metadata = Some(derived);
    let mut document = metadata
        .to_resource_metadata()
        .ok_or(ResourceError::DocumentUnavailable)?;
    let scopes: BTreeSet<_> = scopes.into_iter().collect();
    document.scopes_supported = if scopes.is_empty() {
        None
    } else {
        Some(scopes.into_iter().collect())
    };
    Ok((
        metadata,
        serde_json::to_vec(&document).context(SerializationSnafu)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Metadata;
    impl ProvideValidatorMetadata for Metadata {
        fn validator_metadata(&self, _: Option<&str>) -> ValidatorMetadata {
            ValidatorMetadata::builder().build()
        }
    }
    #[test]
    fn definition_drives_audiences_document_and_challenges() {
        let definition = ResourceDefinition::new(
            PublicUrlMapping::new("https://api.example/gateway", "/edge").unwrap(),
            "/inventory?tenant=one",
            AudienceBinding::ResourceIdentifier,
        )
        .unwrap();
        assert_eq!(definition.incoming_mount(), "/edge/inventory");
        assert_eq!(
            definition.audiences(),
            &["https://api.example/gateway/inventory?tenant=one"]
        );
        assert_eq!(
            definition.metadata_uri(),
            "https://api.example/.well-known/oauth-protected-resource/gateway/inventory?tenant=one"
        );
        let prepared = definition
            .prepare(
                &Metadata,
                vec!["write".into(), "read".into(), "read".into()],
            )
            .unwrap();
        let publication = prepared.publication();
        assert_eq!(publication.uri, definition.metadata_uri());
        assert_eq!(publication.content_type(), "application/json");
        assert_eq!(publication.body, prepared.body);
        let body: serde_json::Value = serde_json::from_slice(&prepared.body).unwrap();
        assert_eq!(body["resource"], definition.resource());
        assert_eq!(
            body["scopes_supported"],
            serde_json::json!(["read", "write"])
        );
        assert_eq!(
            prepared.validator_metadata.resource_metadata.as_deref(),
            Some(definition.metadata_uri().to_string().as_str())
        );
    }
    #[test]
    fn empty_audiences_and_non_https_resources_fail_at_definition() {
        let mapping = PublicUrlMapping::new("https://api.example", "/").unwrap();
        assert!(matches!(
            ResourceDefinition::new(mapping, "/", AudienceBinding::mapped(Vec::<String>::new())),
            Err(ResourceError::EmptyAudiences)
        ));
        assert!(
            ResourceDefinition::new(
                PublicUrlMapping::new("http://api.example", "/").unwrap(),
                "/",
                AudienceBinding::ResourceIdentifier
            )
            .is_err()
        );
    }
}

/// Metadata dispatch capability of the framework publishing the documents.
#[derive(Clone, Copy, Debug)]
pub enum MetadataRouting {
    /// The router distinguishes paths only (for example Axum).
    Path,
    /// The publisher distinguishes paths and queries.
    PathAndQuery,
}

/// Validates the relationships consumed by a server's resource assembly.
#[derive(Debug)]
pub struct ResourceRegistry {
    routing: MetadataRouting,
    entries: Vec<(ResourceDefinition, Uri)>,
}
impl ResourceRegistry {
    /// Starts an empty registry with explicit metadata routing capabilities.
    #[must_use]
    pub fn new(routing: MetadataRouting) -> Self {
        Self {
            routing,
            entries: Vec::new(),
        }
    }

    /// Validates and records a resource and its separately mapped metadata URL.
    /// Overlapping authentication mounts, mixed public origins, and endpoint
    /// collisions are rejected. Adapters reserve registered metadata paths as
    /// public exceptions, including inside authentication mounts.
    ///
    /// # Errors
    /// Rejects conflicting mounts, origins, metadata endpoints, or mappings.
    pub fn register(
        &mut self,
        definition: &ResourceDefinition,
        metadata_mapping: &PublicUrlMapping,
    ) -> Result<Uri, ResourceError> {
        let metadata = metadata_mapping
            .incoming_uri(definition.metadata_uri())
            .context(MappingSnafu)?;
        for (other, endpoint) in &self.entries {
            if other.metadata_uri().scheme() != definition.metadata_uri().scheme()
                || other.metadata_uri().authority() != definition.metadata_uri().authority()
            {
                return Err(ResourceError::MixedPublicOrigins);
            }
            if contains(other.incoming_mount(), definition.incoming_mount())
                || contains(definition.incoming_mount(), other.incoming_mount())
            {
                return Err(ResourceError::OverlappingMounts);
            }
            let duplicate = match self.routing {
                MetadataRouting::Path => endpoint.path() == metadata.path(),
                MetadataRouting::PathAndQuery => {
                    endpoint.path_and_query() == metadata.path_and_query()
                }
            };
            if duplicate {
                return Err(ResourceError::MetadataEndpointCollision);
            }
        }
        self.entries.push((definition.clone(), metadata.clone()));
        Ok(metadata)
    }
}
fn contains(mount: &str, path: &str) -> bool {
    mount == "/"
        || path == mount
        || path
            .strip_prefix(mount)
            .is_some_and(|suffix| mount.ends_with('/') || suffix.starts_with('/'))
}

#[cfg(test)]
mod registry_tests {
    use super::*;
    fn definition(prefix: &str, path: &str) -> ResourceDefinition {
        ResourceDefinition::new(
            PublicUrlMapping::new("https://api.example", prefix).unwrap(),
            path,
            AudienceBinding::ResourceIdentifier,
        )
        .unwrap()
    }
    #[test]
    fn rejects_overlapping_authentication_mounts() {
        let metadata = PublicUrlMapping::new("https://api.example", "/").unwrap();
        let mut registry = ResourceRegistry::new(MetadataRouting::Path);
        registry
            .register(&definition("/", "/app"), &metadata)
            .unwrap();
        assert!(
            registry
                .register(&definition("/", "/app/nested"), &metadata)
                .is_err()
        );
        assert!(
            registry
                .register(&definition("/", "/app"), &metadata)
                .is_err()
        );
        assert!(registry.register(&definition("/", "/"), &metadata).is_err());
        registry
            .register(&definition("/", "/.well-known"), &metadata)
            .unwrap();
        registry
            .register(&definition("/", "/app2"), &metadata)
            .unwrap();
    }
    #[test]
    fn root_mount_and_framework_route_characters_are_not_domain_errors() {
        let metadata = PublicUrlMapping::new("https://api.example", "/").unwrap();
        for path in ["/", "/{tenant}"] {
            let mut registry = ResourceRegistry::new(MetadataRouting::Path);
            registry
                .register(&definition("/", path), &metadata)
                .unwrap();
        }
    }
    #[test]
    fn metadata_query_collision_depends_on_router_capability() {
        let metadata = PublicUrlMapping::new("https://api.example", "/").unwrap();
        let first = definition("/one", "/app?tenant=one");
        let second = definition("/two", "/app?tenant=two");
        let mut paths = ResourceRegistry::new(MetadataRouting::Path);
        paths.register(&first, &metadata).unwrap();
        assert!(paths.register(&second, &metadata).is_err());
        let mut queries = ResourceRegistry::new(MetadataRouting::PathAndQuery);
        queries.register(&first, &metadata).unwrap();
        queries.register(&second, &metadata).unwrap();
    }
    #[test]
    fn metadata_mapping_must_cover_the_canonical_endpoint() {
        let definition = definition("/edge", "/app");
        let mut registry = ResourceRegistry::new(MetadataRouting::Path);
        let wrong = PublicUrlMapping::new("https://api.example/app", "/edge").unwrap();
        assert!(registry.register(&definition, &wrong).is_err());
        let other_origin = PublicUrlMapping::new("https://other.example", "/").unwrap();
        assert!(registry.register(&definition, &other_origin).is_err());
    }
}
