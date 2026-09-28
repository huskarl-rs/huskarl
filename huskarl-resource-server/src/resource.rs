//! Framework-independent protected-resource identity and metadata preparation.
//!
//! A definition can be constructed before its validator. Adapters bind it to
//! authentication and publish the prepared document separately at server scope.
//! See the [metadata guide](crate::_docs::guide::resource_metadata) for builder
//! ownership, scope defaults, standalone publication, and browser discovery.

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
    description: ResourceDescription,
}

// Only owner-supplied fields belong here. Identity and authentication capabilities
// are derived separately and cannot be replaced by presentation configuration.
#[derive(Clone, Debug, Default)]
struct ResourceDescription {
    resource_name: Option<String>,
    resource_documentation: Option<String>,
    resource_policy_uri: Option<String>,
    resource_tos_uri: Option<String>,
    scopes_supported: Option<Vec<String>>,
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

#[bon::bon]
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
            description: ResourceDescription::default(),
        })
    }
    /// Configures a resource with optional owner-supplied discovery information.
    ///
    /// `mapping`, `subpath`, and `audience` are required. Identity, metadata URL,
    /// and ingress mount are derived at `build()`; validator capabilities are
    /// supplied later when binding. Existing `new()` calls remain equivalent to
    /// a builder without owner-supplied fields.
    ///
    /// # Errors
    /// Rejects invalid mappings, resource identifiers, and empty audience bindings.
    #[builder(on(String, into))]
    pub fn builder(
        /// Trusted public-to-ingress URL mapping.
        mapping: PublicUrlMapping,
        /// Resource path relative to the public base, including any query.
        subpath: &str,
        /// Token audiences accepted for this resource.
        audience: AudienceBinding,
        /// Human-readable name of the resource.
        resource_name: Option<String>,
        /// Documentation for using this resource.
        /// Callers should supply an absolute URL. Stored as supplied, without validation.
        resource_documentation: Option<String>,
        /// Resource policy on how clients can use its data.
        /// Callers should supply an absolute URL. Stored as supplied, without validation.
        resource_policy_uri: Option<String>,
        /// Resource terms of service.
        /// Callers should supply an absolute URL. Stored as supplied, without validation.
        resource_tos_uri: Option<String>,
        /// Advertised capabilities, not access grants. Overrides scopes supplied
        /// during binding; an explicit empty list omits the field. When unset,
        /// binding supplies the defaults. Values are sorted and deduplicated.
        scopes_supported: Option<Vec<String>>,
    ) -> Result<Self, ResourceError> {
        let mut definition = Self::new(mapping, subpath, audience)?;
        definition.description = ResourceDescription {
            resource_name,
            resource_documentation,
            resource_policy_uri,
            resource_tos_uri,
            scopes_supported,
        };
        Ok(definition)
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
    /// Owner-configured scopes override the supplied defaults. Advertised scopes
    /// are sorted and deduplicated; an empty list omits them.
    ///
    /// # Errors
    /// Rejects inconsistent metadata URLs or documents that cannot be serialized.
    pub fn prepare<V: ProvideValidatorMetadata>(
        &self,
        validator: &V,
        scopes: Vec<String>,
    ) -> Result<PreparedResource, ResourceError> {
        let (validator_metadata, body) = prepare_metadata_with_description(
            &self.resource,
            validator,
            scopes,
            &self.description,
        )?;
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
    prepare_metadata_with_description(resource, validator, scopes, &ResourceDescription::default())
}

fn prepare_metadata_with_description<V: ProvideValidatorMetadata>(
    resource: &str,
    validator: &V,
    scopes: Vec<String>,
    description: &ResourceDescription,
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
    let scopes: BTreeSet<_> = description
        .scopes_supported
        .clone()
        .unwrap_or(scopes)
        .into_iter()
        .collect();
    let scopes = if scopes.is_empty() {
        None
    } else {
        Some(scopes.into_iter().collect())
    };
    let mut document = metadata
        .to_resource_metadata()
        .ok_or(ResourceError::DocumentUnavailable)?;
    document
        .resource_name
        .clone_from(&description.resource_name);
    document
        .resource_documentation
        .clone_from(&description.resource_documentation);
    document
        .resource_policy_uri
        .clone_from(&description.resource_policy_uri);
    document
        .resource_tos_uri
        .clone_from(&description.resource_tos_uri);
    document.scopes_supported = scopes;
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
    fn builder_preserves_identity_capabilities_and_owner_fields() {
        struct Capabilities;
        impl ProvideValidatorMetadata for Capabilities {
            fn validator_metadata(&self, _: Option<&str>) -> ValidatorMetadata {
                ValidatorMetadata::builder()
                    .authorization_servers(vec!["https://issuer.example".into()])
                    .dpop_bound_access_tokens_required(true)
                    .dpop_signing_alg_values_supported(vec!["ES256".into()])
                    .bearer_methods_supported(vec!["header"])
                    .build()
            }
        }
        let mapping = PublicUrlMapping::new("https://api.example/gateway", "/edge").unwrap();
        let plain = ResourceDefinition::new(
            mapping.clone(),
            "/items?tenant=one",
            AudienceBinding::mapped(["items"]),
        )
        .unwrap();
        let configured = ResourceDefinition::builder()
            .mapping(mapping.clone())
            .subpath("/items?tenant=one")
            .audience(AudienceBinding::mapped(["items"]))
            .resource_name("Items API")
            .resource_documentation("https://api.example/docs#authentication")
            .resource_policy_uri("https://api.example/privacy#data-use")
            .resource_tos_uri("https://api.example/terms#conditions")
            .scopes_supported(vec!["write".into(), "read".into(), "read".into()])
            .build()
            .unwrap();
        assert_eq!(configured.resource(), plain.resource());
        assert_eq!(configured.metadata_uri(), plain.metadata_uri());
        assert_eq!(configured.incoming_mount(), plain.incoming_mount());
        assert_eq!(configured.audiences(), plain.audiences());
        let prepared = configured
            .prepare(&Capabilities, vec!["fallback".into()])
            .unwrap();
        let document: serde_json::Value =
            serde_json::from_slice(prepared.publication().body).unwrap();
        assert_eq!(document["resource"], configured.resource());
        assert_eq!(document["resource_name"], "Items API");
        assert_eq!(
            document["resource_documentation"],
            "https://api.example/docs#authentication"
        );
        assert_eq!(
            document["resource_policy_uri"],
            "https://api.example/privacy#data-use"
        );
        assert_eq!(
            document["resource_tos_uri"],
            "https://api.example/terms#conditions"
        );
        assert_eq!(
            document["scopes_supported"],
            serde_json::json!(["read", "write"])
        );
        assert_eq!(
            document["authorization_servers"],
            serde_json::json!(["https://issuer.example"])
        );
        assert_eq!(document["dpop_bound_access_tokens_required"], true);
        assert_eq!(
            document["dpop_signing_alg_values_supported"],
            serde_json::json!(["ES256"])
        );
        assert_eq!(
            document["bearer_methods_supported"],
            serde_json::json!(["header"])
        );
        let original = plain.prepare(&Capabilities, vec![]).unwrap();
        assert_eq!(
            prepared.validator_metadata.challenges(None, None, None),
            original.validator_metadata.challenges(None, None, None)
        );
    }

    #[test]
    fn builder_scope_defaults_differ_from_explicit_empty_and_validation_is_retained() {
        let mapping = PublicUrlMapping::new("https://api.example", "/").unwrap();
        for explicit in [None, Some(vec![])] {
            let definition = ResourceDefinition::builder()
                .mapping(mapping.clone())
                .subpath("/items")
                .audience(AudienceBinding::ResourceIdentifier)
                .maybe_scopes_supported(explicit.clone())
                .build()
                .unwrap();
            let prepared = definition.prepare(&Metadata, vec!["read".into()]).unwrap();
            let document: serde_json::Value = serde_json::from_slice(&prepared.body).unwrap();
            assert_eq!(
                document.get("scopes_supported").is_some(),
                explicit.is_none()
            );
        }
        assert!(matches!(
            ResourceDefinition::builder()
                .mapping(mapping.clone())
                .subpath("/items")
                .audience(AudienceBinding::mapped(Vec::<String>::new()))
                .build(),
            Err(ResourceError::EmptyAudiences)
        ));
        let http = PublicUrlMapping::new("http://api.example", "/").unwrap();
        assert!(matches!(
            ResourceDefinition::builder()
                .mapping(http)
                .subpath("/items")
                .audience(AudienceBinding::ResourceIdentifier)
                .build(),
            Err(ResourceError::HttpsRequired)
        ));
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
