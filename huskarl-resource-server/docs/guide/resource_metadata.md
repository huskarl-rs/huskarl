# Configure and publish protected-resource metadata

Use `ResourceDefinition::builder()` to configure a resource and its
[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) metadata:

```rust
use huskarl_resource_server::{
    core::url_mapping::PublicUrlMapping,
    resource::{AudienceBinding, ResourceDefinition},
};
let mapping = PublicUrlMapping::new("https://api.example.com/gateway", "/edge")?;
let definition = ResourceDefinition::builder()
    .mapping(mapping)
    .subpath("/inventory")
    .audience(AudienceBinding::ResourceIdentifier)
    .resource_name("Inventory API")
    .resource_documentation("https://api.example.com/docs/inventory#authentication")
    .scopes_supported(vec!["inventory.read".into()])
    .build()?;
assert_eq!(definition.incoming_mount(), "/edge/inventory");
# Ok::<(), Box<dyn std::error::Error>>(())
```

Identity and discovery URLs are derived from the mapping and subpath. Binding
supplies authentication capabilities from the validator. Callers are responsible
for descriptive metadata; documentation, policy, and terms links should be
absolute URLs and are stored without validation, preserving fragments.

Leaving `scopes_supported` unset preserves adapter defaults: Pingora gathers rule
scopes, while Axum takes the list passed during binding. An explicit list overrides
those defaults; an empty list omits the field. Lists are sorted and deduplicated.
Advertised scopes do not change authorization rules.

Bind the definition using the adapter's `BoundResource` or assembly. The native
endpoint and `publication()` snapshot carry the same document. An external
publisher owns routing and HTTP responses at the derived metadata URL.

For standalone publication, use `ValidatorMetadata::to_resource_metadata()` and
assign descriptive fields on the returned document, or construct a document with
`ProtectedResourceMetadata::builder()`. See the `huskarl-core` example:
`cargo run -p huskarl-core --example resource_metadata`.

For browser clients, see [Configure browser access with CORS](crate::_docs::guide::cors).
