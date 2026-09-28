//! Generate RFC 9728 metadata for an independently owned publisher.
//! Run: cargo run -p huskarl-core --example resource_metadata
use huskarl_core::resource_metadata::{ProtectedResourceMetadata, well_known_url};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let document = ProtectedResourceMetadata::builder()
        .resource("https://api.example.com/inventory")
        .resource_name("Inventory API")
        .resource_documentation("https://api.example.com/docs/inventory#authentication")
        .authorization_servers(vec!["https://auth.example.com".into()])
        .scopes_supported(vec!["inventory.read".into()])
        .bearer_methods_supported(vec!["header".into()])
        .build();
    // Derive and validate the canonical publication URL. The consuming server
    // owns routing and HTTP responses (application/json, public GET and HEAD).
    let endpoint = well_known_url(&document.resource)?;
    eprintln!("Publish at {endpoint}");
    println!("{}", serde_json::to_string_pretty(&document)?);
    Ok(())
}
