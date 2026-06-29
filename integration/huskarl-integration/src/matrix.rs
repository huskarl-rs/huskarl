//! Derived coverage report: which flows each provider exercises, computed from
//! [`FLOWS`] and each provider's supported [`Features`].

use huskarl_testkit::{DexProvider, Features, KeycloakProvider, NodeOidcProvider, OktaProvider};

use crate::flows::FLOWS;

/// All variants as `(flow/variant, required_features)` pairs.
pub fn flows() -> Vec<(String, Features)> {
    FLOWS
        .iter()
        .flat_map(|flow| {
            flow.variants
                .iter()
                .map(move |v| (format!("{}/{}", flow.name, v.name), v.required))
        })
        .collect()
}

/// Every wired provider with its supported features (from each `FEATURES` const).
pub fn all_providers() -> Vec<(&'static str, Features)> {
    vec![
        ("keycloak", KeycloakProvider::FEATURES),
        ("dex", DexProvider::FEATURES),
        ("node-oidc", NodeOidcProvider::FEATURES),
        ("okta", OktaProvider::FEATURES),
    ]
}

/// A coverage checklist per provider: each variant marked `✓` or `—`.
pub fn coverage_report() -> String {
    let flows = flows();
    let mut out = String::new();
    for (i, (name, supported)) in all_providers().iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(name);
        out.push('\n');
        for (id, required) in &flows {
            let mark = if supported.contains(*required) {
                "✓"
            } else {
                "—"
            };
            out.push_str(&format!("  {mark} {id}\n"));
        }
    }
    out
}
