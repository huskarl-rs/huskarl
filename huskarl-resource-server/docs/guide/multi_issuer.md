# Accepting tokens from several issuers

[`MultiIssuerValidator`](crate::validator::multi_issuer::MultiIssuerValidator)
routes each request to a per-issuer validator by reading the token's `iss`
claim, then delegates the full validation to it. For why this routing is safe
and how to choose a common claims type, see the [multi-issuer routing
explanation](crate::_docs::explanation::multi_issuer_routing).

## Unifying claim types

Per-issuer validators usually have different claims types. Give them a common
type `C` by wrapping each in
[`MapClaims`](crate::validator::multi_issuer::MapClaims), whose mapping is a
plain `Fn(SourceClaims) -> C`:

```no_run
use std::sync::Arc;

use huskarl_resource_server::{
    core::{jwk::JwksSource, jwt::validator::ClaimCheck},
    validator::{
        custom::CustomValidator,
        multi_issuer::{MapClaims, MultiIssuerValidator},
    },
};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let http = huskarl_reqwest::ReqwestClient::builder().build().await?;
#[derive(Clone, serde::Deserialize)]
struct GoogleIdClaims {
    email: Option<String>,
    email_verified: Option<bool>,
}
#[derive(Clone, serde::Deserialize)]
struct OktaClaims {
    #[serde(default)]
    scp: Vec<String>,
}

#[derive(Clone)]
struct Principal {
    email: Option<String>,
    scopes: Vec<String>,
}

let google = CustomValidator::builder()
    .with_claims::<GoogleIdClaims>()
    .authorization_server("https://accounts.google.com")
    .issuer(ClaimCheck::required_value("https://accounts.google.com"))
    .audience(ClaimCheck::required_value("<your-google-oauth-client-id>"))
    .token_type(ClaimCheck::NoCheck)
    .require_jti(false)
    .jwks_uri("https://www.googleapis.com/oauth2/v3/certs".parse()?)
    .jws_verifier_factory(Arc::new(
        JwksSource::builder().http_client(http.clone()).build(),
    ))
    .build()
    .await?;

let okta = CustomValidator::builder()
    .with_claims::<OktaClaims>()
    .authorization_server("https://example.okta.com/oauth2/default")
    .issuer(ClaimCheck::required_value(
        "https://example.okta.com/oauth2/default",
    ))
    .audience(ClaimCheck::required_value("api://my-resource"))
    .jwks_uri("https://example.okta.com/oauth2/default/v1/keys".parse()?)
    .jws_verifier_factory(Arc::new(
        JwksSource::builder().http_client(http.clone()).build(),
    ))
    .build()
    .await?;

let validator = MultiIssuerValidator::<Principal>::builder()
    .source(
        "https://accounts.google.com",
        MapClaims::new(google, |c: GoogleIdClaims| Principal {
            email: c.email.filter(|_| c.email_verified == Some(true)),
            scopes: Vec::new(),
        }),
    )
    .source(
        "https://example.okta.com/oauth2/default",
        MapClaims::new(okta, |c: OktaClaims| Principal {
            email: None,
            scopes: c.scp,
        }),
    )
    .build();
# let _ = validator;
# Ok(())
# }
```
