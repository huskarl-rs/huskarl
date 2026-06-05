//! Covers the patterns the production crate depends on:
//! - `method(name = "…", vis = "")` config on `#[from_metadata]`
//! - the generated `{Struct}{PascalMethod}State` alias spelled out by a
//!   hand-written wrapper (the `userinfo.rs` / `authorization_code` pattern)
//! - a gating field that also carries `#[try_setter]` (routed through bon's
//!   `_internal` setter, bypassing the fallible conversion)

use bon::Builder;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url(String);

pub trait IntoUrl {
    type Error;
    fn into_url(self) -> Result<Url, Self::Error>;
}

impl IntoUrl for &str {
    type Error = std::convert::Infallible;
    fn into_url(self) -> Result<Url, Self::Error> {
        Ok(Url(self.to_owned()))
    }
}

pub struct Meta {
    // Already the target type in the metadata — `from_metadata` bypasses the
    // fallible conversion via the `_internal` setter.
    endpoint: Option<Url>,
    issuer: String,
}

#[huskarl_macros::from_metadata(
    metadata = crate::Meta,
    method(name = "from_meta_internal", vis = "")
)]
#[huskarl_macros::try_builder]
#[derive(Builder)]
#[builder(state_mod(name = "builder"))]
pub struct Client {
    // Gate (required target, Option source) + try_setter on the same field.
    #[from_metadata(path = "endpoint?")]
    #[try_setter(crate::IntoUrl::into_url)]
    endpoint: Url,

    #[from_metadata(path = "issuer")]
    issuer: Option<String>,
}

impl Client {
    /// Public wrapper spelling out the generated state alias by name, exactly
    /// as the production crate does.
    pub fn from_meta(meta: &Meta) -> Option<ClientBuilder<ClientFromMetaInternalState>> {
        Self::from_meta_internal(meta)
    }
}

fn main() {
    let meta = Meta {
        endpoint: Some(Url("https://as.example.com".to_owned())),
        issuer: "https://as.example.com".to_owned(),
    };
    let client = Client::from_meta(&meta).expect("endpoint present").build();
    assert_eq!(client.endpoint, Url("https://as.example.com".to_owned()));
    assert_eq!(client.issuer.as_deref(), Some("https://as.example.com"));

    // Absent gate source → no builder.
    let meta = Meta {
        endpoint: None,
        issuer: String::new(),
    };
    assert!(Client::from_meta(&meta).is_none());

    // The fallible setter still works for manual construction.
    let client = Client::builder()
        .endpoint("https://manual.example.com")
        .unwrap()
        .build();
    assert_eq!(client.endpoint, Url("https://manual.example.com".to_owned()));
    assert_eq!(client.issuer, None);
}
