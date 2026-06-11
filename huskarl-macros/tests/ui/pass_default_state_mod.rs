//! Verifies that both macros work when the user omits
//! `#[builder(state_mod(name = "…"))]` — they fall back to bon's default,
//! which is snake_case of the builder type name (`{Struct}Builder` →
//! `{struct}_builder`).

#[derive(Debug, PartialEq, Eq)]
struct Url(String);

trait IntoUrl {
    fn into_url(self) -> Result<Url, huskarl_core::Error>;
}

impl IntoUrl for &str {
    fn into_url(self) -> Result<Url, huskarl_core::Error> {
        if self.is_empty() {
            Err(huskarl_core::ErrorKind::Config.into())
        } else {
            Ok(Url(self.to_owned()))
        }
    }
}

mod with_try_builder {
    use super::Url;

    /// No `state_mod(name = "…")` — macro falls back to `widget_builder`.
    #[huskarl_macros::try_builder]
    #[derive(bon::Builder)]
    pub struct Widget {
        #[try_setter(crate::IntoUrl::into_url)]
        pub url: Url,
    }
}

#[derive(Debug)]
struct Src {
    name: String,
}

mod with_from_metadata {
    /// No `state_mod(name = "…")` — macro falls back to `record_builder`.
    #[huskarl_macros::from_metadata(metadata = crate::Src)]
    #[derive(bon::Builder)]
    pub struct Record {
        #[from_metadata(path = "name")]
        pub name: Option<String>,
    }
}

fn main() {
    let w = with_try_builder::Widget::builder()
        .url("https://example.com")
        .expect("parses")
        .build();
    assert_eq!(w.url, Url("https://example.com".to_owned()));

    let src = Src {
        name: "abc".to_owned(),
    };
    let r = with_from_metadata::Record::builder_from_metadata(&src).build();
    assert_eq!(r.name.as_deref(), Some("abc"));
}
