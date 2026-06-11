//! Verifies that `#[try_builder]` produces a working builder for both required
//! and optional fields, surfacing the converter's error as `huskarl_core::Error`.

use bon::Builder;

#[derive(Debug, PartialEq, Eq)]
struct Url(String);

/// A minimal fallible conversion trait — proves the macro is generic over
/// the trait, not hard-coded to `IntoEndpointUrl`.
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

impl IntoUrl for Url {
    fn into_url(self) -> Result<Url, huskarl_core::Error> {
        Ok(self)
    }
}

#[huskarl_macros::try_builder]
#[derive(Builder)]
#[builder(state_mod(name = "builder"))]
struct Endpoints {
    #[try_setter(crate::IntoUrl::into_url)]
    primary: Url,

    #[try_setter(crate::IntoUrl::into_url)]
    mirror: Option<Url>,

    label: String,
}

fn main() {
    // Required + maybe-setter with a non-empty string — both succeed.
    let e = Endpoints::builder()
        .primary("https://example.com")
        .expect("primary should parse")
        .maybe_mirror(Some("https://mirror.example.com"))
        .expect("mirror should parse")
        .label("a".to_owned())
        .build();
    assert_eq!(e.primary, Url("https://example.com".to_owned()));
    assert_eq!(e.mirror, Some(Url("https://mirror.example.com".to_owned())));

    // The maybe setter accepts None and leaves the field unset.
    let e = Endpoints::builder()
        .primary(Url("direct".to_owned()))
        .expect("Url passthrough is Infallible but still typed Result")
        .maybe_mirror::<&str>(None)
        .expect("None never errors")
        .label("b".to_owned())
        .build();
    assert_eq!(e.mirror, None);

    // The required setter surfaces the converter's error.
    let err = Endpoints::builder().primary("");
    assert!(err.is_err());

    // The non-`Option` `mirror`-equivalent: also try the singular `mirror`
    // setter which sets `Some(_)`.
    let e = Endpoints::builder()
        .primary("a")
        .unwrap()
        .mirror("b")
        .unwrap()
        .label("c".to_owned())
        .build();
    assert_eq!(e.mirror, Some(Url("b".to_owned())));
}
