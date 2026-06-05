//! Regression: the generated setters use prefixed generic parameters, so a
//! user struct whose own generics are named `S` and `U` must still compile.

use bon::Builder;

#[derive(Debug, PartialEq, Eq)]
struct Url(String);

trait IntoUrl {
    type Error;
    fn into_url(self) -> Result<Url, Self::Error>;
}

impl IntoUrl for &str {
    type Error = std::convert::Infallible;
    fn into_url(self) -> Result<Url, Self::Error> {
        Ok(Url(self.to_owned()))
    }
}

#[huskarl_macros::try_builder]
#[derive(Builder)]
#[builder(state_mod(name = "builder"))]
struct Wrapper<S: Clone + Default, U: Clone + Default> {
    #[try_setter(crate::IntoUrl::into_url)]
    primary: Url,

    #[try_setter(crate::IntoUrl::into_url)]
    mirror: Option<Url>,

    #[builder(default)]
    s_value: S,
    #[builder(default)]
    u_value: U,
}

fn main() {
    let w = Wrapper::<u32, String>::builder()
        .primary("https://example.com")
        .unwrap()
        .maybe_mirror(Some("https://mirror.example.com"))
        .unwrap()
        .build();
    assert_eq!(w.primary, Url("https://example.com".to_owned()));
    assert_eq!(w.s_value, 0);
    assert_eq!(w.u_value, "");
}
