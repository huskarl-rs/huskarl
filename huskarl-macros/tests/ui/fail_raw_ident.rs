//! Raw identifiers cannot be supported by the generated derived names
//! (`Set{Pascal}`, `{name}_internal`); they must be a spanned error, not an
//! `Ident::new` panic inside the macro.

#[derive(Debug)]
struct Url(String);

trait IntoUrl {
    type Error;
    fn into_url(self) -> Result<Url, Self::Error>;
}

#[huskarl_macros::try_builder]
#[derive(bon::Builder)]
#[builder(state_mod(name = "builder"))]
struct Foo {
    #[try_setter(crate::IntoUrl::into_url)]
    r#type: Url,
}

fn main() {}
