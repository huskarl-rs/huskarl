//! Raw identifiers cannot be supported by the generated derived names
//! (`Set{Pascal}`, `maybe_{name}`); they must be a spanned error, not an
//! `Ident::new` panic inside the macro.

#[derive(Debug)]
struct Src {
    name: String,
}

#[huskarl_macros::from_metadata(metadata = crate::Src)]
#[derive(bon::Builder)]
#[builder(state_mod(name = "builder"))]
struct Foo {
    #[from_metadata(path = "name")]
    r#type: Option<String>,
}

fn main() {}
