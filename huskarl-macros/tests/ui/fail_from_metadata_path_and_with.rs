//! `path` and `with` are mutually exclusive on a field.

struct Src {
    name: String,
}

#[huskarl_macros::from_metadata(metadata = crate::Src)]
#[derive(bon::Builder)]
#[builder(state_mod(name = "builder"))]
struct Foo {
    #[from_metadata(path = "name", with = |m: &crate::Src| m.name.clone())]
    name: Option<String>,
}

fn main() {}
