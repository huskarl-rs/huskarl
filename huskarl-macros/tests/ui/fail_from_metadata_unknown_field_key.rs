//! Unknown keys in the per-field attribute are rejected with a spanned error.

struct Src {
    name: String,
}

#[huskarl_macros::from_metadata(metadata = crate::Src)]
#[derive(bon::Builder)]
#[builder(state_mod(name = "builder"))]
struct Foo {
    #[from_metadata(pathh = "name")]
    name: Option<String>,
}

fn main() {}
