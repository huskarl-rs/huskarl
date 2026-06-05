//! `method(name = "…")` must be a valid identifier — an invalid one is a
//! spanned error, not a proc-macro panic.

struct Src {
    name: String,
}

#[huskarl_macros::from_metadata(metadata = crate::Src, method(name = "not an ident"))]
#[derive(bon::Builder)]
#[builder(state_mod(name = "builder"))]
struct Foo {
    #[from_metadata(path = "name")]
    name: Option<String>,
}

fn main() {}
