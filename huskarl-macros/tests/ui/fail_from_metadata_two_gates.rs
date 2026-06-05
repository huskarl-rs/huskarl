//! At most one gating field (required target drawing from an Option source)
//! is supported.

struct Src {
    a: Option<String>,
    b: Option<String>,
}

#[huskarl_macros::from_metadata(metadata = crate::Src)]
#[derive(bon::Builder)]
#[builder(state_mod(name = "builder"))]
struct Foo {
    #[from_metadata(path = "a?")]
    a: String,
    #[from_metadata(path = "b?")]
    b: String,
}

fn main() {}
