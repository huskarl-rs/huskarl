//! `maybe` only applies to `with`; combining it with `path` must be rejected
//! (Option segments are spelled with `?` instead).

struct Src {
    name: Option<String>,
}

#[huskarl_macros::from_metadata(metadata = crate::Src)]
#[derive(bon::Builder)]
#[builder(state_mod(name = "builder"))]
struct Foo {
    #[from_metadata(path = "name?", maybe)]
    name: Option<String>,
}

fn main() {}
