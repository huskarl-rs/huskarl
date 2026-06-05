//! Verifies that darling's span-preserving error reporting points at the
//! mistyped key rather than at the macro invocation site.

#[derive(Debug)]
struct Src {
    name: String,
}

#[huskarl_macros::from_metadata(metdata = crate::Src)]
#[derive(bon::Builder)]
#[builder(state_mod(name = "builder"))]
struct Foo {
    #[from_metadata(path = "name")]
    name: Option<String>,
}

fn main() {}
