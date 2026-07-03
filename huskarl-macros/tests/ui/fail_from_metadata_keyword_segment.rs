//! A path segment that is a Rust keyword must be a spanned macro error: the
//! generated `metadata.type` field access would otherwise fail to compile
//! with a diagnostic pointing at generated code (and `_` would panic
//! `Ident::new` inside the macro).

#[derive(Debug)]
struct Src {
    name: String,
}

#[huskarl_macros::from_metadata(metadata = crate::Src)]
#[derive(bon::Builder)]
#[builder(state_mod(name = "builder"))]
struct Foo {
    #[from_metadata(path = "type")]
    token_type: Option<String>,
}

#[huskarl_macros::from_metadata(metadata = crate::Src)]
#[derive(bon::Builder)]
#[builder(state_mod(name = "builder2"))]
struct Bar {
    #[from_metadata(path = "outer?.self")]
    inner: Option<String>,
}

fn main() {}
