//! A macro error must not erase the annotated type: the only diagnostic
//! should be the macro's own — no "cannot find type `Foo`" cascade at the
//! use sites below.

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

fn takes_foo(f: Foo) -> Foo {
    f
}

fn main() {
    let f = Foo::builder().name("x".to_owned()).build();
    let _ = takes_foo(f);
}
