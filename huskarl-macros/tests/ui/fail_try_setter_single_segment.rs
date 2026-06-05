//! Verifies that `#[try_setter(only_one_segment)]` is rejected with a clear
//! error pointing at the `Trait::method` requirement.

#[huskarl_macros::try_builder]
#[derive(bon::Builder)]
#[builder(state_mod(name = "builder"))]
struct Foo {
    #[try_setter(into_url)]
    bar: String,
}

fn main() {}
