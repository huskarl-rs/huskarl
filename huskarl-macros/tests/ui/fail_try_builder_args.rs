//! `#[try_builder]` takes no arguments; passing any must be rejected rather
//! than silently ignored. The struct itself must survive the error.

#[huskarl_macros::try_builder(unexpected)]
#[derive(bon::Builder)]
#[builder(state_mod(name = "builder"))]
struct Foo {
    bar: String,
}

fn main() {
    let _ = Foo::builder().bar("x".to_owned()).build();
}
