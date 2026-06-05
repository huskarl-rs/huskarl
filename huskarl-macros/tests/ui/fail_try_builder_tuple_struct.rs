//! `#[try_builder]` requires named fields.

#[huskarl_macros::try_builder]
#[derive(bon::Builder)]
struct Foo(String);

fn main() {}
