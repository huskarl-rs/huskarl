/// Verifies that `#[grant]` rejects a tuple struct with a clear error message.

#[huskarl_macros::grant]
struct MyGrant(String);

fn main() {}
