/// Verifies that `#[grant]` (Mode 2 — no `#[derive(Builder)]`) successfully
/// injects the seven common fields and two generic parameters into a struct.

mod core {
    pub mod client_auth {
        pub trait ClientAuthentication {}
    }
    pub mod dpop {
        pub trait AuthorizationServerDPoP {}
        pub struct NoDPoP;
        impl AuthorizationServerDPoP for NoDPoP {}
    }
    pub struct EndpointUrl;
}

#[huskarl_macros::grant]
struct MyGrant {
    extra_field: u32,
}

fn main() {}
