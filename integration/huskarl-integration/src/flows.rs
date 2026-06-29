//! The canonical flow list, as data. Single source of truth for both the
//! per-provider suite ([`crate::runner`]) and the coverage grid ([`crate::matrix`]).

use std::{future::Future, pin::Pin};

use huskarl_testkit::{Features, TestProvider};

use crate::suite;

/// Not `Send`: the mTLS flow holds a non-`Send` closure across an await, and the
/// runner drives each flow on a single-threaded `block_on`.
pub type BoxFuture<'a> = Pin<Box<dyn Future<Output = ()> + 'a>>;

pub type FlowBody = for<'a> fn(&'a dyn TestProvider, Features) -> BoxFuture<'a>;

/// One runnable variant of a [`Flow`], under a specific required feature set.
pub struct Variant {
    pub name: &'static str,
    pub required: Features,
}

/// A flow and its variants; all share one [`FlowBody`].
pub struct Flow {
    pub name: &'static str,
    pub body: FlowBody,
    pub variants: &'static [Variant],
}

// Box each `async fn` body into a [`FlowBody`] fn pointer.
fn client_credentials(p: &dyn TestProvider, f: Features) -> BoxFuture<'_> {
    Box::pin(suite::client_credentials_flow(p, f))
}
fn refresh(p: &dyn TestProvider, f: Features) -> BoxFuture<'_> {
    Box::pin(suite::refresh_flow(p, f))
}
fn wrong_audience(p: &dyn TestProvider, f: Features) -> BoxFuture<'_> {
    Box::pin(suite::wrong_audience_flow(p, f))
}
fn introspection(p: &dyn TestProvider, f: Features) -> BoxFuture<'_> {
    Box::pin(suite::introspection_flow(p, f))
}
fn mtls(p: &dyn TestProvider, f: Features) -> BoxFuture<'_> {
    Box::pin(suite::mtls_flow(p, f))
}
fn auth_code(p: &dyn TestProvider, f: Features) -> BoxFuture<'_> {
    Box::pin(suite::auth_code_flow(p, f))
}

pub const FLOWS: &[Flow] = &[
    Flow {
        name: "client_credentials",
        body: client_credentials,
        variants: &[
            Variant {
                name: "plain",
                required: Features::CLIENT_CREDENTIALS,
            },
            Variant {
                name: "dpop",
                required: Features::CLIENT_CREDENTIALS.union(Features::DPOP),
            },
            Variant {
                name: "private_key_jwt",
                required: Features::CLIENT_CREDENTIALS.union(Features::PRIVATE_KEY_JWT),
            },
        ],
    },
    Flow {
        name: "refresh",
        body: refresh,
        variants: &[Variant {
            name: "plain",
            required: Features::CLIENT_CREDENTIALS.union(Features::REFRESH),
        }],
    },
    Flow {
        name: "rejection",
        body: wrong_audience,
        variants: &[Variant {
            name: "wrong_audience",
            required: Features::CLIENT_CREDENTIALS,
        }],
    },
    Flow {
        name: "introspection",
        body: introspection,
        variants: &[Variant {
            name: "plain",
            required: Features::CLIENT_CREDENTIALS.union(Features::INTROSPECTION),
        }],
    },
    Flow {
        name: "mtls",
        body: mtls,
        variants: &[Variant {
            name: "plain",
            required: Features::CLIENT_CREDENTIALS.union(Features::MTLS),
        }],
    },
    Flow {
        name: "auth_code",
        body: auth_code,
        variants: &[
            Variant {
                name: "direct",
                required: Features::AUTH_CODE,
            },
            Variant {
                name: "par",
                required: Features::AUTH_CODE.union(Features::PAR),
            },
            Variant {
                name: "jar",
                required: Features::AUTH_CODE.union(Features::JAR),
            },
        ],
    },
];
