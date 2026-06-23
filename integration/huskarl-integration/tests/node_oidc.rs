//! Integration flows against a local node-oidc-provider.

use huskarl_integration::{ProviderFuture, provider_trials};
use huskarl_testkit::{NodeOidcProvider, TestProvider};

fn ctor() -> ProviderFuture {
    Box::pin(async { Ok(Box::new(NodeOidcProvider::local().await?) as Box<dyn TestProvider>) })
}

fn main() {
    let args = libtest_mimic::Arguments::from_args();
    let trials = provider_trials(
        NodeOidcProvider::FEATURES,
        cfg!(feature = "node-oidc"),
        ctor,
    );
    libtest_mimic::run(&args, trials).exit();
}
