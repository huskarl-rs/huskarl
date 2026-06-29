//! Integration flows against a hosted Okta tenant.

use huskarl_integration::{ProviderFuture, provider_trials};
use huskarl_testkit::{OktaProvider, TestProvider};

fn ctor() -> ProviderFuture {
    Box::pin(async { Ok(Box::new(OktaProvider::local().await?) as Box<dyn TestProvider>) })
}

fn main() {
    let args = libtest_mimic::Arguments::from_args();
    // Okta is hosted: gate on a configured tenant (OKTA_DOMAIN), not a running server.
    let configured = cfg!(feature = "okta") && std::env::var_os("OKTA_DOMAIN").is_some();
    let trials = provider_trials(OktaProvider::FEATURES, configured, ctor);
    libtest_mimic::run(&args, trials).exit();
}
