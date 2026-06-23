//! Integration flows against a real Keycloak.

use huskarl_integration::{ProviderFuture, provider_trials};
use huskarl_testkit::{KeycloakProvider, TestProvider};

fn ctor() -> ProviderFuture {
    Box::pin(async { Ok(Box::new(KeycloakProvider::local().await?) as Box<dyn TestProvider>) })
}

fn main() {
    let args = libtest_mimic::Arguments::from_args();
    let trials = provider_trials(KeycloakProvider::FEATURES, cfg!(feature = "keycloak"), ctor);
    libtest_mimic::run(&args, trials).exit();
}
