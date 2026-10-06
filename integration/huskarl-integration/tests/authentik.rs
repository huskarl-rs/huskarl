//! Integration flows against a local Authentik.

use huskarl_integration::{ProviderFuture, provider_trials};
use huskarl_testkit::{AuthentikProvider, TestProvider};

fn ctor() -> ProviderFuture {
    Box::pin(async { Ok(Box::new(AuthentikProvider::local().await?) as Box<dyn TestProvider>) })
}

fn main() {
    let args = libtest_mimic::Arguments::from_args();
    let trials = provider_trials(
        AuthentikProvider::FEATURES,
        cfg!(feature = "authentik"),
        ctor,
    );
    libtest_mimic::run(&args, trials).exit();
}
