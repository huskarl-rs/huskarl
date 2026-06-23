//! Integration flows against a local Dex.

use huskarl_integration::{ProviderFuture, provider_trials};
use huskarl_testkit::{DexProvider, TestProvider};

fn ctor() -> ProviderFuture {
    Box::pin(async { Ok(Box::new(DexProvider::local().await?) as Box<dyn TestProvider>) })
}

fn main() {
    let args = libtest_mimic::Arguments::from_args();
    let trials = provider_trials(DexProvider::FEATURES, cfg!(feature = "dex"), ctor);
    libtest_mimic::run(&args, trials).exit();
}
