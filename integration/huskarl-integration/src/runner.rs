//! Turns [`FLOWS`] into a `libtest-mimic` suite for one provider, emitting
//! one [`Trial`] per variant.

use std::{any::Any, future::Future, panic::AssertUnwindSafe, pin::Pin};

use huskarl_testkit::{Error, Features, TestProvider};
use libtest_mimic::{Failed, Trial};

use crate::flows::{FLOWS, FlowBody};

pub type ProviderFuture =
    Pin<Box<dyn Future<Output = Result<Box<dyn TestProvider>, Error>> + Send>>;

pub type ProviderCtor = fn() -> ProviderFuture;

/// Builds one [`Trial`] per flow variant.
///
/// `feature_enabled` (pass `cfg!(feature = "<provider>")`) and feature support
/// gate each variant; unsupported ones are marked `ignored` rather than passing.
pub fn provider_trials(
    supported: Features,
    feature_enabled: bool,
    ctor: ProviderCtor,
) -> Vec<Trial> {
    let mut trials = Vec::new();
    for flow in FLOWS {
        for variant in flow.variants {
            let test_name = format!("{}::{}", flow.name, variant.name);
            let body = flow.body;
            let required = variant.required;
            let runnable = feature_enabled && supported.contains(required);
            trials.push(
                Trial::test(test_name, move || run_variant(ctor, body, required))
                    .with_ignored_flag(!runnable),
            );
        }
    }
    trials
}

/// Runs one variant: build a runtime, construct the provider, drive the body.
///
/// Catches the flow body's panic so the failure can be attributed to the
/// provider via [`TestProvider::name`].
fn run_variant(ctor: ProviderCtor, body: FlowBody, required: Features) -> Result<(), Failed> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Failed::from(format!("build tokio runtime: {e}")))?;

    let provider = runtime
        .block_on(ctor())
        .map_err(|e| Failed::from(format!("create provider: {e}")))?;
    let name = provider.name().to_owned();

    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(body(&*provider, required))
    }));

    // Teardown on both paths while the runtime is alive; non-fatal.
    if let Err(e) = runtime.block_on(provider.teardown()) {
        eprintln!("huskarl-testkit: teardown failed for {name}: {e}");
    }

    match outcome {
        Ok(()) => Ok(()),
        Err(panic) => Err(Failed::from(format!("[{name}] {}", panic_message(panic)))),
    }
}

/// Extracts the message from a caught panic payload (`&str` or `String`).
fn panic_message(panic: Box<dyn Any + Send>) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "flow panicked (non-string payload)".to_owned()
    }
}
