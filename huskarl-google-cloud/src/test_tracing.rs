//! Test-only capture of Huskarl events and span fields.
#![allow(clippy::unwrap_used)]
use std::sync::{Arc, Mutex, OnceLock};

use tracing::{Instrument as _, instrument::WithSubscriber as _};
use tracing_subscriber::layer::SubscriberExt as _;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) async fn capture<T>(
    future: impl Future<Output = T>,
    level: tracing::Level,
) -> (T, String) {
    capture_with_api(future, level, false).await
}

pub(crate) async fn capture_with_api<T>(
    future: impl Future<Output = T>,
    level: tracing::Level,
    api: bool,
) -> (T, String) {
    // Keep a dispatcher registered between captures, including while other
    // tests first encounter callsites without an active subscriber. Returning
    // `sometimes` keeps those callsites checking the current subscriber instead
    // of caching `never` while capture subscribers are created and dropped.
    static KEEPALIVE: OnceLock<tracing::Dispatch> = OnceLock::new();
    KEEPALIVE.get_or_init(|| {
        tracing::Dispatch::new(
            tracing_subscriber::registry()
                .with(tracing_subscriber::filter::dynamic_filter_fn(|_, _| false)),
        )
    });
    let output = Capture::default();
    let writer = output.clone();
    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .without_time()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW)
        .with_writer(move || writer.clone());
    let targets = tracing_subscriber::filter::Targets::new()
        .with_target("huskarl", level)
        .with_target(
            "huskarl_google_cloud::api",
            if api {
                tracing::level_filters::LevelFilter::TRACE
            } else {
                tracing::level_filters::LevelFilter::OFF
            },
        );
    // Captures use different filters concurrently. Check the active capture on
    // every event instead of caching interest as subscribers come and go.
    let filter = tracing_subscriber::filter::dynamic_filter_fn(move |metadata, _| {
        targets.would_enable(metadata.target(), metadata.level())
    });
    let subscriber = tracing_subscriber::registry().with(filter).with(layer);
    let result = async { future.instrument(tracing::info_span!("test_request")).await }
        .with_subscriber(subscriber)
        .await;
    let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    (result, text)
}
