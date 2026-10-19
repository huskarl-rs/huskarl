//! Test-only capture of Huskarl events and span fields.
#![allow(clippy::unwrap_used)]
use std::sync::{Arc, Mutex};

use tracing::{Instrument as _, instrument::WithSubscriber as _};
use tracing_subscriber::{Layer as _, layer::SubscriberExt as _};

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
    let output = Capture::default();
    let writer = output.clone();
    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .without_time()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW)
        .with_writer(move || writer.clone())
        .with_filter(tracing_subscriber::filter::Targets::new().with_target("huskarl", level));
    let subscriber = tracing_subscriber::registry().with(layer);
    let result = async { future.instrument(tracing::info_span!("test_request")).await }
        .with_subscriber(subscriber)
        .await;
    let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    (result, text)
}
