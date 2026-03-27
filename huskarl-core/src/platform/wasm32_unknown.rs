//! Implementations for wasm32-unknown-unknown (usually web browser).

pub use web_time::{Duration, Instant, SystemTime, SystemTimeError};

/// Sleep implementation.
pub async fn sleep(duration: Duration) {
    gloo_timers::future::sleep(duration).await;
}
