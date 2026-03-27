//! Implementations for platforms other than wasm32-unknown-unknown (usually web browser).

pub use std::time::{Duration, Instant, SystemTime, SystemTimeError};

/// Sleep implementation.
pub async fn sleep(duration: super::Duration) {
    tokio::time::sleep(duration).await;
}
