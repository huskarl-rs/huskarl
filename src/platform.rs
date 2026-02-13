//! Platform-specific marker traits for cross-platform compatibility.
//!
//! Some traits abstract over `Send`/`Sync` requirements that differ between
//! native platforms and WASM. There are also traits for time and sleeping.

#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
pub use std::time::{Duration, Instant, SystemTime};

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
pub use web_time::{Duration, Instant, SystemTime};

#[cfg(not(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
)))]
pub async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
))]
pub async fn sleep(duration: Duration) {
    gloo_timers::future::sleep(duration).await
}

/// Marker trait for types that may be `Send`, depending on platform.
#[cfg(not(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
)))]
pub trait MaybeSend: Send {}
#[cfg(not(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
)))]
impl<T: Send> MaybeSend for T {}

/// Marker trait for types that may be `Send`, depending on platform.
#[cfg(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
))]
pub trait MaybeSend {}
#[cfg(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
))]
impl<T> MaybeSend for T {}

/// Marker trait for types that may be `Send + Sync`, depending on platform.
#[cfg(not(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
)))]
pub trait MaybeSendSync: Send + Sync {}
#[cfg(not(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
)))]
impl<T: Send + Sync> MaybeSendSync for T {}

/// Marker trait for types that may be `Send + Sync`, depending on platform.
#[cfg(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
))]
pub trait MaybeSendSync {}
#[cfg(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
))]
impl<T> MaybeSendSync for T {}

/// Marker trait for types that may be `Sync`, depending on platform.
#[cfg(not(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
)))]
pub trait MaybeSync: Sync {}
#[cfg(not(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
)))]
impl<T: Sync> MaybeSync for T {}

/// Marker trait for types that may be `Sync`, depending on platform.
#[cfg(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
))]
pub trait MaybeSync {}
#[cfg(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
))]
impl<T> MaybeSync for T {}

/// Marker trait for Future types that may be `Send`, depending on platform.
#[cfg(not(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
)))]
pub trait MaybeSendFuture: Future + Send {}
#[cfg(not(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
)))]
impl<T: Future + Send> MaybeSendFuture for T {}

/// Marker trait for Future types that may be `Send`, depending on platform.
#[cfg(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
))]
pub trait MaybeSendFuture: Future {}
#[cfg(any(
    doc,
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
))]
impl<T: Future> MaybeSendFuture for T {}
