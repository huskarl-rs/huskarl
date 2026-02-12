//! Platform-specific marker traits for cross-platform compatibility.
//!
//! Some traits abstract over `Send`/`Sync` requirements that differ between
//! native platforms and WASM. There are also traits for time and sleeping.

#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
pub use std::time::{Duration, Instant, SystemTime};

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
pub use web_time::{Duration, Instant, SystemTime};

#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
pub async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
pub async fn sleep(duration: Duration) {
    gloo_timers::future::sleep(duration).await
}

/// Marker trait for types that may be `Send`, depending on platform.
#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
pub trait MaybeSend: Send {}
#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
impl<T: Send> MaybeSend for T {}

/// Marker trait for types that may be `Send`, depending on platform.
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
pub trait MaybeSend {}
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
impl<T> MaybeSend for T {}

/// Marker trait for types that may be `Send + Sync`, depending on platform.
#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
pub trait MaybeSendSync: Send + Sync {}
#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
impl<T: Send + Sync> MaybeSendSync for T {}

/// Marker trait for types that may be `Send + Sync`, depending on platform.
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
pub trait MaybeSendSync {}
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
impl<T> MaybeSendSync for T {}

/// Marker trait for types that may be `Sync`, depending on platform.
#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
pub trait MaybeSync: Sync {}
#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
impl<T: Sync> MaybeSync for T {}

/// Marker trait for types that may be `Sync`, depending on platform.
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
pub trait MaybeSync {}
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
impl<T> MaybeSync for T {}

/// Marker trait for Future types that may be `Send`, depending on platform.
#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
pub trait MaybeSendFuture: Future + Send {}
#[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
impl<T: Future + Send> MaybeSendFuture for T {}

/// Marker trait for Future types that may be `Send`, depending on platform.
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
pub trait MaybeSendFuture: Future {}
#[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
impl<T: Future> MaybeSendFuture for T {}
