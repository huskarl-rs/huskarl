//! Platform-specific marker traits for cross-platform compatibility.
//!
//! Some traits abstract over `Send`/`Sync` requirements that differ between
//! native platforms and WASM. There are also traits for time and sleeping.

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod wasm32_unknown;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod not_wasm32_unknown;

#[cfg(target_arch = "wasm32")]
mod wasm32;

#[cfg(not(target_arch = "wasm32"))]
mod not_wasm32;

#[cfg(not(target_arch = "wasm32"))]
pub use not_wasm32::{MaybeSend, MaybeSendFuture, MaybeSendSync, MaybeSync};
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use not_wasm32_unknown::{Duration, Instant, SystemTime, SystemTimeError, sleep};
#[cfg(target_arch = "wasm32")]
pub use wasm32::{MaybeSend, MaybeSendFuture, MaybeSendSync, MaybeSync};
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use wasm32_unknown::{Duration, Instant, SystemTime, SystemTimeError, sleep};
