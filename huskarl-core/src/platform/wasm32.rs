//! Marker traits for wasm32 platforms.
//!
//! WASM platforms are assumed to be single-threaded, so these traits do not require `Send` and `Sync` bounds.
//! When WASI gains multi-threading support, these traits will need to be updated.

/// Marker trait for types that may be `Send`, depending on platform.
pub trait MaybeSend {}
impl<T> MaybeSend for T {}

/// Marker trait for types that may be `Sync`, depending on platform.
pub trait MaybeSync {}
impl<T> MaybeSync for T {}

/// Marker trait for types that may be `Send + Sync`, depending on platform.
pub trait MaybeSendSync: MaybeSend + MaybeSync {}
impl<T> MaybeSendSync for T {}

/// Marker trait for types that may be `Send + Sync + Future`, depending on platform.
pub trait MaybeSendFuture: Future {}
impl<T: Future> MaybeSendFuture for T {}
