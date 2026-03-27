//! Marker traits for non-wasm32 platforms.
//!
//! Non-WASM platforms are assumed to be multi-threaded, so these traits require `Send` and `Sync` bounds.

/// Marker trait for types that may be `Send`, depending on platform.
pub trait MaybeSend: Send {}
impl<T: Send> MaybeSend for T {}

/// Marker trait for types that may be `Sync`, depending on platform.
pub trait MaybeSync: Sync {}
impl<T: Sync> MaybeSync for T {}

/// Marker trait for types that may be `Send + Sync`, depending on platform.
pub trait MaybeSendSync: Send + Sync {}
impl<T: Send + Sync> MaybeSendSync for T {}

/// Marker trait for Future types that may be `Send`, depending on platform.
pub trait MaybeSendFuture: Future + Send {}
impl<T: Future + Send> MaybeSendFuture for T {}
