use std::sync::Arc;

/// Prevents downstream crates from implementing `DPoP` traits.
///
/// Customise `DPoP` behaviour via the signer given to [`super::DPoP`] /
/// [`super::ResourceDPoP`] rather than implementing the traits directly.
pub trait Sealed {}

impl<T: Sealed + ?Sized> Sealed for &T {}
impl<T: Sealed + ?Sized> Sealed for Box<T> {}
impl<T: Sealed + ?Sized> Sealed for Arc<T> {}
