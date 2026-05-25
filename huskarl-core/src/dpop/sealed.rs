use std::sync::Arc;

/// Prevents downstream crates from implementing `DPoP` traits.
///
/// Customise `DPoP` behaviour via the `Sgn` type parameter on [`super::DPoP`]
/// and [`super::ResourceDPoP`] rather than implementing the traits directly.
pub trait Sealed {}

impl<T: Sealed> Sealed for Arc<T> {}
