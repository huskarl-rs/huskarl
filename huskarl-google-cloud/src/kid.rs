//! Deriving a JWS/JWE `kid` from a key or secret version.
//!
//! [`VersionKid`] defines a common policy for version-derived key IDs across
//! the crate. Both Cloud KMS keys and Secret Manager sources accept one, so the
//! same three choices — no `kid`, the version verbatim, or a transformed
//! version — are expressed consistently.
//!
//! Only the *default* differs between the two backends, reflecting their
//! conventions: KMS keys default to
//! [`VersionKid::none()`] (a bare KMS version number is rarely a useful `kid`),
//! while Secret Manager sources default to [`VersionKid::verbatim()`] (the
//! secret version is a natural, stable `kid` for rotation).
//!
//! For why the `kid` matters and how it drives multi-key selection, see [key
//! IDs](crate::_docs::explanation::key_ids).

use std::sync::Arc;

type MapFn = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// A policy for deriving a JWS/JWE `kid` from a resource's version identifier —
/// the trailing segment of a Cloud KMS crypto key version resource name or a
/// Secret Manager secret version resource name (for example, `"3"`).
///
/// Construct one with [`none`](Self::none), [`verbatim`](Self::verbatim), or
/// [`map`](Self::map):
///
/// ```rust
/// use huskarl_google_cloud::kid::VersionKid;
///
/// let no_kid = VersionKid::none();
/// let version_as_kid = VersionKid::verbatim();
/// let prefixed = VersionKid::map(|version| format!("my-key-v{version}"));
/// ```
#[derive(Clone)]
pub struct VersionKid(Repr);

#[derive(Clone)]
enum Repr {
    None,
    Verbatim,
    Map(MapFn),
}

impl VersionKid {
    /// Derives no `kid`; keys carry no key ID unless one is supplied another
    /// way, such as an explicit `kid` on a JWK.
    #[must_use]
    pub fn none() -> Self {
        Self(Repr::None)
    }

    /// Uses the version identifier verbatim as the `kid` (for example, version
    /// `"3"` becomes `kid` `"3"`).
    #[must_use]
    pub fn verbatim() -> Self {
        Self(Repr::Verbatim)
    }

    /// Derives the `kid` by transforming the version identifier, for example:
    /// `VersionKid::map(|version| format!("my-key-v{version}"))`.
    #[must_use]
    pub fn map(f: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        Self(Repr::Map(Arc::new(f)))
    }

    /// Applies this policy to `version_id` and returns the derived `kid`.
    pub(crate) fn derive(&self, version_id: &str) -> Option<String> {
        match &self.0 {
            Repr::None => None,
            Repr::Verbatim => Some(version_id.to_owned()),
            Repr::Map(f) => Some(f(version_id)),
        }
    }
}

impl std::fmt::Debug for VersionKid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant = match &self.0 {
            Repr::None => "None",
            Repr::Verbatim => "Verbatim",
            Repr::Map(_) => "Map(..)",
        };
        f.debug_tuple("VersionKid")
            .field(&format_args!("{variant}"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_derives_nothing() {
        assert_eq!(VersionKid::none().derive("3"), None);
    }

    #[test]
    fn verbatim_uses_the_version_id() {
        assert_eq!(VersionKid::verbatim().derive("3").as_deref(), Some("3"));
    }

    #[test]
    fn map_transforms_the_version_id() {
        let policy = VersionKid::map(|v| format!("k-{v}"));
        assert_eq!(policy.derive("3").as_deref(), Some("k-3"));
    }
}
