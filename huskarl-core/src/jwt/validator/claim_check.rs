//! The [`ClaimCheck`] policy applied to individual JWT claims.

/// A check to perform on a JWT claim.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub enum ClaimCheck {
    /// If claim is present, it must equal this value. Lack of value is acceptable.
    IfPresent(String),
    /// Claim must be present, value must match one of these.
    RequireAny(Vec<String>),
    /// Claim must be present and equal this value.
    RequiredValue(String),
    /// Claim must be present.
    Present,
    /// No check is performed.
    #[default]
    NoCheck,
}

impl ClaimCheck {
    /// If claim is present, it must equal this value. Lack of value is acceptable.
    pub fn if_present(value: impl Into<String>) -> Self {
        Self::IfPresent(value.into())
    }

    /// Claim must be present, and value must match one of these.
    pub fn require_any(values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::RequireAny(values.into_iter().map(Into::into).collect())
    }

    /// Claim must be present and equal this value.
    pub fn required_value(value: impl Into<String>) -> Self {
        Self::RequiredValue(value.into())
    }

    /// Claim must be present.
    #[must_use]
    pub fn present() -> Self {
        Self::Present
    }
}
