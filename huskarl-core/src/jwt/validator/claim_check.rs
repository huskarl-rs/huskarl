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

/// A plain string is the common, strict intent: the claim must be present and
/// equal this value ([`ClaimCheck::RequiredValue`]). This is what lets builder
/// fields accept `.aud("https://api")` directly.
impl From<&str> for ClaimCheck {
    fn from(value: &str) -> Self {
        Self::RequiredValue(value.to_owned())
    }
}

/// The claim must be present and equal this value
/// ([`ClaimCheck::RequiredValue`]); see the `From<&str>` impl.
impl From<String> for ClaimCheck {
    fn from(value: String) -> Self {
        Self::RequiredValue(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_strings_convert_to_required_value() {
        // The conversion must be the strict variant — anything laxer would
        // silently weaken validators built with bare strings.
        assert!(matches!(
            ClaimCheck::from("api://resource"),
            ClaimCheck::RequiredValue(v) if v == "api://resource"
        ));
        assert!(matches!(
            ClaimCheck::from(String::from("api://resource")),
            ClaimCheck::RequiredValue(v) if v == "api://resource"
        ));
    }
}
