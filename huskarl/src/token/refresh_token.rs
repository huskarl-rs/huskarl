use serde::{Deserialize, Serialize};

use crate::core::secrets::SecretString;

/// An OAuth 2.0 refresh token, used to obtain new access tokens without
/// re-running the interactive flow.
///
/// May be `DPoP`-bound (RFC 9449): [`dpop_jkt`](Self::dpop_jkt) carries the
/// thumbprint of the key the refresh request must be proven with.
/// Built-in grants retain this binding for public clients independently of the
/// access token's type. Confidential clients use client authentication instead
/// and may select a new proof key when no refresh binding is stored. OIDC Key
/// Binding records the original proof key for both client types. A stored
/// thumbprint is always honored and preserved in replacement refresh tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    token: SecretString,
    #[serde(skip_serializing_if = "Option::is_none")]
    dpop_jkt: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) openid_bound_key_requested: bool,
}

impl RefreshToken {
    /// Creates a new `RefreshToken` with the given token and `DPoP` JWT thumbprint.
    ///
    /// A supplied thumbprint is always honored. To preserve an
    /// OIDC Key Binding request flag, retain the token returned by the grant
    /// or deserialize its complete saved representation instead.
    #[must_use]
    pub fn new(token: SecretString, dpop_jkt: Option<String>) -> Self {
        Self {
            token,
            dpop_jkt,
            openid_bound_key_requested: false,
        }
    }
}

impl PartialEq for RefreshToken {
    /// Equal when the secret value, `DPoP` binding and OIDC request flag match.
    ///
    /// `SecretString` has no `PartialEq` of its own (secrets are not casually
    /// comparable), so this is hand-rolled. It is a plain, **not** constant-time
    /// comparison — refresh tokens are high-entropy and are only compared
    /// against the client's own stored values, never attacker-supplied input.
    fn eq(&self, other: &Self) -> bool {
        self.token.expose_secret() == other.token.expose_secret()
            && self.dpop_jkt == other.dpop_jkt
            && self.openid_bound_key_requested == other.openid_bound_key_requested
    }
}

impl Eq for RefreshToken {}

impl RefreshToken {
    /// Returns the token as a [`SecretString`].
    #[must_use]
    pub fn token(&self) -> &SecretString {
        &self.token
    }

    /// Returns the `DPoP` JWT thumbprint, if present.
    #[must_use]
    pub fn dpop_jkt(&self) -> Option<&str> {
        self.dpop_jkt.as_deref()
    }

    /// Whether OIDC Key Binding was requested during the original authentication.
    /// Retained as protocol context independently of the stored key binding.
    /// This records the request, not confirmation that the OP bound the ID token.
    #[must_use]
    pub fn openid_bound_key_requested(&self) -> bool {
        self.openid_bound_key_requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_state_keeps_ordinary_refresh_semantics() {
        let token: RefreshToken =
            serde_json::from_str(r#"{"token":"refresh","dpop_jkt":"legacy-key"}"#).unwrap();
        assert!(!token.openid_bound_key_requested());
        assert_eq!(
            token,
            RefreshToken::new("refresh".into(), Some("legacy-key".into()))
        );
        // Ordinary tokens keep their previous serialized form.
        assert_eq!(
            serde_json::to_string(&token).unwrap(),
            r#"{"token":"refresh","dpop_jkt":"legacy-key"}"#
        );
        let mut bound = token.clone();
        bound.openid_bound_key_requested = true;
        assert_ne!(bound, token);
    }
}
