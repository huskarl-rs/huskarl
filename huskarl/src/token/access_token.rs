use http::{HeaderValue, header::InvalidHeaderValue};

use crate::core::{
    platform::{Duration, SystemTime},
    secrets::SecretString,
};

/// Computes `received_at + expires_in - expires_margin` without panicking:
/// `expires_in` comes from the token response, so a malicious or buggy server
/// could supply a value that overflows `SystemTime`. Overflow clamps to a
/// century past `received_at` (effectively never stale); underflow past the
/// epoch clamps to the epoch (already stale).
fn effective_expiry(
    received_at: SystemTime,
    expires_in: Duration,
    expires_margin: Duration,
) -> SystemTime {
    const CENTURY: Duration = Duration::from_hours(100 * 365 * 24);

    received_at
        .checked_add(expires_in)
        .or_else(|| received_at.checked_add(CENTURY))
        .unwrap_or(received_at)
        .checked_sub(expires_margin)
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// An access token returned by a token grant, used to authorize resource-server
/// requests.
///
/// Get the `Authorization` header value with
/// [`expose_header_value`](Self::expose_header_value) — the
/// [`HttpAuthorizer`](crate::authorizer::HttpAuthorizer) does this for you. The
/// variant determines how the token is presented: a [`Bearer`](Self::Bearer)
/// token authorizes by possession alone, while a [`Dpop`](Self::Dpop) token is
/// sender-constrained (RFC 9449) — each request must carry a `DPoP` proof over
/// the bound key, whose thumbprint is the token's [`dpop_jkt`](Self::dpop_jkt).
#[derive(Debug, Clone)]
pub enum AccessToken {
    /// A `DPoP` token.
    Dpop(DpopAccessToken),
    /// A `Bearer` token.
    Bearer(BearerAccessToken),
    /// Not an access token (RFC 8693 `token_type` `N_A`): the security token
    /// issued by a token exchange whose `requested_token_type` was something
    /// other than an access token (an ID token, SAML assertion, or JWT). It
    /// cannot authorize resource-server requests — read it via
    /// [`token`](Self::token) and use it in its own protocol context.
    NotAccessToken(NonAccessToken),
}

impl AccessToken {
    /// Exposes the token as a [`SecretString`].
    #[must_use]
    pub fn token(&self) -> &SecretString {
        match self {
            AccessToken::Dpop(token) => &token.token,
            AccessToken::Bearer(token) => &token.token,
            AccessToken::NotAccessToken(token) => &token.token,
        }
    }

    /// Exposes the token as a [`HeaderValue`], suitable for use in an `Authorization` header.
    ///
    /// # Errors
    ///
    /// Returns an [`InvalidHeaderValue`] if the token cannot be represented as
    /// a valid header value — always, for a
    /// [`NotAccessToken`](Self::NotAccessToken), which must never be presented
    /// as an `Authorization` credential (RFC 8693 §2.2.1).
    pub fn expose_header_value(&self) -> Result<HeaderValue, InvalidHeaderValue> {
        match self {
            AccessToken::Dpop(dpop_access_token) => dpop_access_token.expose_header_value(),
            AccessToken::Bearer(bearer_access_token) => bearer_access_token.expose_header_value(),
            // Deterministically manufacture an InvalidHeaderValue (the type
            // has no public constructor): an N_A token has no header form,
            // and a control character is never a valid header value.
            AccessToken::NotAccessToken(_) => HeaderValue::from_str("\n")
                .map(|_| unreachable!("a control character is never a valid header value")),
        }
    }

    /// Returns the `DPoP` JWT thumbprint, if the token is a `DPoP` token.
    #[must_use]
    pub fn dpop_jkt(&self) -> Option<&str> {
        match self {
            AccessToken::Dpop(token) => Some(token.jkt.as_str()),
            AccessToken::Bearer(_) | AccessToken::NotAccessToken(_) => None,
        }
    }

    /// Returns the token type: `"DPoP"`, `"Bearer"`, or `"N_A"`.
    #[must_use]
    pub fn token_type(&self) -> &str {
        match self {
            AccessToken::Dpop(_) => "DPoP",
            AccessToken::Bearer(_) => "Bearer",
            AccessToken::NotAccessToken(_) => "N_A",
        }
    }

    /// The time after which this token should be treated as stale:
    /// `received_at + expires_in - expires_margin`. It is valid while
    /// `SystemTime::now()` is earlier than this.
    ///
    /// `default_expires_in` applies only when the token response carried no
    /// `expires_in` of its own; `expires_margin` is subtracted to retire the
    /// token slightly early. An out-of-range `expires_in` is clamped rather than
    /// panicking.
    #[must_use]
    pub fn effective_expiry(
        &self,
        default_expires_in: Duration,
        expires_margin: Duration,
    ) -> SystemTime {
        match self {
            AccessToken::Dpop(dpop_access_token) => {
                dpop_access_token.effective_expiry(default_expires_in, expires_margin)
            }
            AccessToken::Bearer(bearer_access_token) => {
                bearer_access_token.effective_expiry(default_expires_in, expires_margin)
            }
            AccessToken::NotAccessToken(token) => {
                token.effective_expiry(default_expires_in, expires_margin)
            }
        }
    }

    /// Returns `true` if the underlying access token has expired.
    #[must_use]
    pub fn is_expired(&self, default_expires_in: Duration, expires_margin: Duration) -> bool {
        SystemTime::now() >= self.effective_expiry(default_expires_in, expires_margin)
    }

    /// The token's effective lifetime: the `expires_in` from the token response,
    /// or `default_expires_in` when the response carried none. This is the full
    /// validity span before any `expires_margin` is applied.
    #[must_use]
    pub fn effective_lifetime(&self, default_expires_in: Duration) -> Duration {
        match self {
            AccessToken::Dpop(dpop_access_token) => {
                dpop_access_token.effective_lifetime(default_expires_in)
            }
            AccessToken::Bearer(bearer_access_token) => {
                bearer_access_token.effective_lifetime(default_expires_in)
            }
            AccessToken::NotAccessToken(token) => token.effective_lifetime(default_expires_in),
        }
    }
}

/// The security token from an RFC 8693 token-exchange response with
/// `token_type` `N_A` — issued in the `access_token` field but *not* an access
/// token (an ID token, SAML assertion, or JWT, per the response's
/// `issued_token_type`). Deliberately has no `Authorization`-header form.
#[derive(Debug, Clone)]
pub struct NonAccessToken {
    /// The issued security token.
    token: SecretString,
    /// The time at which the token was received.
    received_at: SystemTime,
    /// The duration for which the token is valid.
    expires_in: Option<Duration>,
}

impl NonAccessToken {
    /// Creates a new [`NonAccessToken`] with the given token, received time,
    /// and expiration duration.
    #[must_use]
    pub fn new(token: SecretString, received_at: SystemTime, expires_in: Option<Duration>) -> Self {
        Self {
            token,
            received_at,
            expires_in,
        }
    }

    /// Exposes the token as a [`str`].
    #[must_use]
    pub fn expose_token(&self) -> &str {
        self.token.expose_secret()
    }

    /// The token's effective expiry; see
    /// [`AccessToken::effective_expiry`] for the parameter semantics.
    #[must_use]
    pub fn effective_expiry(
        &self,
        default_expires_in: Duration,
        expires_margin: Duration,
    ) -> SystemTime {
        let expires_in = self.expires_in.unwrap_or(default_expires_in);
        effective_expiry(self.received_at, expires_in, expires_margin)
    }

    /// Returns `true` if the underlying token has expired.
    #[must_use]
    pub fn is_expired(&self, default_expires_in: Duration, expires_margin: Duration) -> bool {
        SystemTime::now() >= self.effective_expiry(default_expires_in, expires_margin)
    }

    /// The token's effective lifetime; see
    /// [`AccessToken::effective_lifetime`].
    #[must_use]
    pub fn effective_lifetime(&self, default_expires_in: Duration) -> Duration {
        self.expires_in.unwrap_or(default_expires_in)
    }
}

/// An access token, with the `DPoP` token type.
#[derive(Debug, Clone)]
pub struct DpopAccessToken {
    /// The `DPoP` access token.
    token: SecretString,
    /// The `DPoP` JWT thumbprint.
    jkt: String,
    /// The time at which the token was received.
    received_at: SystemTime,
    /// The duration for which the token is valid.
    expires_in: Option<Duration>,
}

impl DpopAccessToken {
    /// Creates a new [`DpopAccessToken`] with the given token, JWT thumbprint, received time, and expiration duration.
    #[must_use]
    pub fn new(
        token: SecretString,
        jkt: String,
        received_at: SystemTime,
        expires_in: Option<Duration>,
    ) -> Self {
        Self {
            token,
            jkt,
            received_at,
            expires_in,
        }
    }

    /// Returns a reference to the `DPoP` JWT thumbprint.
    #[must_use]
    pub fn jkt(&self) -> &str {
        &self.jkt
    }

    /// Returns the token as a [`SecretString`].
    #[must_use]
    pub fn token(&self) -> &SecretString {
        &self.token
    }

    /// Exposes the token as a [`HeaderValue`], suitable for use in an `Authorization` header.
    ///
    /// # Errors
    ///
    /// Returns an [`InvalidHeaderValue`] if the token cannot be represented as a valid header value.
    pub fn expose_header_value(&self) -> Result<HeaderValue, InvalidHeaderValue> {
        HeaderValue::from_str(&format!("DPoP {}", self.token.expose_secret()))
    }

    /// The token's effective expiry; see
    /// [`AccessToken::effective_expiry`] for the parameter semantics.
    #[must_use]
    pub fn effective_expiry(
        &self,
        default_expires_in: Duration,
        expires_margin: Duration,
    ) -> SystemTime {
        let expires_in = self.expires_in.unwrap_or(default_expires_in);
        effective_expiry(self.received_at, expires_in, expires_margin)
    }

    /// Returns `true` if the underlying access token has expired.
    #[must_use]
    pub fn is_expired(&self, default_expires_in: Duration, expires_margin: Duration) -> bool {
        SystemTime::now() >= self.effective_expiry(default_expires_in, expires_margin)
    }

    /// The token's effective lifetime; see
    /// [`AccessToken::effective_lifetime`].
    #[must_use]
    pub fn effective_lifetime(&self, default_expires_in: Duration) -> Duration {
        self.expires_in.unwrap_or(default_expires_in)
    }
}

/// A bearer access token, as used in the `Authorization: Bearer` header.
#[derive(Debug, Clone)]
pub struct BearerAccessToken {
    /// The `Bearer` access token.
    token: SecretString,
    /// The time at which the token was received.
    received_at: SystemTime,
    /// The duration for which the token is valid.
    expires_in: Option<Duration>,
}

impl BearerAccessToken {
    /// Creates a new [`BearerAccessToken`] with the given token, received time, and expiration duration.
    #[must_use]
    pub fn new(token: SecretString, received_at: SystemTime, expires_in: Option<Duration>) -> Self {
        Self {
            token,
            received_at,
            expires_in,
        }
    }

    /// Exposes the token as a [`str`].
    #[must_use]
    pub fn expose_token(&self) -> &str {
        self.token.expose_secret()
    }

    /// Exposes the token as a [`HeaderValue`], suitable for use in an `Authorization` header.
    ///
    /// # Errors
    ///
    /// Returns an [`InvalidHeaderValue`] if the token cannot be represented as a valid header value.
    pub fn expose_header_value(&self) -> Result<HeaderValue, InvalidHeaderValue> {
        HeaderValue::from_str(&format!("Bearer {}", self.token.expose_secret()))
    }

    /// The token's effective expiry; see
    /// [`AccessToken::effective_expiry`] for the parameter semantics.
    #[must_use]
    pub fn effective_expiry(
        &self,
        default_expires_in: Duration,
        expires_margin: Duration,
    ) -> SystemTime {
        let expires_in = self.expires_in.unwrap_or(default_expires_in);
        effective_expiry(self.received_at, expires_in, expires_margin)
    }

    /// Returns `true` if the underlying access token has expired.
    #[must_use]
    pub fn is_expired(&self, default_expires_in: Duration, expires_margin: Duration) -> bool {
        SystemTime::now() >= self.effective_expiry(default_expires_in, expires_margin)
    }

    /// The token's effective lifetime; see
    /// [`AccessToken::effective_lifetime`].
    #[must_use]
    pub fn effective_lifetime(&self, default_expires_in: Duration) -> Duration {
        self.expires_in.unwrap_or(default_expires_in)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huge_expires_in_does_not_panic() {
        // A malicious AS can return expires_in values that overflow SystemTime.
        let token = BearerAccessToken::new(
            SecretString::new("tok"),
            SystemTime::now(),
            Some(Duration::from_secs(u64::MAX)),
        );
        assert!(!token.is_expired(Duration::from_hours(1), Duration::from_secs(30)));
    }

    #[test]
    fn huge_margin_does_not_panic() {
        let token = BearerAccessToken::new(
            SecretString::new("tok"),
            SystemTime::now(),
            Some(Duration::from_hours(1)),
        );
        // A margin larger than the expiry clamps to the epoch: already stale.
        assert!(token.is_expired(Duration::from_hours(1), Duration::from_secs(u64::MAX)));
    }

    #[test]
    fn normal_expiry_unchanged() {
        let received_at = SystemTime::now();
        let token = BearerAccessToken::new(
            SecretString::new("tok"),
            received_at,
            Some(Duration::from_hours(1)),
        );
        assert_eq!(
            token.effective_expiry(Duration::from_hours(1), Duration::from_secs(30)),
            received_at + Duration::from_secs(3600 - 30)
        );
        assert!(!token.is_expired(Duration::from_hours(1), Duration::from_secs(30)));
    }
}
