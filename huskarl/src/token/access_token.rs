use http::{HeaderValue, header::InvalidHeaderValue};

use crate::core::{
    platform::{Duration, SystemTime},
    secrets::SecretString,
};

/// Represents an access token, either a `DPoP` token or a `Bearer` token.
#[derive(Debug, Clone)]
pub enum AccessToken {
    /// A `DPoP` token.
    Dpop(DpopAccessToken),
    /// A `Bearer` token.
    Bearer(BearerAccessToken),
}

impl AccessToken {
    /// Exposes the token as a [`SecretString`].
    #[must_use]
    pub fn token(&self) -> &SecretString {
        match self {
            AccessToken::Dpop(token) => &token.token,
            AccessToken::Bearer(token) => &token.token,
        }
    }

    /// Exposes the token as a [`HeaderValue`], suitable for use in an `Authorization` header.
    ///
    /// # Errors
    ///
    /// Returns an [`InvalidHeaderValue`] if the token cannot be represented as a valid header value.
    pub fn expose_header_value(&self) -> Result<HeaderValue, InvalidHeaderValue> {
        match self {
            AccessToken::Dpop(dpop_access_token) => dpop_access_token.expose_header_value(),
            AccessToken::Bearer(bearer_access_token) => bearer_access_token.expose_header_value(),
        }
    }

    /// Returns the `DPoP` JWT thumbprint, if the token is a `DPoP` token.
    #[must_use]
    pub fn dpop_jkt(&self) -> Option<&str> {
        match self {
            AccessToken::Dpop(token) => Some(token.jkt.as_str()),
            AccessToken::Bearer(_) => None,
        }
    }

    /// Returns the token type, either `"DPoP"` or `"Bearer"`.
    #[must_use]
    pub fn token_type(&self) -> &str {
        match self {
            AccessToken::Dpop(_) => "DPoP",
            AccessToken::Bearer(_) => "Bearer",
        }
    }

    /// Returns the effective expiry time of the token: `received_at + expires_in - margin`.
    ///
    /// This is the point in time after which the token should be considered stale.
    /// The token is valid while `SystemTime::now() < effective_expiry(...)`.
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
        }
    }

    /// Returns `true` if the underlying access token has expired.
    #[must_use]
    pub fn is_expired(&self, default_expires_in: Duration, expires_margin: Duration) -> bool {
        SystemTime::now() >= self.effective_expiry(default_expires_in, expires_margin)
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

    /// Returns the effective expiry time of the token: `received_at + expires_in - margin`.
    ///
    /// This is the point in time after which the token should be considered stale.
    /// The token is valid while `SystemTime::now() < effective_expiry(...)`.
    #[must_use]
    pub fn effective_expiry(
        &self,
        default_expires_in: Duration,
        expires_margin: Duration,
    ) -> SystemTime {
        let expires_in = self.expires_in.unwrap_or(default_expires_in);
        self.received_at + expires_in - expires_margin
    }

    /// Returns `true` if the underlying access token has expired.
    #[must_use]
    pub fn is_expired(&self, default_expires_in: Duration, expires_margin: Duration) -> bool {
        SystemTime::now() >= self.effective_expiry(default_expires_in, expires_margin)
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

    /// Returns the effective expiry time of the token: `received_at + expires_in - margin`.
    ///
    /// This is the point in time after which the token should be considered stale.
    /// The token is valid while `SystemTime::now() < effective_expiry(...)`.
    #[must_use]
    pub fn effective_expiry(
        &self,
        default_expires_in: Duration,
        expires_margin: Duration,
    ) -> SystemTime {
        let expires_in = self.expires_in.unwrap_or(default_expires_in);
        self.received_at + expires_in - expires_margin
    }

    /// Returns `true` if the underlying access token has expired.
    #[must_use]
    pub fn is_expired(&self, default_expires_in: Duration, expires_margin: Duration) -> bool {
        SystemTime::now() >= self.effective_expiry(default_expires_in, expires_margin)
    }
}
