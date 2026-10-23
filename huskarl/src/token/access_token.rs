use http::{HeaderValue, header::InvalidHeaderValue};

use crate::core::{
    platform::{Duration, SystemTime},
    secrets::SecretString,
    time::{Clock, PlatformClock},
};

/// Compute the final deadline before saturating, so a large lifetime and margin
/// can cancel without overflowing an intermediate timestamp.
pub(crate) fn effective_expiry_at(
    received_at: jiff::Timestamp,
    expires_in: Duration,
    expires_margin: Duration,
) -> jiff::Timestamp {
    if let Some(remaining) = expires_in.checked_sub(expires_margin) {
        received_at
            .checked_add(remaining)
            .unwrap_or(jiff::Timestamp::MAX)
    } else {
        received_at
            .checked_sub(expires_margin.saturating_sub(expires_in))
            .unwrap_or(jiff::Timestamp::MIN)
    }
}

fn effective_expiry(
    received_at: SystemTime,
    expires_in: Duration,
    expires_margin: Duration,
) -> SystemTime {
    let received_at = crate::core::time::timestamp_from_system_time_saturating(received_at);
    crate::core::time::system_time_from_timestamp_saturating(effective_expiry_at(
        received_at,
        expires_in,
        expires_margin,
    ))
}

/// An access token returned by a token grant, used to authorize resource-server
/// requests.
///
/// Get the `Authorization` header value with
/// [`expose_header_value`](Self::expose_header_value) — the
/// [`HttpAuthorizer`](crate::authorizer::HttpAuthorizer) does this for you. The
/// variant determines how the token is presented: a [`Bearer`](Self::Bearer)
/// token authorizes by possession alone, while a [`DPoP`](Self::DPoP) token is
/// sender-constrained (RFC 9449) — each request must carry a `DPoP` proof over
/// the bound key, whose thumbprint is the token's [`dpop_jkt`](Self::dpop_jkt).
#[derive(Debug, Clone)]
pub enum AccessToken {
    /// A `DPoP` token.
    DPoP(DPoPAccessToken),
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
            AccessToken::DPoP(token) => &token.token,
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
            AccessToken::DPoP(dpop_access_token) => dpop_access_token.expose_header_value(),
            AccessToken::Bearer(bearer_access_token) => bearer_access_token.expose_header_value(),
            // Deterministically manufacture an InvalidHeaderValue (the type
            // has no public constructor): an N_A token has no header form,
            // and a control character is never a valid header value.
            //
            // The `Ok` branch is unreachable, and deliberately a panic rather
            // than a value: the only value it could yield is a `HeaderValue`,
            // and handing one back would present an N_A issuance as an
            // `Authorization` credential (RFC 8693 §2.2.1). Failing loudly is
            // the safe direction if `http` ever stopped rejecting control
            // characters.
            #[allow(clippy::unreachable)]
            AccessToken::NotAccessToken(_) => HeaderValue::from_str("\n")
                .map(|_| unreachable!("a control character is never a valid header value")),
        }
    }

    /// Returns the `DPoP` JWT thumbprint, if the token is a `DPoP` token.
    #[must_use]
    pub fn dpop_jkt(&self) -> Option<&str> {
        match self {
            AccessToken::DPoP(token) => Some(token.jkt.as_str()),
            AccessToken::Bearer(_) | AccessToken::NotAccessToken(_) => None,
        }
    }

    /// Returns the token type: `"DPoP"`, `"Bearer"`, or `"N_A"`.
    #[must_use]
    pub fn token_type(&self) -> &str {
        match self {
            AccessToken::DPoP(_) => "DPoP",
            AccessToken::Bearer(_) => "Bearer",
            AccessToken::NotAccessToken(_) => "N_A",
        }
    }

    /// The time after which this token should be treated as stale:
    /// `received_at + expires_in - expires_margin`. It is valid while
    /// the current wall-clock time is earlier than this.
    ///
    /// `default_expires_in` applies only when the token response carried no
    /// `expires_in` of its own; `expires_margin` is subtracted to retire the
    /// token slightly early. Out-of-range receipts are clamped to Jiff's timestamp
    /// range. The final deadline saturates at Jiff's and the platform's time
    /// boundaries: oversized lifetimes remain far-future deadlines, while
    /// oversized margins produce far-past deadlines. Lifetime and margin are
    /// combined before timestamp arithmetic, avoiding intermediate overflow.
    #[must_use]
    pub fn effective_expiry(
        &self,
        default_expires_in: Duration,
        expires_margin: Duration,
    ) -> SystemTime {
        match self {
            AccessToken::DPoP(dpop_access_token) => {
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

    /// Returns whether the token is stale at the current time.
    ///
    /// Uses [`Self::effective_expiry`], including its `default_expires_in` and
    /// `expires_margin` semantics.
    #[must_use]
    pub fn is_expired(&self, default_expires_in: Duration, expires_margin: Duration) -> bool {
        self.is_expired_at(
            huskarl_core::time::system_time_from_timestamp_saturating(PlatformClock.now()),
            default_expires_in,
            expires_margin,
        )
    }

    /// Returns whether the token is stale at the supplied wall-clock time.
    ///
    /// Uses [`Self::effective_expiry`]; equality with the deadline counts as expired.
    #[must_use]
    pub fn is_expired_at(
        &self,
        now: SystemTime,
        default_expires_in: Duration,
        expires_margin: Duration,
    ) -> bool {
        now >= self.effective_expiry(default_expires_in, expires_margin)
    }

    /// The token's effective lifetime: the `expires_in` from the token response,
    /// or `default_expires_in` when the response carried none. This is the full
    /// validity span before any `expires_margin` is applied.
    #[must_use]
    pub fn effective_lifetime(&self, default_expires_in: Duration) -> Duration {
        match self {
            AccessToken::DPoP(dpop_access_token) => {
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

    /// Returns whether the token is stale at the current time.
    ///
    /// Uses [`Self::effective_expiry`], including its `default_expires_in` and
    /// `expires_margin` semantics.
    #[must_use]
    pub fn is_expired(&self, default_expires_in: Duration, expires_margin: Duration) -> bool {
        self.is_expired_at(
            huskarl_core::time::system_time_from_timestamp_saturating(PlatformClock.now()),
            default_expires_in,
            expires_margin,
        )
    }

    /// Returns whether the token is stale at the supplied wall-clock time.
    ///
    /// Uses [`Self::effective_expiry`]; equality with the deadline counts as expired.
    #[must_use]
    pub fn is_expired_at(
        &self,
        now: SystemTime,
        default_expires_in: Duration,
        expires_margin: Duration,
    ) -> bool {
        now >= self.effective_expiry(default_expires_in, expires_margin)
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
pub struct DPoPAccessToken {
    /// The `DPoP` access token.
    token: SecretString,
    /// The `DPoP` JWT thumbprint.
    jkt: String,
    /// The time at which the token was received.
    received_at: SystemTime,
    /// The duration for which the token is valid.
    expires_in: Option<Duration>,
}

impl DPoPAccessToken {
    /// Creates a new [`DPoPAccessToken`] with the given token, JWT thumbprint, received time, and expiration duration.
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

    /// Returns whether the token is stale at the current time.
    ///
    /// Uses [`Self::effective_expiry`], including its `default_expires_in` and
    /// `expires_margin` semantics.
    #[must_use]
    pub fn is_expired(&self, default_expires_in: Duration, expires_margin: Duration) -> bool {
        self.is_expired_at(
            huskarl_core::time::system_time_from_timestamp_saturating(PlatformClock.now()),
            default_expires_in,
            expires_margin,
        )
    }

    /// Returns whether the token is stale at the supplied wall-clock time.
    ///
    /// Uses [`Self::effective_expiry`]; equality with the deadline counts as expired.
    #[must_use]
    pub fn is_expired_at(
        &self,
        now: SystemTime,
        default_expires_in: Duration,
        expires_margin: Duration,
    ) -> bool {
        now >= self.effective_expiry(default_expires_in, expires_margin)
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

    /// Returns whether the token is stale at the current time.
    ///
    /// Uses [`Self::effective_expiry`], including its `default_expires_in` and
    /// `expires_margin` semantics.
    #[must_use]
    pub fn is_expired(&self, default_expires_in: Duration, expires_margin: Duration) -> bool {
        self.is_expired_at(
            huskarl_core::time::system_time_from_timestamp_saturating(PlatformClock.now()),
            default_expires_in,
            expires_margin,
        )
    }

    /// Returns whether the token is stale at the supplied wall-clock time.
    ///
    /// Uses [`Self::effective_expiry`]; equality with the deadline counts as expired.
    #[must_use]
    pub fn is_expired_at(
        &self,
        now: SystemTime,
        default_expires_in: Duration,
        expires_margin: Duration,
    ) -> bool {
        now >= self.effective_expiry(default_expires_in, expires_margin)
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

    fn tokens(received_at: SystemTime, expires_in: Option<Duration>) -> [AccessToken; 3] {
        let secret = || SecretString::new("token");
        [
            AccessToken::Bearer(BearerAccessToken::new(secret(), received_at, expires_in)),
            AccessToken::DPoP(DPoPAccessToken::new(
                secret(),
                "key".into(),
                received_at,
                expires_in,
            )),
            AccessToken::NotAccessToken(NonAccessToken::new(secret(), received_at, expires_in)),
        ]
    }

    #[test]
    fn all_token_types_expire_at_the_exact_default_lifetime_boundary() {
        let received = SystemTime::UNIX_EPOCH - Duration::from_secs(100);
        let lifetime = Duration::from_secs(60);
        let margin = Duration::from_secs(10);
        let expiry = received + lifetime - margin;
        for token in tokens(received, None) {
            assert!(!token.is_expired_at(expiry - Duration::from_nanos(1), lifetime, margin));
            assert!(token.is_expired_at(expiry, lifetime, margin));
        }
    }

    #[test]
    fn huge_expires_in_remains_valid_far_into_the_future() {
        // A provider may use an oversized lifetime to mean "does not expire".
        let token = BearerAccessToken::new(
            SecretString::new("tok"),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
            Some(Duration::from_secs(u64::MAX)),
        );
        assert!(!token.is_expired_at(
            SystemTime::UNIX_EPOCH
                + Duration::from_secs(1_000_000)
                + Duration::from_hours(100 * 365 * 24),
            Duration::from_hours(1),
            Duration::from_secs(30)
        ));
    }

    #[test]
    fn huge_margin_does_not_panic() {
        let token = BearerAccessToken::new(
            SecretString::new("tok"),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
            Some(Duration::from_hours(1)),
        );
        // An unrepresentable margin-adjusted expiry is stale.
        assert!(token.is_expired_at(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
            Duration::from_hours(1),
            Duration::from_secs(u64::MAX)
        ));
    }

    #[test]
    fn normal_expiry_unchanged() {
        let received_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let token = BearerAccessToken::new(
            SecretString::new("tok"),
            received_at,
            Some(Duration::from_hours(1)),
        );
        assert_eq!(
            token.effective_expiry(Duration::from_hours(1), Duration::from_secs(30)),
            received_at + Duration::from_secs(3600 - 30)
        );
        assert!(!token.is_expired_at(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
            Duration::from_hours(1),
            Duration::from_secs(30)
        ));
    }
    #[rstest::rstest]
    #[case::explicit(Some(Duration::MAX))]
    #[case::default(None)]
    fn oversized_lifetimes_saturate_for_every_token_type(
        #[case] expires_in: Option<Duration>,
        #[values(Duration::ZERO, Duration::from_secs(30))] margin: Duration,
    ) {
        let received_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let maximum =
            crate::core::time::system_time_from_timestamp_saturating(jiff::Timestamp::MAX);
        for token in tokens(received_at, expires_in) {
            assert_eq!(token.effective_expiry(Duration::MAX, margin), maximum);
            for now in [
                SystemTime::UNIX_EPOCH,
                received_at,
                received_at + Duration::from_secs(1),
            ] {
                assert!(!token.is_expired_at(now, Duration::MAX, margin));
            }
            assert!(token.is_expired_at(maximum, Duration::MAX, margin));
        }
    }

    #[rstest::rstest]
    #[case::at_boundary(Duration::from_secs(1))]
    #[case::overflow(Duration::from_secs(2))]
    fn maximum_representable_expiry_and_overflow_share_the_saturated_boundary(
        #[case] lifetime: Duration,
    ) {
        let maximum = crate::core::time::system_time_from_timestamp(jiff::Timestamp::MAX).unwrap();
        let received_at = maximum - Duration::from_secs(1);
        let token = BearerAccessToken::new(SecretString::new("token"), received_at, Some(lifetime));
        assert_eq!(
            token.effective_expiry(Duration::ZERO, Duration::ZERO),
            maximum
        );
        assert!(!token.is_expired_at(received_at, Duration::ZERO, Duration::ZERO));
        assert!(token.is_expired_at(maximum, Duration::ZERO, Duration::ZERO));
    }

    #[test]
    fn large_lifetime_and_margin_cancel_before_timestamp_arithmetic() {
        let received_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let minute = Duration::from_secs(60);
        for (lifetime, margin, expected) in [
            (Duration::MAX, Duration::MAX, received_at),
            (
                Duration::MAX,
                Duration::MAX.checked_sub(minute).unwrap(),
                received_at + minute,
            ),
            (
                Duration::MAX.checked_sub(minute).unwrap(),
                Duration::MAX,
                received_at - minute,
            ),
        ] {
            let token =
                BearerAccessToken::new(SecretString::new("tok"), received_at, Some(lifetime));
            let expiry: SystemTime = token.effective_expiry(Duration::ZERO, margin);
            assert_eq!(expiry, expected);
            assert!(!token.is_expired_at(expiry - Duration::from_nanos(1), Duration::ZERO, margin));
            assert!(token.is_expired_at(expiry, Duration::ZERO, margin));
        }
    }
}
