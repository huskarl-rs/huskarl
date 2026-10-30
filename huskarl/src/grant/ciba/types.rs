use std::num::NonZeroU32;

use bon::Builder;
use serde::{Deserialize, Serialize};

use crate::{
    core::{jwt::validator::ValidatedJwt, secrets::SecretString},
    grant::core::TokenResponse,
    token::id_token::{IdToken, IdTokenClaims},
};

/// Identifies the user for a CIBA authentication request.
///
/// Exactly one hint is required. Hint tokens use the format agreed with your
/// provider; an ID-token hint is a previously issued signed ID token.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CibaHint {
    /// An identifier the provider recognizes, such as an email address.
    LoginHint(SecretString),
    /// A provider-specific token identifying the user.
    LoginHintToken(SecretString),
    /// A signed ID token previously issued by this provider to this client.
    IdTokenHint(IdToken),
}

impl CibaHint {
    /// Creates a hint from a user identifier the provider recognizes.
    #[must_use]
    pub fn login_hint(value: impl Into<SecretString>) -> Self {
        Self::LoginHint(value.into())
    }

    /// Creates a hint from a provider-specific token identifying the user.
    #[must_use]
    pub fn login_hint_token(value: impl Into<SecretString>) -> Self {
        Self::LoginHintToken(value.into())
    }

    /// Creates a hint from a signed ID token previously issued to this client.
    #[must_use]
    pub fn id_token_hint(value: impl Into<IdToken>) -> Self {
        Self::IdTokenHint(value.into())
    }
}

/// Input to a CIBA authentication request.
///
/// The required hint selects exactly one identification method. The builder
/// omits optional fields, and the grant includes `openid` in the requested scopes.
#[derive(Debug, Clone, Builder)]
#[builder(on(String, into), builder_type(doc {
    /// Configures a CIBA authentication request. Set a hint before building.
}))]
pub struct StartInput {
    /// The user to authenticate.
    pub(super) hint: CibaHint,
    /// Expected subject of the authenticated user, when known.
    /// Persisted with the request and checked after ID-token validation.
    pub(super) expected_sub: Option<String>,
    /// Requested scopes. `openid` is always included by the grant.
    pub(super) scope: Option<Vec<String>>,
    /// Requested authentication contexts, in preference order. These are
    /// preferences, not a requirement imposed on the returned ID token.
    pub(super) acr_values: Option<Vec<String>>,
    /// Short message to display on both devices to identify the transaction.
    pub(super) binding_message: Option<String>,
    /// User-supplied secret authorizing the request. Ask for it for each flow;
    /// do not persist it. Requires provider support and client registration.
    #[builder(into)]
    pub(super) user_code: Option<SecretString>,
    /// Requested authentication lifetime, in seconds. The provider chooses the actual lifetime.
    pub(super) requested_expiry: Option<NonZeroU32>,
    /// Resource indicators (RFC 8707), when supported by the provider.
    pub(super) resource: Option<Vec<String>>,
    /// Rich authorization details (RFC 9396), when supported by the provider.
    pub(super) authorization_details: Option<Vec<crate::core::AuthorizationDetail>>,
}

/// Acknowledgement of a started CIBA authentication request.
#[derive(Debug, Builder)]
#[non_exhaustive]
pub struct StartOutput {
    /// Local expiry estimate, anchored to response receipt.
    /// The provider enforces the actual request lifetime.
    pub expires_at: crate::core::platform::SystemTime,
    /// State to persist and pass to polling operations.
    pub pending_state: PendingState,
}

/// State persisted between CIBA polls.
///
/// Serialization includes the request ID. Store it securely with the initiating
/// user's application session and restore it only with the same client and provider.
#[derive(Builder, Serialize, Deserialize)]
#[builder(on(String, into))]
#[non_exhaustive]
pub struct PendingState {
    /// Opaque authentication request ID returned by the provider.
    pub auth_req_id: String,
    /// Local expiry estimate, persisted so automatic polling can bound its waits.
    pub expires_at: crate::core::platform::SystemTime,
    /// Expected subject, when the initiating application knows it.
    #[serde(default)]
    pub expected_sub: Option<String>,
    /// Minimum polling interval in seconds. A `slow_down` response increases it.
    pub interval_secs: u32,
}

impl core::fmt::Debug for PendingState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingState")
            .field("auth_req_id", &"[REDACTED]")
            .field("interval_secs", &self.interval_secs)
            .field("expires_at", &self.expires_at)
            .field(
                "expected_sub",
                &self.expected_sub.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Completed authentication with a validated identity.
#[derive(Debug)]
#[non_exhaustive]
pub struct CompleteOutput {
    /// Access and optional refresh tokens returned by the token endpoint.
    pub token_response: TokenResponse,
    /// ID token validated against the configured issuer, client ID, and verification keys.
    pub id_token: ValidatedJwt<IdTokenClaims>,
}

/// Result of one CIBA poll.
#[derive(Debug)]
pub enum PollResult {
    /// Authentication is still pending. Respect the state's polling interval.
    Pending,
    /// Authentication completed and the ID token was validated.
    Complete(Box<CompleteOutput>),
}

/// Parameters for a low-level CIBA token exchange.
///
/// [`OAuth2ExchangeGrant::exchange`](crate::grant::core::OAuth2ExchangeGrant::exchange)
/// returns an unvalidated ID token. Use [`CibaPollGrant::poll`](super::CibaPollGrant::poll)
/// to obtain a validated authentication result.
#[derive(Clone, Builder)]
#[builder(on(String, into))]
pub struct CibaPollGrantParameters {
    /// Authentication request ID returned by `start`.
    pub(super) auth_req_id: String,
    /// Resource indicators for the token request (RFC 8707).
    pub(super) resource: Option<Vec<String>>,
}

impl core::fmt::Debug for CibaPollGrantParameters {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CibaPollGrantParameters")
            .field("auth_req_id", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Serialized CIBA token request body.
#[derive(Serialize)]
pub struct CibaPollGrantForm {
    pub(super) grant_type: &'static str,
    pub(super) auth_req_id: String,
    pub(super) resource: Option<Vec<String>>,
}

#[derive(Serialize)]
pub(super) struct AuthenticationRequest<'a> {
    pub scope: Option<String>,
    #[serde(flatten)]
    pub hint: &'a CibaHint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_message: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_code: Option<&'a SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_expiry: Option<NonZeroU32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<&'a [crate::core::AuthorizationDetail]>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum AuthenticationForm<'a> {
    Unsigned(&'a AuthenticationRequest<'a>),
    Signed { request: &'a SecretString },
}

#[derive(Deserialize)]
pub(super) struct AuthenticationResponse {
    pub auth_req_id: String,
    pub expires_in: NonZeroU32,
    #[serde(default = "default_interval")]
    pub interval: NonZeroU32,
}

fn default_interval() -> NonZeroU32 {
    // Five seconds is the CIBA §7.3 default.
    const {
        NonZeroU32::new(super::DEFAULT_MIN_POLL_INTERVAL_SECS)
            .expect("default interval is positive")
    }
}
