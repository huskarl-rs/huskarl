//! `OAuth2` grant type implementations.
//!
//! Choose the grant type that fits your use case:
//!
//! | Grant | Use case |
//! |-------|----------|
//! | [`authorization_code`] | User-facing apps — the user logs in via a browser |
//! | [`client_credentials`] | Machine-to-machine — the client acts on its own behalf |
//! | [`device_authorization`] | Devices with limited input (TVs, CLIs) |
//! | [`jwt_bearer`] | Present a signed JWT assertion vouching for a principal |
//! | [`token_exchange`] | Exchange an existing token for a new one (impersonation, delegation) |
//! | [`refresh`] | Renew an access token using a refresh token |
//!
//! Each grant module documents its own type. For step-by-step setup — building
//! the HTTP client and client authentication, then driving the flow — see the
//! how-to guides in [`crate::_docs::guide`].

pub mod authorization_code;
pub mod client_credentials;
pub mod core;
pub mod device_authorization;
pub mod jwt_bearer;
pub mod refresh;
pub mod token_exchange;

/// Outcome of authorization-code completion, suitable for a low-cardinality
/// metrics label.
///
/// Emitted as the `outcome` label on `huskarl.grant.complete` when the
/// `metrics` feature is on. The security-relevant variants are
/// [`IssuerMismatch`](Self::IssuerMismatch),
/// [`StateMismatch`](Self::StateMismatch) and
/// [`JarmDowngrade`](Self::JarmDowngrade).
///
/// Attacker-controlled values are never included in the label.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantOutcome {
    /// A token was obtained.
    Success,
    /// The `iss` returned to the callback was not the one the flow started
    /// with — an RFC 9207 mix-up, an active attack or a broken AS.
    IssuerMismatch,
    /// The callback carried no matching `state`: unsolicited, or forged.
    StateMismatch,
    /// A JWT-secured response was requested and plain parameters arrived, or a
    /// JARM response arrived that was never asked for — a downgrade attempt.
    JarmDowngrade,
    /// The `DPoP` key differs from the one bound at authorization time.
    DPoPKeyMismatch,
    /// The server returned a well-formed error response.
    Rejected,
    /// The response could not be used.
    Protocol,
    /// This grant was never wired up to validate what it received.
    NotConfigured,
    /// A failure outside the grant's own protocol checks, such as transport or
    /// client authentication.
    Other,
}

impl GrantOutcome {
    /// Returns the value emitted in the `outcome` metrics label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::StateMismatch => "state_mismatch",
            Self::JarmDowngrade => "jarm_downgrade",
            Self::DPoPKeyMismatch => "dpop_key_mismatch",
            Self::Rejected => "rejected",
            Self::Protocol => "protocol",
            Self::NotConfigured => "not_configured",
            Self::Other => "other",
        }
    }
}
