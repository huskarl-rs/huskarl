use bon::Builder;
use rand::TryRng as _;
use serde::{Deserialize, Serialize};

use crate::{
    core::{AuthorizationDetail, platform::Duration},
    grant::core::mk_scopes,
    token::IdToken,
};

/// The authorization-request parameters sent to the authorization endpoint
/// (RFC 6749 §4.1.1, with the OIDC, PKCE, `DPoP`, and resource-indicator
/// extensions).
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationPayload<'a> {
    pub(super) response_type: &'static str,
    pub(super) redirect_uri: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) scope: Option<&'a str>,
    pub(super) state: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) code_challenge: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) code_challenge_method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) dpop_jkt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) nonce: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) display: Option<&'a Display>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) prompt: Option<&'a Prompt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) max_age: Option<&'a Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ui_locales: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) id_token_hint: Option<&'a IdToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) login_hint: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) acr_values: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) resource: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) authorization_details: Option<&'a [AuthorizationDetail]>,
}

/// An [`AuthorizationPayload`] plus the `client_id`, for delivery as plain query
/// parameters — i.e. when the request is *not* wrapped in a JAR request object
/// (which conveys the `client_id` separately).
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationPayloadWithClientId<'a> {
    pub(super) client_id: &'a str,
    #[serde(flatten)]
    pub(super) rest: AuthorizationPayload<'a>,
}

/// The input required when beginning the authorization code flow.
#[derive(Debug, Clone, Builder)]
#[builder(finish_fn(vis = "", name = build_internal), on(String, into))]
pub struct StartInput {
    #[builder(finish_fn)]
    pub(super) state: String,
    #[builder(finish_fn)]
    pub(super) nonce: String,
    #[builder(required, default, with = |scopes: impl IntoIterator<Item = impl Into<String>>| mk_scopes(scopes))]
    pub(super) scopes: Option<String>,
    pub(super) resource: Option<Vec<String>>,
    /// RFC 9396 Rich Authorization Requests: fine-grained authorization
    /// requirements expressed as typed authorization-details objects.
    pub(super) authorization_details: Option<Vec<AuthorizationDetail>>,

    // OIDC Core parameters.
    /// Specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.
    pub(super) display: Option<Display>,
    /// Specifies whether the Authorization Server prompts the End-User for reauthentication and consent.
    pub(super) prompt: Option<Prompt>,
    /// Specifies the allowable elapsed time since the last time the End-User was actively authenticated by the OP.
    pub(super) max_age: Option<Duration>,
    /// End-User's preferred languages and scripts for the user interface, ordered by preference.
    pub(super) ui_locales: Option<Vec<String>>,
    /// ID Token previously issued by the Authorization Server being passed as a hint about the End-User's current or past authenticated session with the Client.
    ///
    /// If the End-User identified by the ID Token is already logged in or is logged in as a result of the request (with the OP possibly evaluating other
    /// information beyond the ID Token in this decision), then the Authorization Server returns a positive response; otherwise, it MUST return an error,
    /// such as `login_required`. When possible, an `id_token_hint` SHOULD be present when prompt=none is used and an `invalid_request` error MAY be returned if
    /// it is not; however, the server SHOULD respond successfully when possible, even if it is not present. The Authorization Server need not be listed as
    /// an audience of the ID Token when it is used as an `id_token_hint` value.
    pub(super) id_token_hint: Option<IdToken>,
    /// Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary)
    pub(super) login_hint: Option<String>,
    /// Requested Authentication Context Class Reference values.
    pub(super) acr_values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub enum Display {
    #[serde(rename = "page")]
    Page,
    #[serde(rename = "popup")]
    Popup,
    #[serde(rename = "touch")]
    Touch,
    #[serde(rename = "wap")]
    Wap,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub enum Prompt {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "login")]
    Login,
    #[serde(rename = "consent")]
    Consent,
    #[serde(rename = "select_account")]
    SelectAccount,
    #[serde(untagged)]
    Other(String),
}

impl StartInput {
    /// Convenience constructor for a start input carrying only scopes.
    ///
    /// This is enough for most use cases; the builder exists as an extensible
    /// API where arbitrary extra fields may be added in future.
    pub fn scopes(scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::builder().scopes(scopes).build()
    }
}

impl<S: start_input_builder::IsComplete> StartInputBuilder<S> {
    pub fn build(self) -> StartInput {
        self.build_internal(generate_random_value(), generate_random_value())
    }
}

/// The result of starting the authorization code flow.
#[non_exhaustive]
pub struct StartOutput {
    /// The URL to redirect the user to for authorization.
    pub authorization_url: http::Uri,
    /// If PAR was used, the time in seconds until the request expires.
    pub expires_in: Option<u64>,
    /// State that must be persisted until the callback completes.
    pub pending_state: PendingState,
}

/// The information needed to complete an authorization code flow.
#[derive(Debug, Clone, Builder)]
pub struct CompleteInput {
    #[builder(into)]
    pub(super) code: String,
    #[builder(into)]
    pub(super) state: String,
    #[builder(into)]
    pub(super) iss: Option<String>,
    pub(super) resource: Option<Vec<String>>,
}

/// The information needed to be stored from the initial flow setup, for use in the callback.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PendingState {
    /// The redirect URI.
    ///
    /// In OAuth 2.0, when this specified at the authorization endpoint, it also needs to be
    /// sent to the token endpoint.
    pub redirect_uri: String,
    /// The PKCE verifier.
    ///
    /// This value is calculated when creating the initial flow, and needs to be sent to the
    /// token endpoint when PKCE is used.
    pub pkce_verifier: Option<String>,
    /// The state parameter.
    ///
    /// The state value passed to the authorization endpoint.
    ///
    /// This value is checked for equality against the state value passed to the callback.
    pub state: String,
    /// Nonce used when verifying any provided ID token.
    ///
    /// The nonce value passed to the authorization endpoint.
    ///
    /// This value is checked for equality against the nonce claim in any returned ID token.
    pub nonce: String,
    /// The `DPoP` JWT thumbprint.
    ///
    /// The thumbprint of the `DPoP` key bound to the request.
    pub dpop_jkt: Option<String>,
}

// `PendingState` is designed to be persisted to a session store and is
// therefore the most likely thing to end up in logs. The PKCE verifier
// protects the code exchange, `state` is the CSRF token, and `nonce` binds
// the ID token, so none of them may appear in `Debug` output.
impl std::fmt::Debug for PendingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingState")
            .field("redirect_uri", &self.redirect_uri)
            .field(
                "pkce_verifier",
                &self.pkce_verifier.as_ref().map(|_| "[REDACTED]"),
            )
            .field("state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("dpop_jkt", &self.dpop_jkt)
            .finish()
    }
}

const RANDOM_VALUE_BYTES: usize = 32;

pub(super) fn generate_random_value() -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let mut random_bytes = [0u8; RANDOM_VALUE_BYTES];
    rand::rng()
        .try_fill_bytes(&mut random_bytes)
        .unwrap_or_else(|e: std::convert::Infallible| match e {});
    URL_SAFE_NO_PAD.encode(random_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_state_debug_redacts_secrets() {
        let state = PendingState {
            redirect_uri: "http://127.0.0.1/cb".to_owned(),
            pkce_verifier: Some("super-secret-verifier".to_owned()),
            state: "csrf-state-value".to_owned(),
            nonce: "id-token-nonce".to_owned(),
            dpop_jkt: Some("jkt-thumbprint".to_owned()),
        };

        let debug = format!("{state:?}");
        assert!(!debug.contains("super-secret-verifier"), "{debug}");
        assert!(!debug.contains("csrf-state-value"), "{debug}");
        assert!(!debug.contains("id-token-nonce"), "{debug}");
        // Non-secret fields stay visible for debugging.
        assert!(debug.contains("http://127.0.0.1/cb"), "{debug}");
        assert!(debug.contains("jkt-thumbprint"), "{debug}");
    }
}
