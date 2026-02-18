use bon::Builder;
use rand::TryRng as _;
use serde::{Deserialize, Serialize};

use crate::grant::core::mk_scopes;

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationPayload<'a> {
    pub(super) response_type: &'static str,
    pub(super) redirect_uri: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) scope: Option<&'a str>,
    pub(super) state: &'a str,
    pub(super) code_challenge: &'a str,
    pub(super) code_challenge_method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) dpop_jkt: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationPayloadWithClientId<'a> {
    pub(super) client_id: &'a str,
    #[serde(flatten)]
    pub(super) rest: AuthorizationPayload<'a>,
}

/// The input required when beginning the authorization code flow.
#[derive(Debug, Clone, Builder)]
#[builder(finish_fn(vis = "", name = build_internal))]
pub struct StartInput {
    #[builder(finish_fn)]
    pub(super) state: String,
    #[builder(required, with = |scopes: impl IntoIterator<Item = impl Into<String>>| mk_scopes(scopes))]
    pub(super) scopes: Option<String>,
}

impl StartInput {
    /// Implements a simple complete input to the flow including just scopes.
    ///
    /// This is enough for most use cases; the builder exists as an extensible
    /// API where arbitrary extra fields may be added in future.
    pub fn scopes(scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::builder().scopes(scopes).build()
    }
}

impl<S: start_input_builder::IsComplete> StartInputBuilder<S> {
    pub fn build(self) -> StartInput {
        self.build_internal(generate_random_value())
    }
}

/// The result of starting the authorization code flow.
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
}

/// The information needed to be stored from the initial flow setup, for use in the callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

const RANDOM_VALUE_BYTES: usize = 32;

pub(super) fn generate_random_value() -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mut random_bytes = [0u8; RANDOM_VALUE_BYTES];
    rand::rng()
        .try_fill_bytes(&mut random_bytes)
        .unwrap_or_else(|e: std::convert::Infallible| match e {});
    URL_SAFE_NO_PAD.encode(random_bytes)
}
