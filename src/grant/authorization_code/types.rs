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

#[derive(Debug, Clone, Builder)]
#[builder(finish_fn(vis = "", name = build_internal))]
pub struct StartInput {
    #[builder(finish_fn)]
    pub state: String,
    #[builder(required, with = |scopes: impl IntoIterator<Item = impl Into<String>>| mk_scopes(scopes))]
    pub(super) scopes: Option<String>,
}

impl StartInput {
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

#[derive(Debug, Clone, Builder)]
pub struct CompleteInput {
    #[builder(into)]
    pub(super) code: String,
    #[builder(into)]
    pub(super) state: String,
    #[builder(into)]
    pub(super) iss: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingState {
    pub redirect_uri: String,
    pub pkce_verifier: Option<String>,
    pub state: String,
}

const RANDOM_VALUE_BYTES: usize = 32;

pub(super) fn generate_random_value() -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mut random_bytes = [0u8; RANDOM_VALUE_BYTES];
    rand::rng().try_fill_bytes(&mut random_bytes);
    URL_SAFE_NO_PAD.encode(random_bytes)
}
