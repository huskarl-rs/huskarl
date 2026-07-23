use bon::{Builder, bon};
use rand::TryRng as _;
use serde::{Deserialize, Serialize};

use crate::{
    core::{AuthorizationDetail, jwt::validator::ValidatedJwt, platform::Duration},
    grant::core::TokenResponse,
    token::{IdToken, id_token::IdTokenClaims},
};

/// The authorization-request parameters sent to the authorization endpoint
/// (RFC 6749 §4.1.1, with the OIDC, PKCE, `DPoP`, and resource-indicator
/// extensions).
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationPayload<'a> {
    pub(super) response_type: &'static str,
    pub(super) redirect_uri: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) scope: Option<String>,
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
    pub(super) response_mode: Option<ResponseMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) display: Option<&'a Display>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) prompt: Option<&'a Prompt>,
    /// Whole seconds — the wire shape OIDC Core §3.1.2.1 requires (serde's
    /// default `Duration` representation is a `{secs, nanos}` struct).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) max_age: Option<u64>,
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
///
/// The device-authorization flow has a same-named counterpart
/// ([`device_authorization::StartInput`](crate::grant::device_authorization::StartInput))
/// with the same [`scope`](Self::scope) convenience constructor; when
/// wiring both flows in one module, qualify or alias the imports.
#[derive(Debug, Clone, Builder)]
#[builder(finish_fn(vis = "", name = build_internal), on(String, into))]
pub struct StartInput {
    #[builder(finish_fn)]
    pub(super) state: String,
    #[builder(finish_fn)]
    pub(super) nonce: String,
    /// The requested scope(s) for the authorization request.
    pub(super) scope: Option<Vec<String>>,
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
    /// ID token previously issued by the Authorization Server, passed as a hint
    /// about the End-User's authenticated session (OIDC Core 1.0 §3.1.2.1).
    ///
    /// Typically paired with `prompt=none`. The AS need not be listed as an
    /// audience of this ID token when it is used as a hint.
    pub(super) id_token_hint: Option<IdToken>,
    /// Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary)
    pub(super) login_hint: Option<String>,
    /// Requested Authentication Context Class Reference values.
    pub(super) acr_values: Option<Vec<String>>,
}

/// The `response_mode` authorization-request parameter ([OAuth 2.0 Multiple
/// Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
/// §2.1; `form_post` is [OAuth 2.0 Form Post Response
/// Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html);
/// the `*.jwt` modes are [JARM](https://openid.net/specs/oauth-v2-jarm.html)
/// §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ResponseMode {
    /// Response parameters in the redirect query (the code-flow default).
    #[serde(rename = "query")]
    Query,
    /// Response parameters posted as a form body to the redirect URI.
    #[serde(rename = "form_post")]
    FormPost,
    /// JWT-secured response in the redirect query (JARM).
    #[serde(rename = "query.jwt")]
    QueryJwt,
    /// JWT-secured response posted as a form body (JARM).
    #[serde(rename = "form_post.jwt")]
    FormPostJwt,
    /// JWT-secured response in the flow's default transport (JARM).
    #[serde(rename = "jwt")]
    Jwt,
}

impl ResponseMode {
    /// Whether this mode returns a JWT-secured authorization response (JARM).
    #[must_use]
    pub fn is_jwt_secured(self) -> bool {
        matches!(self, Self::QueryJwt | Self::FormPostJwt | Self::Jwt)
    }
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
    #[must_use]
    pub fn scope(scope: Vec<String>) -> Self {
        Self::builder().scope(scope).build()
    }

    /// Whether the requested scope contains `openid`.
    pub(super) fn requests_openid(&self) -> bool {
        self.scope
            .as_deref()
            .is_some_and(|s| s.iter().any(|scope| scope == "openid"))
    }
}

impl<S: start_input_builder::IsComplete> StartInputBuilder<S> {
    pub fn build(self) -> StartInput {
        self.build_internal(generate_random_value(), generate_random_value())
    }
}

/// The result of starting the authorization code flow.
///
/// The device-authorization flow has a same-named counterpart
/// ([`device_authorization::StartOutput`](crate::grant::device_authorization::StartOutput))
/// — the workflow grants deliberately share a *start → persist
/// [`PendingState`] → complete* vocabulary. When wiring both flows in one
/// module, qualify (`authorization_code::StartOutput`) or alias the imports.
#[derive(Debug)]
#[non_exhaustive]
pub struct StartOutput {
    /// The URL to redirect the user to for authorization.
    pub authorization_url: http::Uri,
    /// When the pushed authorization request expires (RFC 9126 `expires_in`,
    /// resolved to an absolute time at receipt). `None` when PAR was not
    /// used. Restart the flow rather than redirecting to an expired request.
    pub expires_at: Option<crate::core::platform::SystemTime>,
    /// State that must be persisted until the callback completes.
    pub pending_state: PendingState,
}

/// The result of completing an authorization code flow: the token endpoint
/// response, plus the validated ID token when the flow was OIDC.
///
/// Returned by
/// [`complete`](crate::grant::authorization_code::AuthorizationCodeGrant::complete)
/// and its loopback variant.
#[derive(Debug)]
#[non_exhaustive]
pub struct CompleteOutput {
    /// The token endpoint response.
    pub token_response: TokenResponse,
    /// The validated ID token — `Some` whenever the flow is OIDC (see
    /// [`complete`](crate::grant::authorization_code::AuthorizationCodeGrant::complete)),
    /// `None` otherwise.
    pub id_token: Option<ValidatedJwt<IdTokenClaims>>,
}

/// An authorization response in its final form: the RFC 6749 §4.1.2 success
/// parameters or the §4.1.2.1 error parameters.
///
/// A JARM response folds into this once verified, so the completion checks
/// have no third shape to consider.
#[derive(Debug, Clone)]
pub(super) enum AuthorizationResponse {
    /// The success parameters, plus the RFC 9207 `iss`.
    Success {
        code: String,
        state: String,
        iss: Option<String>,
    },
    /// An OAuth error response (e.g. the user denied access). `state` mirrors
    /// the wire, where it can be absent; completion rejects that.
    Error {
        error: String,
        error_description: Option<String>,
        state: Option<String>,
    },
}

/// What the authorization callback carried, before any verification.
#[derive(Debug, Clone)]
pub(super) enum CallbackPayload {
    /// Response parameters read straight off the callback.
    Plain(AuthorizationResponse),
    /// A JWT-secured authorization response (JARM §2.1), still to be verified.
    Jarm { response: String },
}

/// The information needed to complete an authorization code flow.
///
/// Parse the callback URL or query string via [`FromStr`](std::str::FromStr)
/// to capture `code`, `state`, and the RFC 9207 `iss`;
/// [`builder_from_callback`](Self::builder_from_callback) also lets `resource`
/// be set. When building by hand, include `iss` — it is required when the
/// server advertises RFC 9207 support.
///
/// An OAuth error response also parses; completion checks its `state` like any
/// other callback, then surfaces it as
/// [`CompleteError::OAuthError`](super::CompleteError::OAuthError).
#[derive(Debug, Clone)]
pub struct CompleteInput {
    pub(super) payload: CallbackPayload,
    pub(super) resource: Option<Vec<String>>,
}

#[bon]
impl CompleteInput {
    /// By-hand construction from already-extracted success parameters (e.g.
    /// framework-typed query parameters).
    #[builder]
    pub fn new(
        #[builder(into)] code: String,
        #[builder(into)] state: String,
        #[builder(into)] iss: Option<String>,
        resource: Option<Vec<String>>,
    ) -> Self {
        Self {
            payload: CallbackPayload::Plain(AuthorizationResponse::Success { code, state, iss }),
            resource,
        }
    }

    /// Seeded from a parsed callback; the payload is fixed — only fields the
    /// callback cannot carry are settable.
    #[builder(start_fn(name = seeded, vis = ""), finish_fn(name = build, vis = "pub"), builder_type(vis = "pub", doc {
        /// Builder returned by [`CompleteInput::builder_from_callback`]: the
        /// parsed payload is fixed; only `resource` can be set before `build()`.
    }))]
    fn callback(
        #[builder(start_fn)] payload: CallbackPayload,
        #[builder(setters(vis = "pub"))] resource: Option<Vec<String>>,
    ) -> Self {
        Self { payload, resource }
    }

    /// Parses the authorization-response parameters (RFC 6749 §4.1.2, plus
    /// the RFC 9207 `iss`) into a seeded builder, so fields the callback
    /// cannot carry — the RFC 8707
    /// [`resource`](CompleteInputCallbackBuilder::resource) indicators — can
    /// be set before building.
    ///
    /// Accepts the full callback URL, just its query, or a
    /// `response_mode=form_post` body. Unknown parameters are ignored; a
    /// repeated single-valued parameter is rejected.
    ///
    /// # Errors
    ///
    /// Fails when the parameters cannot be parsed, or `code` or `state` is
    /// missing from a non-error response.
    pub fn builder_from_callback(
        callback: &str,
    ) -> Result<CompleteInputCallbackBuilder, super::ParseCallbackError> {
        use snafu::ResultExt as _;

        use super::error::{InvalidParametersSnafu, ParseCallbackError};

        #[derive(Deserialize)]
        struct CallbackParams {
            code: Option<String>,
            state: Option<String>,
            error: Option<String>,
            error_description: Option<String>,
            iss: Option<String>,
            response: Option<String>,
        }

        // Everything up to the first `?` is the URL/path part; a later raw
        // `?` is query data (RFC 3986) and stays. A trailing fragment is cut
        // — raw `#` cannot appear inside a query, so this is lossless.
        let query = callback.split_once('?').map_or(callback, |(_, q)| q);
        let query = query.split_once('#').map_or(query, |(q, _)| q);
        let params: CallbackParams =
            crate::core::oauth_form::from_str(query).context(InvalidParametersSnafu)?;

        // A JARM `response` JWT carries the whole authorization response
        // (JARM §2.1), so it wins outright; then an OAuth error response
        // takes precedence (RFC 6749 §4.1.2.1) — `error` and `code` are
        // mutually exclusive on the wire.
        let payload = if let Some(response) = params.response {
            CallbackPayload::Jarm { response }
        } else if let Some(error) = params.error {
            CallbackPayload::Plain(AuthorizationResponse::Error {
                error,
                error_description: params.error_description,
                state: params.state,
            })
        } else {
            CallbackPayload::Plain(AuthorizationResponse::Success {
                code: params
                    .code
                    .ok_or(ParseCallbackError::MissingParameter { param: "code" })?,
                state: params
                    .state
                    .ok_or(ParseCallbackError::MissingParameter { param: "state" })?,
                iss: params.iss,
            })
        };

        Ok(Self::seeded(payload))
    }
}

impl std::str::FromStr for CompleteInput {
    type Err = super::ParseCallbackError;

    /// Equivalent to [`builder_from_callback`](Self::builder_from_callback)
    /// followed by `build()`.
    fn from_str(query: &str) -> Result<Self, Self::Err> {
        Ok(Self::builder_from_callback(query)?.build())
    }
}

/// The information needed to be stored from the initial flow setup, for use in the callback.
///
/// The device-authorization flow has a same-named counterpart
/// ([`device_authorization::PendingState`](crate::grant::device_authorization::PendingState)),
/// likewise serializable for persistence and with a redacting [`Debug`].
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PendingState {
    /// The redirect URI.
    ///
    /// In OAuth 2.0, when this is specified at the authorization endpoint, it also needs to be
    /// sent to the token endpoint.
    pub redirect_uri: String,
    /// The PKCE verifier.
    ///
    /// This value is calculated when creating the initial flow, and needs to be sent to the
    /// token endpoint when PKCE is used.
    pub pkce_verifier: Option<String>,
    /// The `state` sent to the authorization endpoint, checked for equality
    /// against the value returned to the callback (CSRF protection).
    pub state: String,
    /// The `nonce` sent to the authorization endpoint, checked against the
    /// `nonce` claim in any returned ID token. `None` when no nonce parameter
    /// was sent (non-`openid` scope, or `send_oidc_nonce` forced off) — the
    /// completion side then skips the nonce check.
    pub nonce: Option<String>,
    /// The thumbprint of the `DPoP` key bound to the request.
    pub dpop_jkt: Option<String>,
    /// Whether the requested scope contained `openid`; completion then
    /// requires an ID token (OIDC Core 1.0 §3.1.3.3). `false` for states
    /// persisted before this field existed.
    #[serde(default)]
    pub openid_requested: bool,
    /// The `response_mode` sent to the authorization endpoint. `None` when no
    /// parameter was sent (including states persisted before this field
    /// existed).
    #[serde(default)]
    pub response_mode: Option<ResponseMode>,
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
            .field("nonce", &self.nonce.as_ref().map(|_| "[REDACTED]"))
            .field("dpop_jkt", &self.dpop_jkt)
            .field("openid_requested", &self.openid_requested)
            .field("response_mode", &self.response_mode)
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
    use rstest::rstest;

    use super::*;

    #[test]
    fn max_age_serializes_as_seconds() {
        let payload = AuthorizationPayload {
            response_type: "code",
            redirect_uri: "http://127.0.0.1/cb",
            scope: Some("openid".into()),
            state: "state",
            code_challenge: None,
            code_challenge_method: None,
            dpop_jkt: None,
            nonce: None,
            response_mode: None,
            display: None,
            prompt: None,
            max_age: Some(300),
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            resource: None,
            authorization_details: None,
        };

        let form = crate::core::oauth_form::to_string(&payload).unwrap();
        assert!(
            form.contains("max_age=300"),
            "max_age must be a number of seconds (OIDC Core §3.1.2.1), got: {form}"
        );
    }

    /// State persisted by versions where `nonce` was a plain string must
    /// still deserialize (in-flight flows across an upgrade).
    #[test]
    fn pending_state_old_format_deserializes() {
        let old = r#"{
            "redirect_uri": "http://127.0.0.1/cb",
            "pkce_verifier": "v",
            "state": "s",
            "nonce": "n",
            "dpop_jkt": null
        }"#;
        let state: PendingState = serde_json::from_str(old).unwrap();
        assert_eq!(state.nonce.as_deref(), Some("n"));
    }

    #[test]
    fn pending_state_response_mode_round_trips() {
        let state = PendingState {
            redirect_uri: "http://127.0.0.1/cb".to_owned(),
            pkce_verifier: None,
            state: "s".to_owned(),
            nonce: None,
            dpop_jkt: None,
            openid_requested: false,
            response_mode: Some(ResponseMode::QueryJwt),
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains(r#""response_mode":"query.jwt""#), "{json}");
        let back: PendingState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.response_mode, Some(ResponseMode::QueryJwt));
    }

    /// Asserts the payload is a plain success response and returns its parts.
    #[track_caller]
    fn success_parts(input: &CompleteInput) -> (&str, &str, Option<&str>) {
        match &input.payload {
            CallbackPayload::Plain(AuthorizationResponse::Success { code, state, iss }) => {
                (code, state, iss.as_deref())
            }
            other => panic!("expected a plain success payload, got {other:?}"),
        }
    }

    // The URL part before the first `?` is discarded and the fragment cut.
    #[rstest]
    #[case::query_with_iss(
        "code=abc&state=xyz&iss=https%3A%2F%2Fissuer.example.com",
        Some("https://issuer.example.com")
    )]
    #[case::leading_question_mark("?code=abc&state=xyz", None)]
    #[case::full_url_with_fragment("https://app.example.com/cb?code=abc&state=xyz#fragment", None)]
    fn complete_input_parses_accepted_shapes(#[case] input: &str, #[case] iss: Option<&str>) {
        let parsed: CompleteInput = input.parse().unwrap();
        assert_eq!(success_parts(&parsed), ("abc", "xyz", iss));
    }

    #[test]
    fn complete_input_builder_from_callback_carries_resource() {
        let input = CompleteInput::builder_from_callback("code=abc&state=xyz")
            .unwrap()
            .resource(bon::vec!["https://api.example.com"])
            .build();
        assert_eq!(success_parts(&input).0, "abc");
        assert_eq!(
            input.resource,
            Some(vec!["https://api.example.com".to_owned()])
        );
    }

    #[test]
    fn complete_input_builder_produces_success_payload() {
        let input = CompleteInput::builder()
            .code("abc")
            .state("xyz")
            .iss("https://issuer.example.com")
            .build();
        assert_eq!(
            success_parts(&input),
            ("abc", "xyz", Some("https://issuer.example.com"))
        );
        assert!(input.resource.is_none());
    }

    /// An OAuth error response parses successfully (surfacing happens at
    /// completion), and takes precedence over any success parameters
    /// (RFC 6749 §4.1.2.1).
    #[test]
    fn complete_input_parse_error_response_takes_precedence() {
        let parsed = "code=abc&state=xyz&error=access_denied&error_description=user+denied"
            .parse::<CompleteInput>()
            .unwrap();
        assert!(
            matches!(
                &parsed.payload,
                // `state` is kept so completion can bind the error to the flow.
                CallbackPayload::Plain(AuthorizationResponse::Error { error, error_description, state })
                    if error == "access_denied"
                        && error_description.as_deref() == Some("user denied")
                        && state.as_deref() == Some("xyz")
            ),
            "got {:?}",
            parsed.payload
        );
    }

    /// A JARM `response` JWT parses into its own payload shape, unverified,
    /// and wins over any plain parameters alongside it (JARM §2.1).
    #[test]
    fn complete_input_parses_jarm_response() {
        let parsed: CompleteInput = "code=abc&state=xyz&response=header.body.sig"
            .parse()
            .unwrap();
        assert!(matches!(
            &parsed.payload,
            CallbackPayload::Jarm { response } if response == "header.body.sig"
        ));
    }

    #[rstest]
    #[case::missing_code("state=xyz", "code")]
    #[case::missing_state("code=abc", "state")]
    fn complete_input_parse_missing_parameter_rejected(#[case] input: &str, #[case] missing: &str) {
        let err = input.parse::<CompleteInput>().unwrap_err();
        assert!(matches!(
            &err,
            super::super::ParseCallbackError::MissingParameter { param } if *param == missing
        ));
    }

    #[test]
    fn complete_input_parse_duplicate_parameter_rejected() {
        // A repeated single-valued parameter is rejected (RFC 6749 §3.1),
        // rather than silently taking one value.
        let err = "code=abc&state=xyz&state=zzz"
            .parse::<CompleteInput>()
            .unwrap_err();
        assert!(matches!(
            &err,
            super::super::ParseCallbackError::InvalidParameters { .. }
        ));
    }

    #[test]
    fn pending_state_debug_redacts_secrets() {
        let state = PendingState {
            redirect_uri: "http://127.0.0.1/cb".to_owned(),
            pkce_verifier: Some("super-secret-verifier".to_owned()),
            state: "csrf-state-value".to_owned(),
            nonce: Some("id-token-nonce".to_owned()),
            dpop_jkt: Some("jkt-thumbprint".to_owned()),
            openid_requested: true,
            response_mode: Some(ResponseMode::QueryJwt),
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
