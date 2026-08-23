//! Error classification and `WWW-Authenticate` challenge metadata.
//!
//! These attributes (error, `error_description`) are used by both the
//! `Bearer` (RFC 6750) and `DPoP` (RFC 9449) authentication schemes.
//! The `error_uri` attribute is supported as a parameter to
//! [`crate::validator::metadata::ValidatorMetadata::challenges`].
//!
//! [`TokenValidationError`] classifies a validation failure as either a client-side
//! error (include RFC 6750 error details in the response) or a server-side error
//! (respond with a status code, no error details).

use std::borrow::Cow;

use crate::{TokenType, core::platform::MaybeSendSync, validator::observe::ValidationOutcome};

/// Escapes a value for safe inclusion in an HTTP quoted-string (RFC 9110 §5.6.4).
///
/// Double-quotes and backslashes are backslash-escaped. Control characters other
/// than HTAB cannot appear in a quoted-string and would break header framing, so
/// they are stripped. All other characters — including non-ASCII `obs-text` —
/// pass through unchanged. The common (clean) case borrows without allocating.
pub(crate) fn escape_quoted(s: &str) -> Cow<'_, str> {
    let needs_work = s
        .chars()
        .any(|c| c == '"' || c == '\\' || (c.is_control() && c != '\t'));
    if !needs_work {
        return Cow::Borrowed(s);
    }

    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            // Control characters (except HTAB) are invalid in a quoted-string and
            // would break header framing; drop them rather than emit them.
            c if c.is_control() && c != '\t' => {}
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// Returns `true` if `c` is a valid HTTP `token` character (RFC 9110 §5.6.2).
fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

/// A parameter for a `WWW-Authenticate` challenge.
///
/// Stored in [`Challenge::params`] so values can be formatted and sanitized for
/// the challenge field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeParam {
    /// A quoted-string parameter: `key="value"`.
    ///
    /// The value is sanitized per RFC 9110 §5.6.4 when formatted: backslashes and
    /// double-quotes are backslash-escaped, and control characters (other than
    /// HTAB) are stripped, so the value cannot break header framing.
    Quoted(&'static str, String),
    /// An unquoted token parameter: `key=value`.
    ///
    /// The value should be a valid HTTP token (RFC 9110 §5.6.2). Because an
    /// unquoted value cannot be escaped, any non-token characters are stripped
    /// when formatted.
    Token(&'static str, String),
}

impl ChallengeParam {
    /// Formats this parameter as a `key=value` or `key="escaped-value"` string.
    ///
    /// Values are sanitized so the result is always a valid challenge parameter
    /// regardless of input (see the variant docs).
    #[must_use]
    pub fn format(&self) -> String {
        match self {
            Self::Quoted(key, value) => format!(r#"{}="{}""#, key, escape_quoted(value)),
            Self::Token(key, value) => {
                let value: String = value.chars().filter(|c| is_tchar(*c)).collect();
                format!("{key}={value}")
            }
        }
    }
}

/// An HTTP 5xx status for a server-side validation failure.
///
/// [`TokenValidationError::Server`] accepts this type so a server-side failure
/// cannot accidentally produce a success or client-error status. Construct an
/// arbitrary 5xx with [`new`](Self::new), or use one of the provided constants.
/// See [the error model](crate::_docs::explanation::error_handling).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerStatus(http::StatusCode);

impl ServerStatus {
    /// HTTP 500 Internal Server Error.
    pub const INTERNAL_SERVER_ERROR: Self = Self(http::StatusCode::INTERNAL_SERVER_ERROR);
    /// HTTP 502 Bad Gateway.
    pub const BAD_GATEWAY: Self = Self(http::StatusCode::BAD_GATEWAY);
    /// HTTP 503 Service Unavailable.
    pub const SERVICE_UNAVAILABLE: Self = Self(http::StatusCode::SERVICE_UNAVAILABLE);

    /// Returns the status wrapped as a [`ServerStatus`] if it is in the 5xx
    /// range, or `None` otherwise.
    #[must_use]
    pub fn new(status: http::StatusCode) -> Option<Self> {
        status.is_server_error().then_some(Self(status))
    }

    /// Returns the wrapped HTTP status.
    #[must_use]
    pub fn get(self) -> http::StatusCode {
        self.0
    }
}

impl From<ServerStatus> for http::StatusCode {
    fn from(status: ServerStatus) -> Self {
        status.get()
    }
}

impl std::fmt::Display for ServerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Response metadata contributed by a [`ToRfc6750Error`].
///
/// Client errors are rendered into `WWW-Authenticate` attributes. Server
/// errors instead provide a status and optional retry interval.
///
/// [`ValidatorMetadata::challenges`]: crate::validator::metadata::ValidatorMetadata::challenges
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Whether the failure is client-side or server-side, and its response status.
    pub error: TokenValidationError,
    /// The RFC 6750 `error_description` attribute for a client error.
    ///
    /// Ignored for server-side errors.
    pub description: Option<String>,
    /// Additional challenge attributes, such as RFC 9470 `acr_values` and
    /// `max_age`.
    ///
    /// Values are formatted and sanitized according to their [`ChallengeParam`]
    /// variant. Ignored for server-side errors.
    pub params: Vec<ChallengeParam>,
    /// The RFC 6750 §3 `scope` attribute naming the required scope.
    ///
    /// When set, this takes precedence over the fallback scope passed to
    /// [`ValidatorMetadata::challenges`](crate::validator::metadata::ValidatorMetadata::challenges).
    pub scope: Option<String>,
}

impl Challenge {
    /// Creates response metadata with no description, extra parameters, or scope.
    #[must_use]
    pub fn new(error: TokenValidationError) -> Self {
        Self {
            error,
            description: None,
            params: Vec::new(),
            scope: None,
        }
    }

    /// Sets the RFC 6750 `error_description` attribute.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets additional challenge attributes.
    #[must_use]
    pub fn with_params(mut self, params: Vec<ChallengeParam>) -> Self {
        self.params = params;
        self
    }

    /// Sets the RFC 6750 `scope` attribute required by the resource.
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }
}

/// Classifies a token validation failure for an HTTP rejection response.
///
/// Client errors produce the status associated with their [`TokenErrorCode`]
/// and may include RFC 6750 error details in `WWW-Authenticate`. Server errors
/// produce the specified 5xx status, omit `WWW-Authenticate`, and may produce a
/// `Retry-After` header through [`Rejection`](crate::rejection::Rejection).
/// See [the error model](crate::_docs::explanation::error_handling).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenValidationError {
    /// A client-side request or token error.
    ///
    /// The code determines the HTTP status and is included in the attempted
    /// scheme's `WWW-Authenticate` challenge.
    Client(TokenErrorCode),
    /// A server-side failure for which no token verdict was produced.
    ///
    /// Respond with the supplied 5xx status and no `WWW-Authenticate` header.
    Server {
        /// The status to respond with, as a [`ServerStatus`].
        status: ServerStatus,
        /// The delay emitted as `Retry-After`, if known.
        ///
        /// `None` omits the header; it does not mean retry immediately.
        retry_after: Option<crate::core::platform::Duration>,
    },
}

impl TokenValidationError {
    /// Creates a server-side failure with no `Retry-After` interval.
    #[must_use]
    pub fn server(status: ServerStatus) -> Self {
        Self::Server {
            status,
            retry_after: None,
        }
    }

    /// Returns the HTTP status code for the rejection response.
    #[must_use]
    pub fn suggested_status(&self) -> http::StatusCode {
        match self {
            Self::Client(code) => code.suggested_status(),
            Self::Server { status, .. } => status.get(),
        }
    }

    /// Returns the server-provided retry interval.
    ///
    /// Client errors always return `None`.
    #[must_use]
    pub fn retry_after(&self) -> Option<crate::core::platform::Duration> {
        match self {
            Self::Client(_) => None,
            Self::Server { retry_after, .. } => *retry_after,
        }
    }
}

/// RFC 6750 §3.1 error codes for resource server responses.
///
/// Most variants are returned directly by this library's validators. [`Self::InsufficientScope`]
/// and [`Self::InsufficientUserAuthentication`] are application-level decisions — use
/// [`InsufficientScope`] and [`InsufficientUserAuthentication`] respectively to build
/// `WWW-Authenticate` responses for those cases.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    strum::IntoStaticStr,
    strum::AsRefStr,
    strum::Display,
    strum::EnumString,
)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
// Tests compare this count with their table of emitted codes.
#[cfg_attr(test, derive(strum::EnumCount))]
pub enum TokenErrorCode {
    /// The request is malformed. Respond with HTTP 400.
    InvalidRequest,
    /// The access token is invalid, expired, or revoked. Respond with HTTP 401.
    InvalidToken,
    /// The token has insufficient scope for the requested resource. Respond with HTTP 403.
    InsufficientScope,
    /// The `DPoP` proof is invalid. Respond with HTTP 401 (RFC 9449).
    // `snake_case` would mangle the `DPoP` acronym, so spell it out.
    #[strum(serialize = "invalid_dpop_proof")]
    InvalidDPoPProof,
    /// A `DPoP` nonce is required. Respond with HTTP 401 (RFC 9449).
    #[strum(serialize = "use_dpop_nonce")]
    UseDPoPNonce,
    /// The token was obtained with insufficient user authentication strength.
    /// Respond with HTTP 401 (RFC 9470).
    InsufficientUserAuthentication,
}

impl TokenErrorCode {
    /// The error code string as defined in RFC 6750 §3.1 or RFC 9449 §7.1.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.into()
    }

    /// The suggested HTTP status code.
    #[must_use]
    pub fn suggested_status(&self) -> http::StatusCode {
        match self {
            Self::InvalidRequest => http::StatusCode::BAD_REQUEST,
            Self::InvalidToken
            | Self::InvalidDPoPProof
            | Self::UseDPoPNonce
            | Self::InsufficientUserAuthentication => http::StatusCode::UNAUTHORIZED,
            Self::InsufficientScope => http::StatusCode::FORBIDDEN,
        }
    }
}

/// An application-level error for tokens that lack the required scope.
///
/// Implements [`ToRfc6750Error`] so it can be passed to
/// [`crate::validator::metadata::ValidatorMetadata::challenges`] (or the
/// assembled [`rejection`](crate::validator::metadata::ValidatorMetadata::rejection))
/// when building a `WWW-Authenticate` response for an insufficient-scope
/// rejection.
///
/// Construct with [`new`](Self::new) so the challenge tells the client which
/// scope it was missing (RFC 6750 §3 `scope` attribute); use
/// [`InsufficientScope::default()`] only when the required scope should not
/// be disclosed.
#[derive(Debug, Clone, Default)]
pub struct InsufficientScope {
    /// The scope required to access the resource, as a space-separated list
    /// (RFC 6750 §3). Emitted as the challenge `scope` attribute.
    pub scope: Option<String>,
}

impl InsufficientScope {
    /// An insufficient-scope rejection naming the `scope` the resource requires.
    #[must_use]
    pub fn new(scope: impl Into<String>) -> Self {
        Self {
            scope: Some(scope.into()),
        }
    }
}

impl std::fmt::Display for InsufficientScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the access token has insufficient scope")?;
        if let Some(scope) = &self.scope {
            write!(f, " (requires {scope})")?;
        }
        Ok(())
    }
}

impl std::error::Error for InsufficientScope {}

impl ToRfc6750Error for InsufficientScope {
    fn attempted_scheme(&self) -> Option<TokenType> {
        None
    }

    fn challenge(&self) -> Challenge {
        let challenge = Challenge::new(TokenValidationError::Client(
            TokenErrorCode::InsufficientScope,
        ))
        .with_description("The access token has insufficient scope for the requested resource");
        match &self.scope {
            Some(scope) => challenge.with_scope(scope.clone()),
            None => challenge,
        }
    }
}

/// An application-level error for tokens obtained with insufficient authentication strength.
///
/// Implements [`ToRfc6750Error`] so it can be passed to
/// [`crate::validator::metadata::ValidatorMetadata::challenges`] when building
/// a `WWW-Authenticate` response per RFC 9470 (Step Up Authentication Challenge Protocol).
///
/// Set `acr_values` and/or `max_age` to include the corresponding RFC 9470 challenge parameters.
#[derive(Debug, Clone, Default)]
pub struct InsufficientUserAuthentication {
    /// The required Authentication Context Class Reference values (RFC 9470 §2).
    pub acr_values: Option<String>,
    /// The maximum acceptable authentication age in seconds (RFC 9470 §2).
    pub max_age: Option<u64>,
}

impl std::fmt::Display for InsufficientUserAuthentication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the access token was obtained with insufficient user authentication")?;
        if let Some(acr) = &self.acr_values {
            write!(f, " (requires acr_values {acr})")?;
        }
        if let Some(max_age) = self.max_age {
            write!(f, " (requires max_age {max_age})")?;
        }
        Ok(())
    }
}

impl std::error::Error for InsufficientUserAuthentication {}

impl ToRfc6750Error for InsufficientUserAuthentication {
    fn attempted_scheme(&self) -> Option<TokenType> {
        None
    }

    fn challenge(&self) -> Challenge {
        let mut params = Vec::new();
        if let Some(acr) = &self.acr_values {
            params.push(ChallengeParam::Quoted("acr_values", acr.clone()));
        }
        if let Some(max_age) = self.max_age {
            params.push(ChallengeParam::Token("max_age", max_age.to_string()));
        }
        Challenge::new(TokenValidationError::Client(
            TokenErrorCode::InsufficientUserAuthentication,
        ))
        .with_description("A higher authentication level is required to access this resource")
        .with_params(params)
    }
}

/// Implementation detail of [`forwarding_table!`](crate::forwarding_table).
#[doc(hidden)]
pub mod __forwarding {
    use super::ToRfc6750Error;

    /// Asserts that `wrapped` reports the same challenge as `inner`.
    pub fn assert_forwards(label: &str, inner: &dyn ToRfc6750Error, wrapped: &dyn ToRfc6750Error) {
        assert_eq!(
            inner.challenge(),
            wrapped.challenge(),
            "{label}: the challenge must survive the wrapper whole — a client \
             told it was rejected but not what it was missing is the bug this \
             prevents",
        );
    }
}

/// Asserts a wrapping [`ToRfc6750Error`] reports the [`Challenge`] exactly as
/// the error it wraps.
///
/// Each row contains an inner-error factory and a closure that wraps one. Only
/// the challenge is compared; wrapper-owned context is not.
#[macro_export]
macro_rules! forwarding_table {
    (
        $(#[$attr:meta])*
        $name:ident { $( $inner:expr => $wrap:expr ),+ $(,)? }
    ) => {
        $(#[$attr])*
        #[test]
        fn $name() {
            $({
                let make = $inner;
                let wrap = $wrap;
                $crate::error::__forwarding::assert_forwards(
                    ::std::concat!(::std::stringify!($inner), " wrapped by ", ::std::stringify!($wrap)),
                    &make(),
                    &wrap(make()),
                );
            })+
        }
    };
}

/// Converts a validation error into rejection and observation metadata.
///
/// Implementations provide the client-visible [`Challenge`] separately from
/// contextual metadata such as the attempted authentication scheme, observation
/// outcome, and trusted issuer.
///
/// # Implementing
///
/// An error that wraps another [`ToRfc6750Error`] must return the inner
/// [`Challenge`] unchanged and expose the inner error through
/// [`std::error::Error::source`]. The wrapper should report contextual values
/// itself: the presented scheme, validation stage, and registered issuer may be
/// known only at that layer.
///
/// [`forwarding_table!`](crate::forwarding_table) can verify challenge
/// forwarding in tests.
pub trait ToRfc6750Error: std::error::Error + MaybeSendSync {
    /// Returns the authentication scheme used to present the token, if known.
    ///
    /// This selects which supported challenge receives client error details.
    /// When `None`, the details may be included in both `Bearer` and `DPoP`
    /// challenges.
    fn attempted_scheme(&self) -> Option<TokenType>;

    /// Returns the response metadata contributed by this error.
    fn challenge(&self) -> Challenge;

    /// Classifies this error for [`ObservedValidator`](crate::validator::observe::ObservedValidator).
    ///
    /// The default derives a coarse outcome from [`challenge`](Self::challenge).
    /// Implementations may override it when they can distinguish validation
    /// stages or more specific outcomes.
    fn validation_outcome(&self) -> ValidationOutcome {
        match self.challenge().error {
            TokenValidationError::Client(TokenErrorCode::InvalidRequest) => {
                ValidationOutcome::ExtractError
            }
            TokenValidationError::Client(TokenErrorCode::InvalidDPoPProof) => {
                ValidationOutcome::BindingError
            }
            TokenValidationError::Client(TokenErrorCode::UseDPoPNonce) => {
                ValidationOutcome::NonceRequired
            }
            TokenValidationError::Client(_) => ValidationOutcome::InvalidToken,
            TokenValidationError::Server { .. } => ValidationOutcome::CallError,
        }
    }

    /// The issuer this validation attempt is attributed to, when the validator
    /// knows one that is safe to use as a metrics label — e.g. the registered
    /// issuer a [multi-issuer validator](crate::validator::multi_issuer)
    /// routed to.
    ///
    /// Implementations must return only trusted, bounded values (configured or
    /// registered issuers), never unverified token contents — an attacker could
    /// otherwise mint unbounded label values. Defaults to `None`.
    fn issuer(&self) -> Option<&str> {
        None
    }
}

impl ToRfc6750Error for crate::core::jwt::validator::JwtValidationError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        None
    }

    fn challenge(&self) -> Challenge {
        use crate::core::{crypto::verifier::VerifyError, jwt::validator::JwtValidationError as E};
        let error = match self {
            // These failures prevent validation rather than reject the token.
            E::JtiCheck { .. }
            | E::Signature {
                source: VerifyError::KeysUnavailable,
            } => TokenValidationError::server(ServerStatus::INTERNAL_SERVER_ERROR),
            _ => TokenValidationError::Client(TokenErrorCode::InvalidToken),
        };
        let description = match self {
            // Server failures do not expose token details to the client.
            E::JtiCheck { .. }
            | E::Signature {
                source: VerifyError::KeysUnavailable,
            } => None,
            E::Parse { .. } => Some("The access token is malformed".to_string()),
            E::Signature { .. } => Some("The access token signature is invalid".to_string()),
            E::UnsignedToken => Some("The access token is unsigned".to_string()),
            E::DisallowedAlgorithm { .. } => {
                Some("The access token uses an unsupported signature algorithm".to_string())
            }
            E::UnrecognizedCriticalHeader { .. } => Some(
                "The access token contains unrecognized critical header parameters".to_string(),
            ),
            E::Expired { .. } => Some("The access token expired".to_string()),
            E::NotYetValid { .. } => Some("The access token is not yet valid".to_string()),
            E::IssuedInFuture { .. } => {
                Some("The access token was issued in the future".to_string())
            }
            E::TokenTooOld { .. } => Some("The access token is too old".to_string()),
            E::InvalidTokenType { .. } => Some("The access token type is invalid".to_string()),
            E::ClaimMismatch { claim, .. } => {
                Some(format!("The access token '{claim}' claim is invalid"))
            }
            E::RequiredClaimMissing { claim } => Some(format!(
                "The access token is missing the required '{claim}' claim"
            )),
            E::JtiNotUnique => {
                Some("The access token 'jti' claim value was previously seen".to_string())
            }
            E::ExtraClaims { .. } => {
                Some("The access token does not contain the required claims".to_string())
            }
            E::JtiTooLong { .. } => Some("The access token 'jti' claim is too long".to_string()),
        };
        let challenge = Challenge::new(error);
        match description {
            Some(description) => challenge.with_description(description),
            None => challenge,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shared table of every code emitted by this crate.
    const EMITTED: &[(TokenErrorCode, &str)] = &[
        (TokenErrorCode::InvalidRequest, "invalid_request"),
        (TokenErrorCode::InvalidToken, "invalid_token"),
        (TokenErrorCode::InsufficientScope, "insufficient_scope"),
        (TokenErrorCode::InvalidDPoPProof, "invalid_dpop_proof"),
        (TokenErrorCode::UseDPoPNonce, "use_dpop_nonce"),
        (
            TokenErrorCode::InsufficientUserAuthentication,
            "insufficient_user_authentication",
        ),
    ];

    // The enum count makes this fail when a new variant lacks a table row.
    #[test]
    fn every_code_is_covered_by_the_tables() {
        use strum::EnumCount as _;

        assert_eq!(
            EMITTED.len(),
            TokenErrorCode::COUNT,
            "every variant of `TokenErrorCode` needs a row in `EMITTED` — one was \
             added without a spelling and without a client-side counterpart",
        );
    }

    #[test]
    fn token_error_code_str_roundtrip() {
        for (code, s) in EMITTED {
            assert_eq!(code.as_str(), *s);
            assert_eq!(code.to_string(), *s, "Display matches the RFC code");
            assert_eq!(&s.parse::<TokenErrorCode>().unwrap(), code);
        }
        // Unknown codes are rejected.
        assert!("not_a_code".parse::<TokenErrorCode>().is_err());
    }

    // Every emitted code must have a named client-side representation.
    #[test]
    fn every_emitted_code_is_typed_on_the_client_side() {
        use crate::core::OAuthErrorCode;

        for (code, _) in EMITTED {
            let parsed = OAuthErrorCode::from(code.as_str());
            assert!(
                !matches!(parsed, OAuthErrorCode::Other(_)),
                "{code} reaches a client untyped",
            );
            assert_eq!(parsed.as_str(), code.as_str(), "{code}");
        }
    }

    // Unavailable keys prevent validation and therefore produce a server error.
    #[test]
    fn keys_unavailable_is_a_server_error_not_invalid_token() {
        use crate::core::{crypto::verifier::VerifyError, jwt::validator::JwtValidationError};

        let err = JwtValidationError::Signature {
            source: VerifyError::KeysUnavailable,
        };
        assert!(matches!(
            err.challenge().error,
            TokenValidationError::Server {
                status: ServerStatus::INTERNAL_SERVER_ERROR,
                retry_after: None,
            }
        ));
        assert_eq!(err.challenge().description, None);
        assert_eq!(err.validation_outcome(), ValidationOutcome::CallError);
    }

    // A checked signature mismatch remains an invalid-token client error.
    #[test]
    fn signature_mismatch_remains_invalid_token() {
        use crate::core::{crypto::verifier::VerifyError, jwt::validator::JwtValidationError};

        let err = JwtValidationError::Signature {
            source: VerifyError::SignatureMismatch,
        };
        assert!(matches!(
            err.challenge().error,
            TokenValidationError::Client(TokenErrorCode::InvalidToken)
        ));
        assert_eq!(err.validation_outcome(), ValidationOutcome::InvalidToken);
    }

    // Server statuses cannot contain success or redirection codes.
    #[test]
    fn a_server_status_cannot_fail_open() {
        assert_eq!(ServerStatus::new(http::StatusCode::default()), None);
        for status in [200, 201, 204, 301, 302, 304] {
            let status = http::StatusCode::from_u16(status).expect("a real status");
            assert_eq!(ServerStatus::new(status), None, "{status}");
        }
    }

    // Client-error statuses cannot be represented as server failures.
    #[test]
    fn a_server_status_cannot_be_a_client_error() {
        for status in [400, 401, 403, 404, 429] {
            let status = http::StatusCode::from_u16(status).expect("a real status");
            assert_eq!(ServerStatus::new(status), None, "{status}");
        }
    }

    // Any 5xx status is accepted, including those without named constants here.
    #[test]
    fn every_server_error_status_round_trips() {
        for status in [500, 501, 502, 503, 504, 507] {
            let status = http::StatusCode::from_u16(status).expect("a real status");
            let wrapped = ServerStatus::new(status).expect("a 5xx");
            assert_eq!(wrapped.get(), status);
            assert_eq!(http::StatusCode::from(wrapped), status);
        }
        for named in [
            ServerStatus::INTERNAL_SERVER_ERROR,
            ServerStatus::BAD_GATEWAY,
            ServerStatus::SERVICE_UNAVAILABLE,
        ] {
            assert!(named.get().is_server_error(), "{named}");
            assert_eq!(ServerStatus::new(named.get()), Some(named));
        }
    }

    // No validation failure may suggest a successful response status.
    #[test]
    fn no_classification_suggests_a_success_status() {
        let mut cases: Vec<TokenValidationError> = EMITTED
            .iter()
            .map(|(code, _)| TokenValidationError::Client(*code))
            .collect();
        cases.extend([
            TokenValidationError::server(ServerStatus::INTERNAL_SERVER_ERROR),
            TokenValidationError::server(ServerStatus::BAD_GATEWAY),
            TokenValidationError::Server {
                status: ServerStatus::SERVICE_UNAVAILABLE,
                retry_after: Some(crate::core::platform::Duration::from_secs(30)),
            },
        ]);

        for case in cases {
            let status = case.suggested_status();
            assert!(
                status.is_client_error() || status.is_server_error(),
                "{case:?} suggests {status}, which does not reject anything",
            );
        }
    }

    #[test]
    fn escape_quoted_escapes_quote_and_backslash() {
        assert_eq!(escape_quoted(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn escape_quoted_clean_input_is_borrowed() {
        assert!(matches!(escape_quoted("clean value"), Cow::Borrowed(_)));
    }

    #[test]
    fn escape_quoted_strips_control_chars_but_keeps_tab_and_unicode() {
        // CR/LF and other controls are removed (no header-framing injection);
        // HTAB and non-ASCII obs-text survive.
        let out = escape_quoted("a\r\nb\u{0007}c\td\u{00e9}");
        assert_eq!(out, "abc\td\u{00e9}");
        assert!(!out.contains(['\r', '\n']));
    }

    #[test]
    fn token_param_strips_non_token_chars() {
        // A valid token is unchanged.
        assert_eq!(
            ChallengeParam::Token("max_age", "60".to_string()).format(),
            "max_age=60"
        );
        // An injection attempt via a Token value cannot split the header.
        let injected = ChallengeParam::Token("max_age", "1\r\n2".to_string()).format();
        assert_eq!(injected, "max_age=12");
        assert!(!injected.contains(['\r', '\n']));
    }
}
