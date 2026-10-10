//! Route credentials by a case-sensitive token-value prefix, with an optional fallback.
//!
//! [`PrefixRoutingValidator`] selects a branch by the credential's prefix, not
//! the authentication scheme, and forwards the original request unchanged.
//! Branches must use the same token header and validate the full credential,
//! scheme, and sender constraints. The router does not decode or authenticate it.
//!
//! Matching token headers is a correctness requirement, including for the
//! fallback. Otherwise, routing may select a branch using one credential while
//! that branch authenticates another. The router cannot detect this when the
//! branch returns successful validation; [`PrefixRoutingError::MissingValidation`]
//! catches only cases where the selected branch reports no credential.
//!
//! Tokens must use the Bearer or DPoP authentication scheme. Other schemes
//! produce `invalid_request` before routing. The selected validator enforces
//! its own scheme and sender-constraint requirements. Unmatched credentials
//! without a fallback produce `invalid_token`.
//!
//! Every branch requires a label, reported on routed failures through
//! [`PrefixRoutingError`]. Unmatched credentials have no branch label.
//!
//! See the [prefix routing guide](crate::_docs::guide::prefix_routing) for
//! configuration and the [error model](crate::_docs::explanation::error_handling)
//! for failure handling.

use http::{HeaderName, header::AUTHORIZATION};
use snafu::{IntoError as _, prelude::*};

use crate::{
    core::platform::{MaybeSendBoxFuture, MaybeSendSync},
    error::{Challenge, ServerStatus, ToRfc6750Error, TokenErrorCode, TokenValidationError},
    validator::{
        AccessTokenValidator, ValidationResult,
        extract::{TokenExtractError, TokenType, extract_token},
        metadata::{ProvideValidatorMetadata, ValidatorMetadata, union_metadata},
        observe::ValidationOutcome,
    },
};

/// Invalid prefix routing configuration.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PrefixRoutingBuildError {
    /// Empty prefixes would match everything; configure a fallback instead.
    #[snafu(display("an empty token prefix is not allowed; use a fallback"))]
    EmptyPrefix,
    /// Each prefix must have exactly one registered validator.
    #[snafu(display("duplicate token prefix {prefix:?}"))]
    DuplicatePrefix {
        /// The duplicated configuration value, not a presented credential.
        prefix: String,
    },
    /// One registered prefix starts with another, making routing ambiguous.
    #[snafu(display("overlapping token prefixes {prefix:?} and {other:?}"))]
    OverlappingPrefixes {
        /// One of the overlapping configuration values.
        prefix: String,
        /// The other overlapping configuration value.
        other: String,
    },
}

/// Extraction, routing, or selected-validator failure.
///
/// Routing failures do not include the presented token value. Inner errors
/// retain their challenge, classification, issuer, and source chain; custom
/// validators are responsible for keeping secrets out of those errors.
/// For nested prefix routers, [`ToRfc6750Error::branch_label`] returns the
/// outer selected branch's label. Inner labels remain available through the
/// error source chain; labels are not concatenated.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PrefixRoutingError {
    /// The request did not contain a well-formed token presentation.
    #[snafu(display("token presentation error"))]
    #[non_exhaustive]
    Extract {
        /// The extraction failure.
        source: TokenExtractError,
    },
    /// No prefix matched and no fallback was configured.
    #[snafu(display("no validator matches the access token"))]
    #[non_exhaustive]
    Unmatched {
        /// The scheme used to present the credential.
        scheme: TokenType,
    },
    /// The selected validator failed; no other branch is attempted.
    #[snafu(display("routed token validation error"))]
    #[non_exhaustive]
    Validation {
        /// The configured label of the selected branch.
        label: String,
        /// The original validation error.
        #[snafu(source)]
        error: Box<dyn ToRfc6750Error>,
    },
    /// A selected validator reported no credential after the router found one.
    ///
    /// Usually indicates that the branch and router use different token headers.
    /// A mismatch is not detected if the branch successfully validates a
    /// credential from a different header.
    #[snafu(display(
        "selected validator did not validate the presented credential; check token header configuration"
    ))]
    #[non_exhaustive]
    MissingValidation {
        /// The configured label of the selected branch.
        label: String,
        /// The scheme the router extracted from the presented credential.
        scheme: TokenType,
    },
}

impl ToRfc6750Error for PrefixRoutingError {
    fn challenge(&self) -> Challenge {
        match self {
            Self::Extract { source } => source.challenge(),
            Self::Unmatched { .. } => {
                Challenge::new(TokenValidationError::Client(TokenErrorCode::InvalidToken))
                    .with_description("The access token is not recognized")
            }
            Self::Validation { error, .. } => error.challenge(),
            Self::MissingValidation { .. } => Challenge::new(TokenValidationError::server(
                ServerStatus::INTERNAL_SERVER_ERROR,
            )),
        }
    }

    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            Self::Extract { source } => source.attempted_scheme(),
            Self::Unmatched { scheme } | Self::MissingValidation { scheme, .. } => Some(*scheme),
            Self::Validation { error, .. } => error.attempted_scheme(),
        }
    }

    fn validation_outcome(&self, challenge: &Challenge) -> ValidationOutcome {
        match self {
            Self::Extract { source } => source.validation_outcome(challenge),
            Self::Unmatched { .. } => ValidationOutcome::InvalidToken,
            Self::Validation { error, .. } => error.validation_outcome(challenge),
            Self::MissingValidation { .. } => ValidationOutcome::CallError,
        }
    }

    fn issuer(&self) -> Option<&str> {
        match self {
            Self::Validation { error, .. } => error.issuer(),
            Self::Extract { .. } | Self::Unmatched { .. } | Self::MissingValidation { .. } => None,
        }
    }

    fn branch_label(&self) -> Option<&str> {
        match self {
            Self::Validation { label, .. } | Self::MissingValidation { label, .. } => Some(label),
            Self::Extract { .. } | Self::Unmatched { .. } => None,
        }
    }
}

struct Branch<C> {
    label: String,
    validator: Box<dyn AccessTokenValidator<Claims = C, Error = PrefixRoutingError>>,
    metadata: ValidatorMetadata,
}

impl<C: MaybeSendSync + 'static> Branch<C> {
    fn new<V>(label: String, validator: V) -> Self
    where
        V: AccessTokenValidator<Claims = C> + ProvideValidatorMetadata + 'static,
        V::Error: 'static,
    {
        Self {
            label: label.clone(),
            metadata: validator.validator_metadata(None),
            validator: Box::new(AdaptError {
                label,
                inner: validator,
            }),
        }
    }
}

struct AdaptError<V> {
    label: String,
    inner: V,
}

impl<V: AccessTokenValidator> AccessTokenValidator for AdaptError<V>
where
    V::Error: 'static,
{
    type Claims = V::Claims;
    type Error = PrefixRoutingError;

    fn validate_request<'a>(
        &'a self,
        headers: &'a http::HeaderMap,
        method: &'a http::Method,
        uri: &'a http::Uri,
        client_cert_der: Option<&'a [u8]>,
    ) -> MaybeSendBoxFuture<'a, ValidationResult<Self::Claims, Self::Error>> {
        Box::pin(async move {
            let result = self
                .inner
                .validate_request(headers, method, uri, client_cert_der)
                .await;
            ValidationResult {
                outcome: result.outcome.map_err(|error| {
                    ValidationSnafu {
                        label: self.label.clone(),
                    }
                    .into_error(Box::new(error))
                }),
                dpop_nonce: result.dpop_nonce,
            }
        })
    }
}

/// Routes credentials by prefix. See the [module documentation](self) for routing rules.
///
/// Metadata is the union of branch capabilities, captured with
/// `validator_metadata(None)` at registration. Later queries replace only
/// `resource`; branch metadata is not recomputed. Challenges use this union.
pub struct PrefixRoutingValidator<C> {
    routes: Vec<(String, Branch<C>)>,
    fallback: Option<Branch<C>>,
    token_header: HeaderName,
    metadata: ValidatorMetadata,
}

#[bon::bon]
impl<C: MaybeSendSync + 'static> PrefixRoutingValidator<C> {
    /// Builds a router with zero or more prefixes and an optional fallback.
    ///
    /// Use [`prefix`](PrefixRoutingValidatorBuilder::prefix) to register
    /// branches and [`fallback`](PrefixRoutingValidatorBuilder::fallback) for
    /// credentials that do not match any prefix.
    ///
    /// # Errors
    ///
    /// Rejects empty, duplicate, or overlapping prefixes.
    #[builder]
    pub fn new(
        /// Validators registered through the builder's `prefix` method.
        #[builder(field)]
        routes: Vec<(String, Branch<C>)>,
        /// Optional validator registered through the builder's `fallback` method.
        #[builder(setters(name = "fallback_internal", vis = ""))]
        fallback: Option<Branch<C>>,
        /// Header containing `<scheme> <token>`; all branches must use it too.
        #[builder(default = AUTHORIZATION)]
        token_header: HeaderName,
    ) -> Result<Self, PrefixRoutingBuildError> {
        let mut prefixes = std::collections::HashSet::new();
        for (prefix, _) in &routes {
            ensure!(!prefix.is_empty(), EmptyPrefixSnafu);
            ensure!(prefixes.insert(prefix), DuplicatePrefixSnafu { prefix });
        }
        for (index, (prefix, _)) in routes.iter().enumerate() {
            for (other, _) in &routes[..index] {
                ensure!(
                    !prefix.starts_with(other) && !other.starts_with(prefix),
                    OverlappingPrefixesSnafu { prefix, other }
                );
            }
        }
        let metadata = union_metadata(
            routes
                .iter()
                .map(|(_, branch)| branch.metadata.clone())
                .chain(fallback.iter().map(|branch| branch.metadata.clone())),
            None,
        );
        Ok(Self {
            routes,
            fallback,
            token_header,
            metadata,
        })
    }

    /// Validates using exactly one branch, preserving the original request.
    ///
    /// Absent credentials return `Ok(None)`; malformed presentations fail before
    /// routing. A selected branch's result is final. Its `Ok(None)` becomes
    /// [`PrefixRoutingError::MissingValidation`], a server-side integration error.
    ///
    /// `uri` and `client_cert_der` follow [`AccessTokenValidator::validate_request`].
    pub async fn validate_request(
        &self,
        headers: &http::HeaderMap,
        method: &http::Method,
        uri: &http::Uri,
        client_cert_der: Option<&[u8]>,
    ) -> ValidationResult<C, PrefixRoutingError> {
        let (scheme, token) = match extract_token(headers, &self.token_header).context(ExtractSnafu)
        {
            Ok(Some(token)) => token,
            Ok(None) => {
                return ValidationResult {
                    outcome: Ok(None),
                    dpop_nonce: None,
                };
            }
            Err(error) => {
                return ValidationResult {
                    outcome: Err(error),
                    dpop_nonce: None,
                };
            }
        };
        let selected = self
            .routes
            .iter()
            .find(|(prefix, _)| token.expose_secret().starts_with(prefix))
            .map(|(_, branch)| branch)
            .or(self.fallback.as_ref());
        if let Some(branch) = selected {
            let mut result = branch
                .validator
                .validate_request(headers, method, uri, client_cert_der)
                .await;
            if matches!(result.outcome, Ok(None)) {
                result.outcome = MissingValidationSnafu {
                    label: branch.label.clone(),
                    scheme,
                }
                .fail();
            }
            result
        } else {
            ValidationResult {
                outcome: UnmatchedSnafu { scheme }.fail(),
                dpop_nonce: None,
            }
        }
    }
}

impl<C: MaybeSendSync + 'static, S: prefix_routing_validator_builder::State>
    PrefixRoutingValidatorBuilder<C, S>
{
    /// Registers a case-sensitive token prefix with a failure observation label.
    ///
    /// Empty, duplicate, and overlapping prefixes are rejected by `build`.
    /// Branches must use the router's token header and claims type. Labels need
    /// not be unique; they identify routed failures independently of issuers.
    pub fn prefix<V>(
        mut self,
        prefix: impl Into<String>,
        label: impl Into<String>,
        validator: V,
    ) -> Self
    where
        V: AccessTokenValidator<Claims = C> + ProvideValidatorMetadata + 'static,
        V::Error: 'static,
    {
        self.routes
            .push((prefix.into(), Branch::new(label.into(), validator)));
        self
    }

    /// Sets the optional validator for unmatched credentials once, with a label.
    ///
    /// It is never called after a matched validator rejects a credential, nor
    /// for absent or malformed token presentations. The label identifies routed
    /// failures and may be shared with prefix branches for metrics aggregation.
    pub fn fallback<V>(
        self,
        label: impl Into<String>,
        validator: V,
    ) -> PrefixRoutingValidatorBuilder<C, prefix_routing_validator_builder::SetFallback<S>>
    where
        S::Fallback: prefix_routing_validator_builder::IsUnset,
        V: AccessTokenValidator<Claims = C> + ProvideValidatorMetadata + 'static,
        V::Error: 'static,
    {
        self.fallback_internal(Branch::new(label.into(), validator))
    }
}

impl<C: MaybeSendSync + 'static> AccessTokenValidator for PrefixRoutingValidator<C> {
    type Claims = C;
    type Error = PrefixRoutingError;

    fn validate_request<'a>(
        &'a self,
        headers: &'a http::HeaderMap,
        method: &'a http::Method,
        uri: &'a http::Uri,
        client_cert_der: Option<&'a [u8]>,
    ) -> MaybeSendBoxFuture<'a, ValidationResult<C, PrefixRoutingError>> {
        Box::pin(self.validate_request(headers, method, uri, client_cert_der))
    }
}

impl<C> ProvideValidatorMetadata for PrefixRoutingValidator<C> {
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        ValidatorMetadata {
            resource: resource.map(str::to_owned),
            ..self.metadata.clone()
        }
    }
}
