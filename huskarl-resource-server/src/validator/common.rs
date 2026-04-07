use crate::core::jwt::validator::JwtValidator;
use http::HeaderName;
use serde::Deserialize;
use snafu::prelude::*;

use crate::{
    ValidatedRequest,
    validator::{
        ValidationResult,
        binding::{DPoPBindingChecker, check_token_binding},
        dpop_nonce::DpopNonceChecker,
        error::{BindingSnafu, ExtractSnafu, InvalidJwtSnafu, ValidateHeadersError},
        extract::extract_token,
    },
};

pub(super) struct ValidatorInner<N: DpopNonceChecker> {
    pub jwt_validator: JwtValidator,
    pub dpop_binding_checker: DPoPBindingChecker<N>,
    pub token_header: HeaderName,
    /// If `true`, tokens without a `cnf.x5t#S256` certificate binding are rejected.
    pub require_mtls: bool,
}

impl<N: DpopNonceChecker> ValidatorInner<N> {
    pub async fn validate_request<Claims: for<'de> Deserialize<'de> + Clone + 'static>(
        &self,
        headers: &http::HeaderMap,
        http_method: &http::Method,
        http_uri: &http::Uri,
        client_cert_der: Option<&[u8]>,
    ) -> ValidationResult<Claims, ValidateHeadersError> {
        let extract_result = extract_token(headers, &self.token_header).context(ExtractSnafu);
        let (token_type, access_token) = match extract_result {
            Err(e) => {
                return ValidationResult {
                    outcome: Err(e),
                    dpop_nonce: None,
                };
            }
            Ok(None) => {
                return ValidationResult {
                    outcome: Ok(None),
                    dpop_nonce: None,
                };
            }
            Ok(Some(v)) => v,
        };

        let validated = match self
            .jwt_validator
            .validate::<Claims>(access_token.expose_secret())
            .await
            .context(InvalidJwtSnafu { token_type })
        {
            Err(e) => {
                return ValidationResult {
                    outcome: Err(e),
                    dpop_nonce: None,
                };
            }
            Ok(v) => v,
        };

        let (dpop_nonce, binding_result) = check_token_binding(
            token_type,
            validated.cnf.as_ref(),
            &access_token,
            &self.dpop_binding_checker,
            self.require_mtls,
            headers,
            http_method,
            http_uri,
            client_cert_der,
        )
        .await;

        let outcome = binding_result
            .context(BindingSnafu { token_type })
            .map(|()| Some(ValidatedRequest::from(validated)));

        ValidationResult {
            outcome,
            dpop_nonce,
        }
    }
}
