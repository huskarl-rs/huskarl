use http::HeaderName;
use huskarl_core::token::validator::JwtValidator;
use serde::Deserialize;
use snafu::prelude::*;

use crate::{
    ValidatedRequest,
    validator::{
        binding::{DPoPBindingChecker, check_token_binding},
        error::{BindingSnafu, ExtractSnafu, InvalidJwtSnafu, ValidateHeadersError},
        extract::extract_token,
    },
};

pub(super) struct ValidatorInner {
    pub token_validator: JwtValidator,
    pub dpop_binding_checker: DPoPBindingChecker,
    pub token_header: HeaderName,
    /// If `true`, tokens without a `cnf.x5t#S256` certificate binding are rejected.
    pub require_mtls: bool,
}

impl ValidatorInner {
    pub async fn validate_request<Claims: for<'de> Deserialize<'de> + Clone + 'static>(
        &self,
        headers: &http::HeaderMap,
        http_method: &http::Method,
        http_uri: &http::Uri,
        client_cert_der: Option<&[u8]>,
    ) -> Result<Option<ValidatedRequest<Claims>>, ValidateHeadersError> {
        let Some((token_type, access_token)) =
            extract_token(headers, &self.token_header).context(ExtractSnafu)?
        else {
            return Ok(None);
        };

        let validated = self
            .token_validator
            .validate::<Claims>(access_token.expose_token())
            .await
            .context(InvalidJwtSnafu)?;

        check_token_binding(
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
        .await
        .context(BindingSnafu)?;

        Ok(Some(validated.into()))
    }
}
