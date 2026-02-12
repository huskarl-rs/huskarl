use serde::Serialize;

/// Metadata about how an access token validator is configured.
///
/// Returned by [`ProvideValidatorMetadata::validator_metadata`]. Intended as
/// input to a Protected Resource Metadata document (RFC 9728).
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorMetadata {
    /// The authorization server(s) this validator trusts, by issuer URI.
    ///
    /// `None` if not known or if the authorization server does not have an issuer URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<String>>,
    /// DPoP proof signing algorithms accepted by this validator.
    ///
    /// `None` if unrestricted (the validator accepts any algorithm its verifier supports).
    /// When `None`, this field should be omitted from RFC 9728 metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// Whether DPoP-bound tokens are required.
    ///
    /// `Some(true)` means Bearer tokens are rejected. `None` means the requirement
    /// status is not known (e.g. a validator that cannot determine this). Maps to
    /// `dpop_bound_access_tokens_required` in RFC 9728 metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_bound_access_tokens_required: Option<bool>,
    /// The resource server's identifier URI.
    ///
    /// Taken from the configured audience value when known. Maps to `resource` in RFC 9728 metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Supported methods for presenting Bearer tokens (RFC 6750).
    ///
    /// Values correspond to RFC 6750 sections: `"header"` (§2.1 Authorization header),
    /// `"body"` (§2.2 form-encoded body parameter), `"query"` (§2.3 URI query parameter).
    /// `None` means unspecified. Maps to `bearer_methods_supported` in RFC 9728 metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_methods_supported: Option<Vec<&'static str>>,
}

/// A trait for validators that can describe their configuration.
///
/// The returned [`ValidatorMetadata`] can be used to populate a Protected Resource
/// Metadata document (RFC 9728).
pub trait ProvideValidatorMetadata {
    /// Returns metadata describing how this validator is configured.
    fn validator_metadata(&self) -> ValidatorMetadata;
}
