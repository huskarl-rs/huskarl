//! Preserve client rejection reasons before erasing errors for evidence.
use huskarl::{
    core::{crypto::verifier::VerifyError, jwt::validator::JwtValidationError},
    grant::authorization_code::LoopbackError,
    token::id_token::IdTokenValidationError,
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Rejection {
    DiscoveryIssuer,
    CallbackState,
    CallbackIssuer,
    MissingCallbackIssuer,
    MissingCallbackState,
    UserInfoSubject,
    IdToken(TokenRejection),
    Jarm(TokenRejection),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum TokenRejection {
    ClaimMismatch(&'static str),
    MissingClaim(&'static str),
    Expired,
    Unsigned,
    Algorithm,
    Signature,
    AmbiguousKey,
    Nonce,
    UntrustedAudience,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientError {
    pub message: String,
    pub rejection: Option<Rejection>,
}

impl ClientError {
    pub fn capture(error: &(dyn std::error::Error + 'static)) -> Self {
        let mut messages = Vec::new();
        let mut rejection = None;
        let mut token_reason = None;
        let mut id_token = false;
        let mut jarm = false;
        let mut current = Some(error);
        while let Some(error) = current {
            // Error::source skips its erased cause; inspect that cause explicitly.
            if let Some(error) = error.downcast_ref::<huskarl::core::Error>() {
                current = Some(error.cause());
                continue;
            }
            let message = error.to_string();
            if let Some(error) = error.downcast_ref::<IdTokenValidationError>() {
                id_token = true;
                token_reason = match error {
                    IdTokenValidationError::NonceMismatch => Some(TokenRejection::Nonce),
                    IdTokenValidationError::SubjectMissing => {
                        Some(TokenRejection::MissingClaim("sub"))
                    }
                    IdTokenValidationError::UntrustedAudience { .. } => {
                        Some(TokenRejection::UntrustedAudience)
                    }
                    _ => token_reason,
                };
            }
            if let Some(error) = error.downcast_ref::<JwtValidationError>() {
                token_reason = match error {
                    JwtValidationError::ClaimMismatch { claim, .. } => {
                        Some(TokenRejection::ClaimMismatch(claim))
                    }
                    JwtValidationError::RequiredClaimMissing { claim } => {
                        Some(TokenRejection::MissingClaim(claim))
                    }
                    JwtValidationError::Expired { .. } => Some(TokenRejection::Expired),
                    JwtValidationError::UnsignedToken => Some(TokenRejection::Unsigned),
                    JwtValidationError::DisallowedAlgorithm { .. } => {
                        Some(TokenRejection::Algorithm)
                    }
                    _ => token_reason,
                };
            }
            if let Some(error) = error.downcast_ref::<VerifyError>() {
                token_reason = match error {
                    VerifyError::SignatureMismatch | VerifyError::MalformedSignature { .. } => {
                        Some(TokenRejection::Signature)
                    }
                    VerifyError::AmbiguousKeyMatch => Some(TokenRejection::AmbiguousKey),
                    _ => token_reason,
                };
            }
            if matches!(
                error.downcast_ref::<LoopbackError>(),
                Some(LoopbackError::MissingParameter { param: "state" })
            ) {
                rejection = Some(Rejection::MissingCallbackState);
            }
            // These library causes are private. Match only their specific diagnostics;
            // unknown messages stay unclassified and cannot satisfy a negative test.
            if message.starts_with("issuer mismatch (RFC 8414 §3.3): expected ") {
                rejection = Some(Rejection::DiscoveryIssuer);
            } else if message == "state mismatch between original request and callback" {
                rejection = Some(Rejection::CallbackState);
            } else if message.starts_with("issuer mismatch: original = ") {
                rejection = Some(Rejection::CallbackIssuer);
            } else if message
                == "authorization server claims to support issuer identification but no issuer returned"
            {
                rejection = Some(Rejection::MissingCallbackIssuer);
            } else if message == "JARM response is missing the 'state' claim" {
                rejection = Some(Rejection::MissingCallbackState);
            } else if message == "JARM response JWT validation failed" {
                jarm = true;
            } else if message.starts_with("UserInfo sub mismatch: expected ") {
                rejection = Some(Rejection::UserInfoSubject);
            }
            messages.push(message);
            current = error.source();
        }
        if let Some(reason) = token_reason {
            if id_token {
                rejection = Some(Rejection::IdToken(reason));
            } else if jarm {
                rejection = Some(Rejection::Jarm(reason));
            }
        }
        Self {
            message: messages.join(": "),
            rejection,
        }
    }
}

impl From<String> for ClientError {
    fn from(message: String) -> Self {
        Self {
            message,
            rejection: None,
        }
    }
}

impl From<&str> for ClientError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_typed_rejection_through_erased_cause_and_loopback() {
        let cause = IdTokenValidationError::Jwt {
            source: JwtValidationError::RequiredClaimMissing { claim: "iat" },
        };
        let error = LoopbackError::Complete {
            source: huskarl::core::Error::new(huskarl::core::RetryAdvice::No, cause),
        };
        assert_eq!(
            ClientError::capture(&error).rejection,
            Some(Rejection::IdToken(TokenRejection::MissingClaim("iat")))
        );
    }

    #[test]
    fn transport_and_unavailable_keys_are_not_protocol_rejections() {
        for error in [
            huskarl::core::Error::new(
                huskarl::core::RetryAdvice::RETRY,
                std::io::Error::other("connection reset"),
            ),
            huskarl::core::Error::from(VerifyError::KeysUnavailable),
        ] {
            assert_eq!(
                ClientError::capture(&LoopbackError::Complete { source: error }).rejection,
                None
            );
        }
    }
}
