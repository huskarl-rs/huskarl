//! Validation of key-bound ID-token presentations within a relying party.
//!
//! OpenID Connect Key Binding draft 03 leaves the presentation proof protocol
//! unspecified. This module validates the OP-issued token and delegates the
//! complete possession protocol to a required [`IdTokenPresentationProofVerifier`].
//! It does not define a DPoP-over-ID-token wire protocol or treat ID tokens as
//! access tokens. Use [`super::id_token::IdTokenValidator`] for OP responses.

use std::{collections::HashSet, sync::Arc};

use bon::Builder;
use snafu::{ResultExt as _, Snafu, ensure};

use super::id_token::{IdToken, IdTokenClaims};
use crate::core::{
    Error,
    crypto::verifier::JwsVerifier,
    jwk::PublicJwk,
    jwt::{
        JwkConfirmationClaim, JwsParseError, parse_compact_jws_with_confirmation,
        validator::{ClaimCheck, JwtValidationError, JwtValidator, ValidatedJwt},
    },
    platform::{Duration, MaybeSend, MaybeSendSync, MaybeSync},
};

/// Application-supplied verification of an ID-token presentation protocol.
///
/// Implementations are trusted security components. Before returning success,
/// they must extract the public key from `id_token` using [`binding_key`] and
/// verify possession of it, bind the proof to the token and intended interaction,
/// enforce algorithm and freshness policy, and prevent replay (for example
/// through an atomically consumed challenge).
/// Checking a signature or matching a thumbprint alone is insufficient.
///
/// When called by [`IdTokenPresentationValidator`], the token's OP signature,
/// issuer, audience, lifetime, type and subject have already passed validation.
/// Use the key from the token, never a key supplied in the proof.
/// Application context must come from the consumer's trusted request/session
/// state, rather than being accepted uncritically from the presenter.
pub trait IdTokenPresentationProofVerifier: MaybeSendSync {
    /// The proof representation defined by the application's protocol.
    type Proof: ?Sized + MaybeSync;
    /// Trusted context for this presentation (e.g. a session challenge).
    type Context: ?Sized + MaybeSync;

    /// Verify the complete presentation protocol against the OP-bound key.
    /// Extract that key from `id_token` with [`binding_key`]; propagate extraction
    /// failures as errors before accessing replay state. Return success only
    /// after all proof checks succeed.
    ///
    /// # Errors
    ///
    /// Return an error for invalid, stale, replayed or incorrectly bound proofs,
    /// and for failures of required verification infrastructure.
    fn verify(
        &self,
        id_token: &IdToken,
        proof: &Self::Proof,
        context: &Self::Context,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend;
}

impl<T: IdTokenPresentationProofVerifier + ?Sized> IdTokenPresentationProofVerifier for &T {
    type Proof = T::Proof;
    type Context = T::Context;

    fn verify(
        &self,
        id_token: &IdToken,
        proof: &Self::Proof,
        context: &Self::Context,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend {
        (**self).verify(id_token, proof, context)
    }
}

impl<T: IdTokenPresentationProofVerifier + ?Sized> IdTokenPresentationProofVerifier for Box<T> {
    type Proof = T::Proof;
    type Context = T::Context;

    fn verify(
        &self,
        id_token: &IdToken,
        proof: &Self::Proof,
        context: &Self::Context,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend {
        (**self).verify(id_token, proof, context)
    }
}

impl<T: IdTokenPresentationProofVerifier + ?Sized> IdTokenPresentationProofVerifier for Arc<T> {
    type Proof = T::Proof;
    type Context = T::Context;

    fn verify(
        &self,
        id_token: &IdToken,
        proof: &Self::Proof,
        context: &Self::Context,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend {
        (**self).verify(id_token, proof, context)
    }
}

/// Validates a bound ID token and its presentation proof for a consuming RP
/// component. All configured audiences must belong to applications it serves
/// within the same RP trust boundary.
///
/// Requires `typ: dpop+id_token`. The proof verifier checks the public `cnf.jwk`
/// binding and possession of its key. There is no proof-free mode. The original
/// authentication nonce is not a presentation challenge and is not checked here.
///
/// The proof verifier supplies the application-specific presentation protocol;
/// this validator does not imply that a particular protocol is standardized.
#[derive(Debug, Builder)]
#[builder(on(String, into))]
pub struct IdTokenPresentationValidator<P: IdTokenPresentationProofVerifier> {
    /// Verifier for the OP's signature, configured independently of the token.
    #[builder(with = |verifier: impl JwsVerifier + 'static| Arc::new(verifier) as Arc<dyn JwsVerifier>)]
    verifier: Arc<dyn JwsVerifier>,
    /// Exact issuer identifier accepted by this consumer.
    issuer: String,
    /// Accepted originating client IDs, not the consumer's endpoint URL.
    /// At least one must match `aud`. An empty set accepts no tokens.
    #[builder(with = FromIterator::from_iter)]
    audiences: HashSet<String>,
    /// Required implementation of the presentation proof protocol.
    proof_verifier: P,
    /// Leeway for token expiry and issuance timestamps. Defaults to 10 seconds.
    #[builder(default = Duration::from_secs(10))]
    clock_leeway: Duration,
    /// Optional allowlist for OP signature algorithms, independent of proof policy.
    #[builder(with = FromIterator::from_iter)]
    allowed_algorithms: Option<HashSet<String>>,
}

impl<P: IdTokenPresentationProofVerifier> IdTokenPresentationValidator<P> {
    /// Validate the token, then the proof, returning identity claims only after
    /// both succeed. The proof verifier is not called if the OP signature or token
    /// claims fail validation.
    ///
    /// Authorization to perform an application action remains the caller's job.
    ///
    /// # Errors
    ///
    /// Returns an error if token validation, binding extraction or presentation
    /// proof verification fails. Proof-verifier errors retain their source.
    pub async fn validate(
        &self,
        id_token: &IdToken,
        proof: &P::Proof,
        context: &P::Context,
    ) -> Result<VerifiedIdTokenPresentation, IdTokenPresentationError> {
        let claims = JwtValidator::builder()
            .verifier(self.verifier.clone())
            .iss(ClaimCheck::required_value(&self.issuer))
            .aud(ClaimCheck::require_any(self.audiences.iter().cloned()))
            .sub(ClaimCheck::present())
            .typ(ClaimCheck::required_value("dpop+id_token"))
            .require_exp(true)
            .require_iat(true)
            .clock_leeway(self.clock_leeway)
            .maybe_allowed_algorithms(self.allowed_algorithms.clone())
            .build()
            .validate::<IdTokenClaims>(id_token.token())
            .await
            .context(TokenSnafu)?;

        self.proof_verifier
            .verify(id_token, proof, context)
            .await
            .context(ProofSnafu)?;
        Ok(VerifiedIdTokenPresentation { claims })
    }
}

/// An ID token whose OP claims and presentation proof were both accepted.
///
/// Constructed only by [`IdTokenPresentationValidator`]. Acceptance applies to
/// the context of that validation; persisting or cloning claims does not make
/// them evidence of a fresh presentation.
#[derive(Debug)]
pub struct VerifiedIdTokenPresentation {
    claims: ValidatedJwt<IdTokenClaims>,
}

impl VerifiedIdTokenPresentation {
    /// The verified identity claims. These do not themselves grant permission
    /// to perform an application action.
    #[must_use]
    pub fn claims(&self) -> &ValidatedJwt<IdTokenClaims> {
        &self.claims
    }
}

/// Extract the public `cnf.jwk` used to verify an ID-token presentation proof.
///
/// This checks the binding's structure, not the token's signature or claims.
/// [`IdTokenPresentationValidator`] validates those before calling the proof
/// verifier. Calling this helper alone does not authenticate a token.
///
/// # Errors
///
/// Returns an error if the compact token cannot be parsed, `cnf.jwk` is missing or
/// malformed, `cnf` has other members, or the key contains private parameters
/// or an `x5u` reference.
pub fn binding_key(token: &IdToken) -> Result<PublicJwk, IdTokenPresentationError> {
    let (_, confirmation) =
        parse_compact_jws_with_confirmation::<(), (), JwkConfirmationClaim>(token.token())
            .context(ParseSnafu)?;
    let key = confirmation.ok_or_else(|| MissingBindingSnafu.build())?.jwk;
    ensure!(
        !key.has_private_parameters && key.x5u.is_none(),
        InvalidBindingKeySnafu
    );
    Ok(key)
}

/// Failures validating an ID-token presentation.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum IdTokenPresentationError {
    /// OP signature or registered/identity claim validation failed.
    #[snafu(display("validating the presented ID token"))]
    Token {
        /// Underlying JWT validation error.
        source: JwtValidationError,
    },
    /// The token did not carry a binding.
    #[snafu(display("the ID token has no key binding"))]
    MissingBinding,
    /// The compact JWS or its confirmation claim could not be parsed.
    #[snafu(display("parsing the presented ID token and its key binding"))]
    Parse {
        /// Underlying compact JWS or claims parsing error.
        source: JwsParseError,
    },
    /// The binding JWK contained private material or a remote certificate URL.
    #[snafu(display("the ID token binding key contains private material or x5u"))]
    InvalidBindingKey,
    /// The application-specific proof verifier rejected the presentation.
    #[snafu(display("verifying ID token proof of possession"))]
    Proof {
        /// Underlying verification or infrastructure error.
        source: Error,
    },
}

#[cfg(test)]
mod tests;
