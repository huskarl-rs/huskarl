//! Experimental confirmation parsing pending the next breaking release.

use serde::Deserialize;

use crate::jwk::PublicJwk;

/// A confirmation claim containing only an embedded public JWK (RFC 7800 §3.2).
///
/// Used by the experimental ID-token presentation profile. Missing `jwk` and
/// other confirmation members are rejected during deserialization. Callers must
/// still reject private key material and remote key references according to
/// their protocol, and verify possession of the key.
///
/// This separate representation preserves the source compatibility of
/// [`super::ConfirmationClaim`]. It is experimental and may be replaced by
/// `ConfirmationClaim` support in a future breaking release.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct JwkConfirmationClaim {
    /// The embedded key. Parsing does not authenticate it or prove possession.
    pub jwk: PublicJwk,
}

// Migration: add jwk support to ConfirmationClaim in the next breaking release,
// then replace this representation and the sidecar parser. Preserve the
// presentation profile's rejection of additional confirmation members.
