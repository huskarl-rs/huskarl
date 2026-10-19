//! Cryptographic interfaces and definitions.
//!
//! Many OAuth 2.0 grants and auxiliary interfaces require cryptographic
//! operations to ensure properties such as integrity, authentication,
//! confidentiality, and non-repudiation.
//!
//! This module holds the signing ([`signer`]), verification ([`verifier`]), and
//! encryption ([`cipher`]) traits, plus the shared key-matching types
//! ([`KeyMatchStrength`]); [`seal`] is a convenience layer over [`cipher`] for
//! self-contained bundles. Concrete implementations live in platform crates.
//!
//! Each base trait comes with a family of composable wrappers (multi-key,
//! refreshable, scheduled-refresh, retrying) that decorate it without changing
//! its interface. See [composing crypto
//! strategies](crate::_docs::explanation::crypto_strategies) for how they stack.
//!
//! # Refresh metrics
//!
//! [`signer::ScheduledRefreshSigner`], [`verifier::ScheduledRefreshVerifier`],
//! and [`cipher::ScheduledRefreshCipher`] accept an optional `metrics_name` on
//! their builders. With the `metrics` feature enabled, named sources emit the
//! `huskarl.crypto.refresh` counter. Without that feature the setting is inert;
//! unnamed sources emit no refresh counters. Names must come from bounded
//! application configuration, never request headers.
//!
//! Each counter has three labels:
//!
//! | Label | Values |
//! | --- | --- |
//! | `name` | The configured source name |
//! | `trigger` | `read` (use of the source), `stale` (manual staleness poll), `miss` (key-miss or cold-start recovery), `forced` (explicit refresh) |
//! | `outcome` | Defined below |
//!
//! | Outcome | Meaning |
//! | --- | --- |
//! | `success` | A factory reload completed successfully |
//! | `failure` | A factory reload returned an error |
//! | `skipped` | TTL, minimum interval, or backoff prevented an attempt |
//! | `adopted` | A waiting caller adopted another caller's successful reload |
//! | `in_flight` | A read passed the policy pre-check but found a reload running or already published |
//!
//! Initial construction and cancelled reloads do not count as `success` or
//! `failure`. Ordinary reads of a fresh snapshot count as `skipped`. Reads during
//! a reload can also count as `skipped` when its claimed attempt triggers the
//! policy pre-check, so `in_flight` does not count every concurrent read.
//! Forced refreshes bypass policy and report `success`, `failure`, or `adopted`.
//! Only `success` and `failure` count completed factory reloads.

pub mod cipher;
pub(crate) mod refreshable;
pub mod seal;
pub mod signer;
pub mod verifier;

/// States how well a particular key matched the selection criteria from a JOSE header.
///
/// Used by both JWS verifiers and JWE ciphers to express the strength of a key match,
/// allowing multi-key types to prefer exact matches over algorithm-only matches.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum KeyMatchStrength {
    /// Both the algorithm and the key ID match exactly.
    ByKeyId,
    /// The algorithm matches but the key ID was not used for matching — either
    /// the header has no `kid`, or this key has no `kid` registered.
    ByAlgorithm,
}

/// The shared `kid` half of the key-matching rules, applied after the
/// algorithm has already been found compatible: both sides present and equal
/// is a `ByKeyId` match, both present and different is a mismatch, and a
/// `kid` missing on either side falls back to `ByAlgorithm`.
pub(crate) fn kid_match_strength(
    requested: Option<&str>,
    registered: Option<&str>,
) -> Option<KeyMatchStrength> {
    match (requested, registered) {
        (Some(requested), Some(registered)) => {
            (requested == registered).then_some(KeyMatchStrength::ByKeyId)
        }
        _ => Some(KeyMatchStrength::ByAlgorithm),
    }
}
