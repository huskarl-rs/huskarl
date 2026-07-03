//! Free functions that check individual registered JWT claims.

use snafu::ensure;

use super::{
    ClaimCheck, ClaimMismatchSnafu, ExpiredSnafu, InvalidTokenTypeSnafu, IssuedInFutureSnafu,
    JwtValidationError, NotYetValidSnafu, RequiredClaimMissingSnafu,
};
use crate::platform::{Duration, SystemTime};

/// Per RFC 7515 §4.1.9 and RFC 2045, `typ` media type subtypes are case-insensitive,
/// and the `application/` prefix may be omitted when there is no other `/` in the value.
/// Normalize to the short form before comparison.
pub(super) fn normalize_typ(typ: &str) -> &str {
    match typ.split_at_checked(12) {
        Some((prefix, rest)) if !rest.is_empty() && prefix.eq_ignore_ascii_case("application/") => {
            rest
        }
        _ => typ,
    }
}

pub(super) fn check_str_claim(
    claim: &'static str,
    check: &ClaimCheck,
    value: Option<&str>,
) -> Result<(), JwtValidationError> {
    match check {
        ClaimCheck::Present => {
            if value.is_none() {
                return Err(RequiredClaimMissingSnafu { claim }.build());
            }
        }
        ClaimCheck::RequiredValue(v) => match value {
            Some(val) if val == v.as_str() => {}
            Some(val) => {
                return Err(ClaimMismatchSnafu {
                    claim,
                    expected: v.clone(),
                    actual: val,
                }
                .build());
            }
            None => return Err(RequiredClaimMissingSnafu { claim }.build()),
        },
        ClaimCheck::RequireAny(vs) => match value {
            Some(val) if vs.iter().any(|x| val == x.as_str()) => {}
            Some(val) => {
                return Err(ClaimMismatchSnafu {
                    claim,
                    expected: vs.join(", "),
                    actual: val,
                }
                .build());
            }
            None => return Err(RequiredClaimMissingSnafu { claim }.build()),
        },
        ClaimCheck::IfPresent(v) => {
            if let Some(val) = value
                && val != v.as_str()
            {
                return Err(ClaimMismatchSnafu {
                    claim,
                    expected: v.clone(),
                    actual: val,
                }
                .build());
            }
        }
        ClaimCheck::NoCheck => {}
    }
    Ok(())
}

pub(super) fn check_aud(check: &ClaimCheck, aud: &[String]) -> Result<(), JwtValidationError> {
    match check {
        ClaimCheck::Present => ensure!(!aud.is_empty(), RequiredClaimMissingSnafu { claim: "aud" }),
        ClaimCheck::RequiredValue(v) => ensure!(
            aud.contains(v),
            ClaimMismatchSnafu {
                claim: "aud",
                expected: v.clone(),
                actual: aud.join(", "),
            }
        ),
        ClaimCheck::RequireAny(vs) => ensure!(
            vs.iter().any(|v| aud.contains(v)),
            ClaimMismatchSnafu {
                claim: "aud",
                expected: vs.join(", "),
                actual: aud.join(", "),
            }
        ),
        ClaimCheck::IfPresent(v) => {
            if !aud.is_empty() {
                ensure!(
                    aud.contains(v),
                    ClaimMismatchSnafu {
                        claim: "aud",
                        expected: v.clone(),
                        actual: aud.join(", "),
                    }
                );
            }
        }
        ClaimCheck::NoCheck => {}
    }
    Ok(())
}

pub(super) fn check_typ(check: &ClaimCheck, typ: Option<&str>) -> Result<(), JwtValidationError> {
    match check {
        ClaimCheck::IfPresent(t) => ensure!(
            typ.is_none_or(|v| normalize_typ(v).eq_ignore_ascii_case(normalize_typ(t))),
            InvalidTokenTypeSnafu {
                typ: typ.map(Into::into)
            }
        ),
        ClaimCheck::RequireAny(allowed) => match typ {
            None => return RequiredClaimMissingSnafu { claim: "typ" }.fail(),
            Some(v)
                if allowed
                    .iter()
                    .any(|t| normalize_typ(v).eq_ignore_ascii_case(normalize_typ(t))) => {}
            Some(v) => {
                return InvalidTokenTypeSnafu {
                    typ: Some(v.into()),
                }
                .fail();
            }
        },
        ClaimCheck::RequiredValue(t) => match typ {
            None => return RequiredClaimMissingSnafu { claim: "typ" }.fail(),
            Some(v) if normalize_typ(v).eq_ignore_ascii_case(normalize_typ(t)) => {}
            Some(v) => {
                return InvalidTokenTypeSnafu {
                    typ: Some(v.into()),
                }
                .fail();
            }
        },
        ClaimCheck::Present => {
            ensure!(typ.is_some(), RequiredClaimMissingSnafu { claim: "typ" });
        }
        ClaimCheck::NoCheck => {}
    }
    Ok(())
}

/// Returns whether `timestamp` is at most `max_age` before `now`, with clock
/// leeway.
///
/// Shared by the JWT `max_token_age` check (against `iat`) and the OIDC
/// `max_age` check (against `auth_time`), which must agree on two invariants:
///
/// - A future `timestamp` (issuer clock ahead) counts as age zero rather than
///   a rejection. Policing future timestamps is the temporal checks' job (the
///   issued-in-future arm below), with its own leeway.
/// - `clock_leeway` widens the allowed age (saturating); it does not shift
///   `now`.
#[must_use]
pub fn within_max_age(
    now: SystemTime,
    timestamp: SystemTime,
    max_age: Duration,
    clock_leeway: Duration,
) -> bool {
    let age = now.duration_since(timestamp).unwrap_or(Duration::ZERO);
    age <= max_age.saturating_add(clock_leeway)
}

/// Temporal comparisons are expressed via `duration_since` rather than
/// `SystemTime`/`Duration` addition: the claim timestamps are attacker-controlled
/// and may sit at the edge of the representable range, where addition panics.
pub(super) fn check_temporal(
    now: SystemTime,
    clock_leeway: Duration,
    exp: Option<SystemTime>,
    nbf: Option<SystemTime>,
    iat: Option<SystemTime>,
) -> Result<(), JwtValidationError> {
    if let Some(expiration) = exp {
        // Expired iff `now > expiration + leeway`.
        ensure!(
            !now.duration_since(expiration)
                .is_ok_and(|past| past > clock_leeway),
            ExpiredSnafu { expiration, now }
        );
    }
    if let Some(not_before) = nbf {
        // Not yet valid iff `not_before > now + leeway`.
        ensure!(
            !not_before
                .duration_since(now)
                .is_ok_and(|ahead| ahead > clock_leeway),
            NotYetValidSnafu { not_before, now }
        );
    }
    if let Some(issued_at) = iat {
        // Issued in the future iff `issued_at > now + leeway`.
        ensure!(
            !issued_at
                .duration_since(now)
                .is_ok_and(|ahead| ahead > clock_leeway),
            IssuedInFutureSnafu { issued_at, now }
        );
    }
    Ok(())
}
