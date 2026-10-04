//! Conversions between wall timestamps and the platform clock representation.

use super::{Duration, TimeOverflow};
use crate::platform::SystemTime;

/// Convert a platform time to a timestamp.
///
/// # Errors
/// Returns [`TimeOverflow`] if the time is outside Jiff's timestamp range.
pub fn timestamp_from_system_time(value: SystemTime) -> Result<jiff::Timestamp, TimeOverflow> {
    match value.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => jiff::Timestamp::UNIX_EPOCH.checked_add(duration),
        Err(error) => jiff::Timestamp::UNIX_EPOCH.checked_sub(error.duration()),
    }
    .map_err(|_| TimeOverflow)
}

/// Convert a timestamp to the platform's wall-clock type.
///
/// # Errors
/// Returns [`TimeOverflow`] if the platform cannot represent the timestamp.
pub fn system_time_from_timestamp(value: jiff::Timestamp) -> Result<SystemTime, TimeOverflow> {
    let duration = value.as_duration().unsigned_abs();
    if value < jiff::Timestamp::UNIX_EPOCH {
        SystemTime::UNIX_EPOCH.checked_sub(duration)
    } else {
        SystemTime::UNIX_EPOCH.checked_add(duration)
    }
    .ok_or(TimeOverflow)
}

/// Convert to the platform's wall-clock type, clamping out-of-range values
/// to its nearest representable boundary.
#[must_use]
pub fn system_time_from_timestamp_saturating(value: jiff::Timestamp) -> SystemTime {
    if let Ok(time) = system_time_from_timestamp(value) {
        return time;
    }

    let before_epoch = value < jiff::Timestamp::UNIX_EPOCH;
    let mut upper = value.as_duration().unsigned_abs();
    let mut lower = Duration::ZERO;
    let mut result = SystemTime::UNIX_EPOCH;
    // SystemTime exposes checked arithmetic but no MIN/MAX constants.
    // Search only on overflow; ordinary readings take the fast path above.
    while lower < upper {
        let midpoint = lower
            .saturating_add(upper.saturating_sub(lower) / 2)
            .saturating_add(Duration::from_nanos(1));
        let candidate = if before_epoch {
            SystemTime::UNIX_EPOCH.checked_sub(midpoint)
        } else {
            SystemTime::UNIX_EPOCH.checked_add(midpoint)
        };
        if let Some(time) = candidate {
            lower = midpoint;
            result = time;
        } else {
            upper = midpoint.saturating_sub(Duration::from_nanos(1));
        }
    }
    result
}

/// Convert Unix seconds and a nonnegative nanosecond fraction from a host or API.
///
/// # Errors
/// Returns [`TimeOverflow`] for an invalid fraction or a time outside Jiff's range.
pub fn timestamp_from_unix_parts(
    seconds: i64,
    nanos: u32,
) -> Result<jiff::Timestamp, TimeOverflow> {
    let nanos = i32::try_from(nanos).map_err(|_| TimeOverflow)?;
    jiff::Timestamp::new(seconds, nanos).map_err(|_| TimeOverflow)
}
