//! Conversions between wall timestamps and the platform clock representation.

use super::{Duration, TimeOverflow};
use crate::platform::SystemTime;

/// Convert a platform time to a timestamp.
///
/// # Errors
/// Returns [`TimeOverflow`] if the time is outside Jiff's timestamp range.
pub(crate) fn timestamp_from_system_time(
    value: SystemTime,
) -> Result<jiff::Timestamp, TimeOverflow> {
    match value.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => jiff::Timestamp::UNIX_EPOCH.checked_add(duration),
        Err(error) => jiff::Timestamp::UNIX_EPOCH.checked_sub(error.duration()),
    }
    .map_err(|_| TimeOverflow)
}

/// Convert a platform time to a timestamp, clamping out-of-range values to
/// [`jiff::Timestamp::MIN`] or [`jiff::Timestamp::MAX`].
#[must_use]
#[doc(hidden)]
pub fn timestamp_from_system_time_saturating(value: SystemTime) -> jiff::Timestamp {
    timestamp_from_system_time(value).unwrap_or_else(|_| {
        if value < SystemTime::UNIX_EPOCH {
            jiff::Timestamp::MIN
        } else {
            jiff::Timestamp::MAX
        }
    })
}

/// Convert a timestamp to the platform's wall-clock type.
///
/// # Errors
/// Returns [`TimeOverflow`] if the platform cannot represent the timestamp.
#[doc(hidden)]
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
#[doc(hidden)]
#[doc(hidden)]
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

// HTTP-date parsing returns std::time::SystemTime even in browsers, where the
// platform SystemTime is web_time::SystemTime.
pub(crate) fn timestamp_from_std_system_time(
    value: std::time::SystemTime,
) -> Result<jiff::Timestamp, TimeOverflow> {
    jiff::Timestamp::try_from(value).map_err(|_| TimeOverflow)
}

// Nonce wire values are unsigned whole seconds. Check the full timestamp before
// truncating: Jiff's as_second() maps a negative fractional second to zero.
pub(crate) fn unix_seconds_from_timestamp(value: jiff::Timestamp) -> Result<u64, TimeOverflow> {
    if value < jiff::Timestamp::UNIX_EPOCH {
        return Err(TimeOverflow);
    }
    u64::try_from(value.as_second()).map_err(|_| TimeOverflow)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    use core::prelude::v1::test;

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    fn timestamp(seconds: i64, nanos: i32) -> jiff::Timestamp {
        jiff::Timestamp::new(seconds, nanos).unwrap()
    }

    #[test]
    fn system_time_round_trips() {
        for value in [
            jiff::Timestamp::UNIX_EPOCH,
            timestamp(1_700_000_000, 123_456_789),
        ] {
            let system = system_time_from_timestamp(value).unwrap();
            assert_eq!(timestamp_from_system_time(system), Ok(value));
        }
        // web_time cannot represent pre-epoch values; conversion must remain checked.
        let before = timestamp(-1, 999_999_999);
        let system = system_time_from_timestamp(before);
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        assert_eq!(timestamp_from_system_time(system.unwrap()), Ok(before));
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        assert_eq!(system, Err(TimeOverflow));
    }

    #[rstest::rstest]
    #[case::minimum(jiff::Timestamp::MIN)]
    #[case::pre_epoch(jiff::Timestamp::new(-1, 500_000_000).unwrap())]
    #[case::epoch(jiff::Timestamp::UNIX_EPOCH)]
    #[case::fractional(jiff::Timestamp::new(2_000_000, 123_456_789).unwrap())]
    #[case::maximum(jiff::Timestamp::MAX)]
    #[self::test]
    fn system_time_saturation_preserves_values_or_reaches_the_platform_boundary(
        #[case] timestamp: jiff::Timestamp,
    ) {
        let saturated = system_time_from_timestamp_saturating(timestamp);
        if let Ok(exact) = system_time_from_timestamp(timestamp) {
            assert_eq!(saturated, exact);
        } else if timestamp < jiff::Timestamp::UNIX_EPOCH {
            assert!(saturated.checked_sub(Duration::from_nanos(1)).is_none());
        } else {
            assert!(saturated.checked_add(Duration::from_nanos(1)).is_none());
        }
    }

    #[rstest::rstest]
    #[case::minimum(jiff::Timestamp::MIN, true)]
    #[case::maximum(jiff::Timestamp::MAX, false)]
    #[self::test]
    fn system_time_conversion_rejects_values_outside_jiff_range(
        #[case] boundary: jiff::Timestamp,
        #[case] before: bool,
    ) {
        let Ok(system) = system_time_from_timestamp(boundary) else {
            return;
        };
        let outside = if before {
            system.checked_sub(Duration::from_nanos(1))
        } else {
            system.checked_add(Duration::from_nanos(1))
        };
        if let Some(outside) = outside {
            assert_eq!(timestamp_from_system_time(outside), Err(TimeOverflow));
            assert_eq!(timestamp_from_system_time_saturating(outside), boundary);
        }
        assert_eq!(timestamp_from_system_time_saturating(system), boundary);
    }
}
