//! Serde helpers for serializing `SystemTime` as Unix seconds.
//!
//! OIDC and `OAuth2` wire formats represent timestamps as integer seconds since
//! the Unix epoch. The domain types use `SystemTime` for ergonomic arithmetic,
//! so these adapters bridge the two via `#[serde(with = "...")]`.
//!
//! # Wire format
//!
//! - Serializes as `u64` whole seconds since the Unix epoch. Pre-epoch
//!   `SystemTime` values are a serialization error rather than being silently
//!   clamped. Sub-second precision is dropped — the wire format is whole seconds.
//! - Deserializes from any JSON number: integers and floats are accepted, with
//!   floats truncated toward zero. Negative, NaN, or out-of-`u64`-range values
//!   are rejected, as are values that overflow `SystemTime` when added to the
//!   Unix epoch.

use serde::{Deserializer, Serialize, Serializer, de};

use crate::platform::{Duration, SystemTime};

fn to_unix<E: serde::ser::Error>(t: SystemTime) -> Result<u64, E> {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| E::custom("SystemTime is before the Unix epoch"))
}

fn from_unix<E: serde::de::Error>(secs: u64) -> Result<SystemTime, E> {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .ok_or_else(|| E::custom("Unix timestamp overflows SystemTime"))
}

pub(crate) struct SecsVisitor;

impl de::Visitor<'_> for SecsVisitor {
    type Value = u64;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a non-negative numeric Unix timestamp in seconds")
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
        Ok(v)
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
        if v < 0 {
            return Err(E::custom("Unix timestamp cannot be negative"));
        }
        Ok(v.cast_unsigned())
    }

    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::cast_sign_loss)]
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<u64, E> {
        if v.is_nan() {
            return Err(E::custom("Unix timestamp cannot be NaN"));
        }
        // `u64::MAX as f64` rounds up to 2^64, so reject with `>=` rather than
        // `>` — a value equal to that bound is outside `u64`'s representable
        // range and would saturate on cast.
        if v < 0.0 || v >= u64::MAX as f64 {
            return Err(E::custom("Unix timestamp outside u64 range"));
        }
        Ok(v as u64)
    }
}

/// Serde adapter for `SystemTime` as Unix-epoch seconds.
pub mod unix_secs {
    use super::{Deserializer, SecsVisitor, Serialize, Serializer, SystemTime, from_unix, to_unix};

    /// Serializes a `SystemTime` as an integer count of seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns a serializer error if `time` is before the Unix epoch, or any
    /// error produced by the underlying serializer.
    pub fn serialize<S: Serializer>(time: &SystemTime, ser: S) -> Result<S::Ok, S::Error> {
        to_unix(*time)?.serialize(ser)
    }

    /// Deserializes a `SystemTime` from a numeric Unix-epoch seconds value.
    ///
    /// Accepts integers and floats; floats are truncated toward zero.
    ///
    /// # Errors
    ///
    /// Returns a deserializer error if the value is negative, NaN, outside
    /// `u64` range, would overflow `SystemTime`, or any error produced by the
    /// underlying deserializer.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<SystemTime, D::Error> {
        de.deserialize_any(SecsVisitor).and_then(from_unix)
    }
}

/// Serde adapter for `Option<SystemTime>` as Unix-epoch seconds.
///
/// Pair with `#[serde(default, skip_serializing_if = "Option::is_none")]` if
/// `None` should be encoded as field omission rather than `null`, and if an
/// absent field should deserialize to `None`.
pub mod option_unix_secs {
    use super::{
        Deserializer, SecsVisitor, Serialize, Serializer, SystemTime, de, from_unix, to_unix,
    };

    /// Serializes an `Option<SystemTime>` as an optional integer count of seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns a serializer error if the inner `SystemTime` is before the Unix
    /// epoch, or any error produced by the underlying serializer.
    pub fn serialize<S: Serializer>(time: &Option<SystemTime>, ser: S) -> Result<S::Ok, S::Error> {
        let secs = match *time {
            Some(t) => Some(to_unix(t)?),
            None => None,
        };
        secs.serialize(ser)
    }

    /// Deserializes an `Option<SystemTime>` from an optional numeric Unix-epoch seconds value.
    ///
    /// Accepts integers and floats; floats are truncated toward zero.
    ///
    /// # Errors
    ///
    /// Returns a deserializer error if the value is negative, NaN, outside
    /// `u64` range, would overflow `SystemTime`, or any error produced by the
    /// underlying deserializer.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<SystemTime>, D::Error> {
        struct OptVisitor;

        impl<'de> de::Visitor<'de> for OptVisitor {
            type Value = Option<SystemTime>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a non-negative numeric Unix timestamp in seconds, or null")
            }

            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
                d.deserialize_any(SecsVisitor).and_then(from_unix).map(Some)
            }
        }

        de.deserialize_option(OptVisitor)
    }
}

#[cfg(test)]
mod tests {
    use serde::{
        Deserialize, Serialize,
        de::{
            IntoDeserializer,
            value::{Error as ValueError, F64Deserializer},
        },
    };
    use serde_json::json;

    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    struct WithTime {
        #[serde(with = "unix_secs")]
        t: SystemTime,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct WithOptTime {
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "option_unix_secs"
        )]
        t: Option<SystemTime>,
    }

    fn epoch_plus(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    // --- unix_secs ---

    #[test]
    fn unix_secs_roundtrip_integer() {
        let t = epoch_plus(1_700_000_000);
        let v = serde_json::to_value(WithTime { t }).unwrap();
        assert_eq!(v, json!({ "t": 1_700_000_000_u64 }));
        let parsed: WithTime = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.t, t);
    }

    #[test]
    fn unix_secs_serialize_drops_sub_second() {
        let t = SystemTime::UNIX_EPOCH + Duration::new(42, 999_999_999);
        let v = serde_json::to_value(WithTime { t }).unwrap();
        assert_eq!(v, json!({ "t": 42_u64 }));
    }

    #[test]
    fn unix_secs_serialize_pre_epoch_errors() {
        let Some(t) = SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(1)) else {
            return;
        };
        let err = serde_json::to_value(WithTime { t }).unwrap_err();
        assert!(err.to_string().contains("before the Unix epoch"));
    }

    #[test]
    fn unix_secs_deserialize_float_truncates() {
        let parsed: WithTime = serde_json::from_value(json!({ "t": 1234.9 })).unwrap();
        assert_eq!(parsed.t, epoch_plus(1234));
    }

    #[test]
    fn unix_secs_deserialize_negative_errors() {
        let err = serde_json::from_value::<WithTime>(json!({ "t": -1 })).unwrap_err();
        assert!(err.to_string().contains("negative"));
    }

    #[test]
    fn unix_secs_deserialize_huge_float_errors() {
        // 2^64 is outside u64 range; the previous `>` check let this through and
        // silently saturated to u64::MAX.
        let de: F64Deserializer<ValueError> = (2.0_f64.powi(64)).into_deserializer();
        let err = de.deserialize_any(SecsVisitor).unwrap_err();
        assert!(err.to_string().contains("outside u64 range"));
    }

    #[test]
    fn unix_secs_deserialize_nan_errors() {
        let de: F64Deserializer<ValueError> = f64::NAN.into_deserializer();
        let err = de.deserialize_any(SecsVisitor).unwrap_err();
        assert!(err.to_string().contains("NaN"));
    }

    #[test]
    fn unix_secs_deserialize_overflow_errors() {
        let err = serde_json::from_value::<WithTime>(json!({ "t": u64::MAX })).unwrap_err();
        assert!(err.to_string().contains("overflows"));
    }

    // --- option_unix_secs ---

    #[test]
    fn option_unix_secs_roundtrip_some() {
        let t = epoch_plus(1_700_000_000);
        let v = serde_json::to_value(WithOptTime { t: Some(t) }).unwrap();
        assert_eq!(v, json!({ "t": 1_700_000_000_u64 }));
        let parsed: WithOptTime = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.t, Some(t));
    }

    #[test]
    fn option_unix_secs_serialize_none_omitted_with_skip() {
        // With `skip_serializing_if = "Option::is_none"`, None becomes field omission.
        let v = serde_json::to_value(WithOptTime { t: None }).unwrap();
        assert_eq!(v, json!({}));
    }

    #[test]
    fn option_unix_secs_deserialize_null() {
        let parsed: WithOptTime = serde_json::from_value(json!({ "t": null })).unwrap();
        assert_eq!(parsed.t, None);
    }

    #[test]
    fn option_unix_secs_deserialize_absent() {
        let parsed: WithOptTime = serde_json::from_value(json!({})).unwrap();
        assert_eq!(parsed.t, None);
    }

    #[test]
    fn option_unix_secs_deserialize_negative_errors() {
        let err = serde_json::from_value::<WithOptTime>(json!({ "t": -1 })).unwrap_err();
        assert!(err.to_string().contains("negative"));
    }
}
