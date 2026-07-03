use serde::{Deserializer, de};

/// Forgiving visitor for second-count fields (`expires_in`, `interval`):
/// servers variously emit them as integers, floats (`3600.0`), strings
/// (`"3600"`), or float strings (`"3600.0"`). Fractional values truncate,
/// which only ever shortens a lifetime — the safe side.
struct U64OrString;

impl de::Visitor<'_> for U64OrString {
    type Value = Option<u64>;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a number or string containing a number")
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(Some(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        u64::try_from(v)
            .map(Some)
            .map_err(|_| E::custom(format!("negative seconds value: {v}")))
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
        if v.is_finite() && v >= 0.0 {
            Ok(Some(v as u64)) // saturates at u64::MAX
        } else {
            Err(E::custom(format!("invalid seconds value: {v}")))
        }
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        if let Ok(n) = v.parse::<u64>() {
            return Ok(Some(n));
        }
        match v.parse::<f64>() {
            // visit_f64 keeps the "inf"/"NaN" strings f64 parsing accepts out.
            Ok(f) => self.visit_f64(f),
            Err(e) => Err(E::custom(e)),
        }
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
}

/// Deserialize an optional `u64` seconds count from a number or a string
/// containing a number.
pub(crate) fn deserialize_u64_or_string<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(U64OrString)
}

/// Deserialize a required `u32` seconds count from a number or a string
/// containing a number.
pub(crate) fn deserialize_u32_or_string<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    match deserializer.deserialize_any(U64OrString)? {
        Some(v) => u32::try_from(v).map_err(de::Error::custom),
        None => Err(de::Error::custom("expected a number, got null")),
    }
}
