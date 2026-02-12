use serde::{Deserializer, de};

/// Deserialize a `u64` from either a JSON number or a string containing a number.
pub(crate) fn deserialize_u64_or_string<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
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
                .map_err(|_| E::custom(format!("negative expires_in: {v}")))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.parse::<u64>().map(Some).map_err(E::custom)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    }

    deserializer.deserialize_any(U64OrString)
}
