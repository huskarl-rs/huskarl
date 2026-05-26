//! Serde helpers for string / array-of-strings duality.
//!
//! Several OIDC and `OAuth2` claims (notably JWT `aud`, RFC 7519 §4.1.3) accept
//! either a single string or an array of strings on the wire. These adapters
//! normalize to `Vec<String>` in memory.

/// Serde adapter for `Vec<String>` encoded as either a bare string or a JSON array.
///
/// On serialize: empty → `null`, one element → bare string, more → array.
/// Pair with `#[serde(default, skip_serializing_if = "Vec::is_empty")]` to omit
/// the empty case rather than emit `null`, and to allow an absent field to
/// deserialize as an empty `Vec`.
pub mod string_or_vec {
    use serde::{Deserializer, Serializer, de};

    /// Serializes a `Vec<String>` as a single string when length is 1, an array otherwise.
    ///
    /// # Errors
    ///
    /// Returns any error produced by the underlying serializer.
    pub fn serialize<S>(values: &'_ Vec<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq as _;

        match values.len() {
            0 => serializer.serialize_none(),
            1 => serializer.serialize_str(values[0].as_ref()),
            n => {
                let mut seq = serializer.serialize_seq(Some(n))?;
                for element in values {
                    seq.serialize_element(element)?;
                }
                seq.end()
            }
        }
    }

    /// Deserializes a `Vec<String>` from either a single string or an array of strings.
    ///
    /// # Errors
    ///
    /// Returns any error produced by the underlying deserializer.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringOrVec;

        impl<'de> de::Visitor<'de> for StringOrVec {
            type Value = Vec<String>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string or array of strings")
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(vec![v])
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(vec![v.to_owned()])
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(vec![v.to_owned()])
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(1));
                while let Some(value) = seq.next_element()? {
                    vec.push(value);
                }
                Ok(vec)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_any(self)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Vec::new())
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Vec::new())
            }
        }

        deserializer.deserialize_any(StringOrVec)
    }
}
