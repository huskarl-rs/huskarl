use std::borrow::Cow;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

fn serialize_string_or_vec<S>(values: &'_ [Cow<'_, str>], serializer: S) -> Result<S::Ok, S::Error>
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

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<Cow<'de, str>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    struct StringOrVec;

    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = Vec<Cow<'de, str>>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or array of strings")
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![Cow::Owned(v)])
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![Cow::Owned(v.to_owned())])
        }

        fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![Cow::Borrowed(v)])
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(1));
            while let Some(value) = seq.next_element::<Cow<'de, str>>()? {
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
            E: serde::de::Error,
        {
            Ok(Vec::new())
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

fn deserialize_whole_or_fractional<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    struct WholeOrFractionalOrNull;

    impl<'de> de::Visitor<'de> for WholeOrFractionalOrNull {
        type Value = Option<u64>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a positive numeric value, or null")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(v))
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v < 0 {
                return Err(E::custom("cannot have a negative value"));
            }

            Ok(Some(v.cast_unsigned()))
        }

        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::cast_precision_loss)]
        #[allow(clippy::cast_sign_loss)]
        fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v.is_nan() {
                return Err(E::custom("cannot be NaN"));
            }

            if v < 0.0 || v > u64::MAX as f64 {
                return Err(E::custom("outside u64 range"));
            }

            Ok(Some(v as u64))
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(WholeOrFractionalOrNull)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "ExtraHeaders: serde::de::Deserialize<'de>"))]
pub struct JwtHeader<'a, ExtraHeaders: Clone> {
    pub alg: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<Cow<'a, str>>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra_headers: Option<Cow<'a, ExtraHeaders>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "ExtraClaims: serde::de::Deserialize<'de>"))]
pub struct JwtClaims<'a, ExtraClaims: Clone> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<Cow<'a, str>>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_or_vec",
        serialize_with = "serialize_string_or_vec",
        borrow
    )]
    pub aud: Vec<Cow<'a, str>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_whole_or_fractional"
    )]
    pub iat: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_whole_or_fractional"
    )]
    pub exp: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_whole_or_fractional"
    )]
    pub nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<Cow<'a, str>>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra_claims: Option<Cow<'a, ExtraClaims>>,
}
