pub mod base64url {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: String = Deserialize::deserialize(d)?;
        URL_SAFE_NO_PAD.decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Returns `bytes` with leading zero bytes stripped, preserving at least one byte.
///
/// Per RFC 7518 §2, `Base64urlUInt` values must use the minimum number of octets.
pub(super) fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b != 0) {
        Some(i) => &bytes[i..],
        None => &[0],
    }
}

pub mod base64url_uint {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&URL_SAFE_NO_PAD.encode(super::trim_leading_zeros(bytes)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        URL_SAFE_NO_PAD.decode(&s).map_err(serde::de::Error::custom)
    }
}
