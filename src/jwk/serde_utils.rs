pub mod base64url {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: &str = Deserialize::deserialize(d)?;
        URL_SAFE_NO_PAD.decode(s).map_err(serde::de::Error::custom)
    }
}

pub mod base64url_uint {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        let trimmed = match bytes.iter().position(|&b| b != 0) {
            Some(i) => &bytes[i..],
            None => &[0],
        };
        ser.serialize_str(&URL_SAFE_NO_PAD.encode(trimmed))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s: &str = Deserialize::deserialize(de)?;
        URL_SAFE_NO_PAD.decode(s).map_err(serde::de::Error::custom)
    }
}
