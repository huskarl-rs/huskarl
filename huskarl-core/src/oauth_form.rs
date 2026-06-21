//! `application/x-www-form-urlencoded` serialization for OAuth 2.0 messages.
//!
//! OAuth carries request parameters as form-encoded data — in the query string
//! of an authorization request (OAuth 2.1 Appendix C.1) and in the body of a
//! token-endpoint request (Appendix C.2). [`to_string`] serializes a `serde`
//! value — a struct, a map, or a sequence of `(key, value)` pairs — into that
//! format, and [`from_str`] parses it back.
//!
//! Unlike a plain form encoder, this supports parameters whose value is a JSON
//! object or array — for example RFC 9396 `authorization_details` — by encoding
//! that value as JSON text within the form field. Scalar sequences (such as the
//! RFC 8707 `resource` parameter) are encoded as repeated keys.
//!
//! | parameter value              | encoding                       |
//! |------------------------------|--------------------------------|
//! | scalar (string/number/bool)  | `key=value`                    |
//! | sequence of scalars          | repeated `key=v1&key=v2`       |
//! | object / sequence of objects | `key=<JSON text>`              |
//! | `None` / null                | omitted                        |
//!
//! Octets are escaped per OAuth 2.1 Appendix B (UTF-8, with space encoded as
//! `+`). When parsing, a parameter whose target type is a single value is
//! rejected if it appears more than once (RFC 6749 §3.1); a sequence-typed
//! parameter is read from repeated keys, or from a single JSON-array value.
//! Enum-typed parameters round-trip too: a unit variant is a bare name
//! (`prompt=consent`), and a data-carrying or `#[serde(tag = "…")]` variant is
//! carried as JSON text.
//!
//! ```
//! # use huskarl_core::oauth_form;
//! # use serde::{Serialize, Deserialize};
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct Request {
//!     grant_type: String,
//!     resource: Vec<String>,
//! }
//!
//! let req = Request {
//!     grant_type: "authorization_code".into(),
//!     resource: vec!["https://api.example/".into()],
//! };
//! let body = oauth_form::to_string(&req).unwrap();
//! assert_eq!(oauth_form::from_str::<Request>(&body).unwrap(), req);
//! ```

use std::fmt;

use serde::{
    Deserialize, Serialize,
    de::{self, IntoDeserializer, MapAccess, SeqAccess, Visitor},
    ser::{self, Impossible, SerializeMap, SerializeSeq, SerializeStruct, SerializeTuple},
};
use snafu::Snafu;

// ============================ Error ============================

/// An error returned while serializing or deserializing OAuth form data.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    /// A single-valued parameter appeared more than once. RFC 6749 §3.1
    /// requires request and response parameters to appear at most once.
    #[snafu(display(
        "parameter `{name}` appears {count} times but a single value is expected (RFC 6749 §3.1)"
    ))]
    DuplicateParameter {
        /// The name of the repeated parameter.
        name: String,
        /// The number of times it appeared.
        count: usize,
    },

    /// A structured parameter value could not be encoded to, or decoded from, JSON.
    #[snafu(display("invalid JSON in a form parameter value"), context(false))]
    Json {
        /// The underlying JSON error.
        source: serde_json::Error,
    },

    /// Any other serialization or deserialization failure (including malformed
    /// input and unsupported value shapes).
    #[snafu(display("{message}"))]
    Other {
        /// A description of the failure.
        message: String,
    },
}

impl Error {
    fn other(message: impl Into<String>) -> Self {
        Error::Other {
            message: message.into(),
        }
    }
}

impl ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error::other(msg.to_string())
    }
}
impl de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error::other(msg.to_string())
    }
}

fn top_level_err<T>() -> Result<T, Error> {
    Err(Error::other(
        "value must be a struct, map, or sequence of key/value pairs",
    ))
}

// ============================ Serialize ============================

/// Serializes `value` to an `application/x-www-form-urlencoded` string.
///
/// `value` must serialize as a struct, a map, or a sequence of `(key, value)`
/// pairs. See the [module documentation](self) for the per-parameter encoding.
///
/// # Errors
/// Returns an error if `value` is not one of those top-level shapes, or if a
/// nested structured value cannot be encoded as JSON.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    let mut ser = FormSerializer::new();
    value.serialize(&mut ser)?;
    Ok(ser.out.finish())
}

/// Serializes `value` and appends the result to `out`.
///
/// The caller is responsible for any `&` separator between existing content and
/// the appended pairs. Useful for adding parameters to an already-built body.
///
/// # Errors
/// As for [`to_string`].
pub fn push_to_string<T: Serialize + ?Sized>(out: &mut String, value: &T) -> Result<(), Error> {
    let mut ser = FormSerializer::new();
    value.serialize(&mut ser)?;
    out.push_str(&ser.out.finish());
    Ok(())
}

fn is_scalar(v: &serde_json::Value) -> bool {
    v.is_string() || v.is_number() || v.is_boolean()
}

/// Renders a scalar JSON value as its bare form-field text (no JSON quoting).
fn scalar_text(v: serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s,
        other => other.to_string(),
    }
}

struct FormSerializer {
    out: form_urlencoded::Serializer<'static, String>,
}

impl FormSerializer {
    fn new() -> Self {
        Self {
            out: form_urlencoded::Serializer::new(String::new()),
        }
    }

    /// Emits one field. Scalars — including secret strings — stream straight
    /// through the percent-encoder with no intermediate owned copy; only
    /// non-scalar structured values fall back to a `serde_json` round-trip, and
    /// those never carry secrets in OAuth.
    fn add_field<T: Serialize + ?Sized>(&mut self, key: &str, value: &T) -> Result<(), Error> {
        match value.serialize(ScalarProbe {
            out: &mut self.out,
            key,
        }) {
            Ok(()) => Ok(()),
            Err(Probe::NotScalar) => self.add_structured_field(key, value),
            Err(Probe::Fail(e)) => Err(e),
        }
    }

    /// Fallback for non-scalar fields: a sequence of scalars becomes repeated
    /// keys; an object (or sequence of objects) becomes one JSON-string value,
    /// re-serialized from the original `value` so nested object key order is
    /// preserved. Reached only for non-secret structured data.
    fn add_structured_field<T: Serialize + ?Sized>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<(), Error> {
        use serde_json::Value::{Array, Bool, Null, Number, Object, String as JString};
        match serde_json::to_value(value)? {
            Null => {}
            Bool(b) => {
                self.out.append_pair(key, &b.to_string());
            }
            Number(n) => {
                self.out.append_pair(key, &n.to_string());
            }
            JString(s) => {
                self.out.append_pair(key, &s);
            }
            Array(a) if a.iter().all(is_scalar) => {
                for e in a {
                    self.out.append_pair(key, &scalar_text(e));
                }
            }
            Array(_) | Object(_) => {
                self.out.append_pair(key, &serde_json::to_string(value)?);
            }
        }
        Ok(())
    }
}

impl<'a> ser::Serializer for &'a mut FormSerializer {
    type Ok = ();
    type Error = Error;
    type SerializeStruct = StructSer<'a>;
    type SerializeMap = MapSer<'a>;
    type SerializeSeq = SeqSer<'a>;
    type SerializeTuple = Impossible<(), Error>;
    type SerializeTupleStruct = Impossible<(), Error>;
    type SerializeTupleVariant = Impossible<(), Error>;
    type SerializeStructVariant = Impossible<(), Error>;

    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeStruct, Error> {
        Ok(StructSer { ser: self })
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Ok(MapSer {
            ser: self,
            key: None,
        })
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Ok(SeqSer { ser: self })
    }

    fn serialize_some<T: Serialize + ?Sized>(self, v: &T) -> Result<(), Error> {
        v.serialize(self)
    }
    fn serialize_none(self) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        v: &T,
    ) -> Result<(), Error> {
        v.serialize(self)
    }

    fn serialize_bool(self, _: bool) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_i8(self, _: i8) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_i16(self, _: i16) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_i32(self, _: i32) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_i64(self, _: i64) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_u8(self, _: u8) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_u16(self, _: u16) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_u32(self, _: u32) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_u64(self, _: u64) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_f32(self, _: f32) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_f64(self, _: f64) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_char(self, _: char) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_str(self, _: &str) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_bytes(self, _: &[u8]) -> Result<(), Error> {
        top_level_err()
    }
    // `()`, a unit struct, and `None` all denote "no parameters" — they
    // serialize to an empty body, so a request with no form parameters can use
    // `()` as its form type.
    fn serialize_unit(self) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), Error> {
        top_level_err()
    }
    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Error> {
        top_level_err()
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        top_level_err()
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        top_level_err()
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        top_level_err()
    }
}

struct StructSer<'a> {
    ser: &'a mut FormSerializer,
}
impl SerializeStruct for StructSer<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.ser.add_field(key, value)
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

struct MapSer<'a> {
    ser: &'a mut FormSerializer,
    key: Option<String>,
}
impl SerializeMap for MapSer<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Error> {
        let k = serde_json::to_value(key)?;
        let s = k
            .as_str()
            .ok_or_else(|| Error::other("map key must be a string"))?;
        self.key = Some(s.to_string());
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let key = self
            .key
            .take()
            .ok_or_else(|| Error::other("serialize_value called before serialize_key"))?;
        self.ser.add_field(&key, value)
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

/// Top-level sequence of `(key, value)` pairs (e.g. a `Vec<(&str, _)>`).
struct SeqSer<'a> {
    ser: &'a mut FormSerializer,
}
impl SerializeSeq for SeqSer<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        // Each element is a `(key, value)` pair; route the value through
        // `add_field` so a secret value streams without an intermediate copy.
        value.serialize(PairSerializer { ser: self.ser })
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

// ---- scalar fast-path (keeps secret values out of intermediate buffers) ----

/// [`ScalarProbe`] error: distinguishes "not a scalar, take the structured
/// path" from a genuine serialization failure.
enum Probe {
    NotScalar,
    Fail(Error),
}
impl fmt::Display for Probe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Probe::NotScalar => f.write_str("value is not a scalar"),
            Probe::Fail(e) => e.fmt(f),
        }
    }
}
impl fmt::Debug for Probe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}
impl std::error::Error for Probe {}
impl ser::Error for Probe {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Probe::Fail(Error::other(msg.to_string()))
    }
}

/// Serializer that emits a single scalar field directly into the output (no
/// intermediate owned `String`), and reports [`Probe::NotScalar`] for anything
/// that is not a scalar so the caller can take the structured path.
struct ScalarProbe<'a> {
    out: &'a mut form_urlencoded::Serializer<'static, String>,
    key: &'a str,
}
impl ScalarProbe<'_> {
    fn emit(self, value: &str) {
        self.out.append_pair(self.key, value);
    }
}
impl ser::Serializer for ScalarProbe<'_> {
    type Ok = ();
    type Error = Probe;
    type SerializeSeq = Impossible<(), Probe>;
    type SerializeTuple = Impossible<(), Probe>;
    type SerializeTupleStruct = Impossible<(), Probe>;
    type SerializeTupleVariant = Impossible<(), Probe>;
    type SerializeMap = Impossible<(), Probe>;
    type SerializeStruct = Impossible<(), Probe>;
    type SerializeStructVariant = Impossible<(), Probe>;

    fn serialize_str(self, v: &str) -> Result<(), Probe> {
        self.emit(v);
        Ok(())
    }
    fn serialize_bool(self, v: bool) -> Result<(), Probe> {
        self.emit(if v { "true" } else { "false" });
        Ok(())
    }
    fn serialize_i64(self, v: i64) -> Result<(), Probe> {
        self.emit(&v.to_string());
        Ok(())
    }
    fn serialize_i8(self, v: i8) -> Result<(), Probe> {
        self.serialize_i64(i64::from(v))
    }
    fn serialize_i16(self, v: i16) -> Result<(), Probe> {
        self.serialize_i64(i64::from(v))
    }
    fn serialize_i32(self, v: i32) -> Result<(), Probe> {
        self.serialize_i64(i64::from(v))
    }
    fn serialize_u64(self, v: u64) -> Result<(), Probe> {
        self.emit(&v.to_string());
        Ok(())
    }
    fn serialize_u8(self, v: u8) -> Result<(), Probe> {
        self.serialize_u64(u64::from(v))
    }
    fn serialize_u16(self, v: u16) -> Result<(), Probe> {
        self.serialize_u64(u64::from(v))
    }
    fn serialize_u32(self, v: u32) -> Result<(), Probe> {
        self.serialize_u64(u64::from(v))
    }
    fn serialize_f64(self, v: f64) -> Result<(), Probe> {
        self.emit(&v.to_string());
        Ok(())
    }
    fn serialize_f32(self, v: f32) -> Result<(), Probe> {
        self.serialize_f64(f64::from(v))
    }
    fn serialize_char(self, v: char) -> Result<(), Probe> {
        self.emit(v.encode_utf8(&mut [0u8; 4]));
        Ok(())
    }
    fn serialize_none(self) -> Result<(), Probe> {
        Ok(())
    }
    fn serialize_unit(self) -> Result<(), Probe> {
        Ok(())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Probe> {
        Ok(())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, v: &T) -> Result<(), Probe> {
        v.serialize(self)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        v: &T,
    ) -> Result<(), Probe> {
        v.serialize(self)
    }

    fn serialize_bytes(self, _: &[u8]) -> Result<(), Probe> {
        Err(Probe::NotScalar)
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<(), Probe> {
        Err(Probe::NotScalar)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), Probe> {
        Err(Probe::NotScalar)
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Probe> {
        Err(Probe::NotScalar)
    }
    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Probe> {
        Err(Probe::NotScalar)
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Probe> {
        Err(Probe::NotScalar)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Probe> {
        Err(Probe::NotScalar)
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Probe> {
        Err(Probe::NotScalar)
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeStruct, Probe> {
        Err(Probe::NotScalar)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Probe> {
        Err(Probe::NotScalar)
    }
}

// ---- top-level `(key, value)` pair elements (for `Vec<(K, V)>` inputs) ----

fn pair_err<T>() -> Result<T, Error> {
    Err(Error::other("sequence element must be a (key, value) pair"))
}

/// Serializes one `(key, value)` pair, routing the value through
/// [`FormSerializer::add_field`] so a secret value streams without a copy.
struct PairSerializer<'a> {
    ser: &'a mut FormSerializer,
}
impl<'a> ser::Serializer for PairSerializer<'a> {
    type Ok = ();
    type Error = Error;
    type SerializeTuple = PairBuilder<'a>;
    type SerializeSeq = Impossible<(), Error>;
    type SerializeTupleStruct = Impossible<(), Error>;
    type SerializeTupleVariant = Impossible<(), Error>;
    type SerializeMap = Impossible<(), Error>;
    type SerializeStruct = Impossible<(), Error>;
    type SerializeStructVariant = Impossible<(), Error>;

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Error> {
        if len == 2 {
            Ok(PairBuilder {
                ser: self.ser,
                key: None,
            })
        } else {
            pair_err()
        }
    }

    fn serialize_bool(self, _: bool) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_i8(self, _: i8) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_i16(self, _: i16) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_i32(self, _: i32) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_i64(self, _: i64) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_u8(self, _: u8) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_u16(self, _: u16) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_u32(self, _: u32) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_u64(self, _: u64) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_f32(self, _: f32) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_f64(self, _: f64) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_char(self, _: char) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_str(self, _: &str) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_bytes(self, _: &[u8]) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_none(self) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_some<T: Serialize + ?Sized>(self, _: &T) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_unit(self) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), Error> {
        pair_err()
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        pair_err()
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        pair_err()
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        pair_err()
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Error> {
        pair_err()
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeStruct, Error> {
        pair_err()
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        pair_err()
    }
}

/// Collects a `(key, value)` tuple: key as a string, then the value routed
/// through [`FormSerializer::add_field`].
struct PairBuilder<'a> {
    ser: &'a mut FormSerializer,
    key: Option<String>,
}
impl SerializeTuple for PairBuilder<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        match self.key.take() {
            None => {
                self.key = Some(key_string(value)?);
                Ok(())
            }
            Some(key) => self.ser.add_field(&key, value),
        }
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

/// Extracts a pair key as an owned string (keys are parameter names, never
/// secret, so a copy here is fine).
fn key_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    serde_json::to_value(value)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::other("pair key must be a string"))
}

// ============================ Deserialize ============================

/// Parses `application/x-www-form-urlencoded` data into `T`.
///
/// The target field types drive interpretation: a single-valued field rejects a
/// parameter that appears more than once (RFC 6749 §3.1); a sequence-typed field
/// is filled from repeated keys, or from a single JSON-array value (the
/// structured case). See the [module documentation](self).
///
/// # Errors
/// Returns an error on malformed structure, a duplicated single-valued
/// parameter, or invalid nested JSON.
pub fn from_str<'de, T: Deserialize<'de>>(input: &str) -> Result<T, Error> {
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for (k, v) in form_urlencoded::parse(input.as_bytes()) {
        match groups.iter_mut().find(|(gk, _)| *gk == k) {
            Some(g) => g.1.push(v.into_owned()),
            None => groups.push((k.into_owned(), vec![v.into_owned()])),
        }
    }
    T::deserialize(FormDeserializer { groups })
}

struct FormDeserializer {
    groups: Vec<(String, Vec<String>)>,
}
impl<'de> de::Deserializer<'de> for FormDeserializer {
    type Error = Error;
    fn deserialize_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_map(GroupsMap {
            iter: self.groups.into_iter(),
            entry: None,
        })
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_any(v)
    }
    fn deserialize_map<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        self.deserialize_any(v)
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes
        byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct
        enum identifier ignored_any
    }
}

struct GroupsMap {
    iter: std::vec::IntoIter<(String, Vec<String>)>,
    entry: Option<(String, Vec<String>)>,
}
impl<'de> MapAccess<'de> for GroupsMap {
    type Error = Error;
    fn next_key_seed<K: de::DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        match self.iter.next() {
            Some((k, vs)) => {
                self.entry = Some((k.clone(), vs));
                seed.deserialize(k.into_deserializer()).map(Some)
            }
            None => Ok(None),
        }
    }
    fn next_value_seed<V: de::DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let (name, values) = self
            .entry
            .take()
            .ok_or_else(|| Error::other("next_value_seed called before next_key_seed"))?;
        seed.deserialize(ValueDe { name, values })
    }
}

/// Deserializer for one parameter's group of (percent-decoded) string values.
struct ValueDe {
    name: String,
    values: Vec<String>,
}
impl ValueDe {
    /// Enforces the single-value rule (RFC 6749 §3.1: a parameter MUST NOT
    /// appear more than once), returning the borrowed lone value.
    fn single(&self) -> Result<&str, Error> {
        match self.values.as_slice() {
            [one] => Ok(one),
            many => Err(Error::DuplicateParameter {
                name: self.name.clone(),
                count: many.len(),
            }),
        }
    }
    fn into_single(self) -> Result<String, Error> {
        self.single()?;
        self.values
            .into_iter()
            .next()
            .ok_or_else(|| Error::other("empty parameter group"))
    }
}
impl<'de> de::Deserializer<'de> for ValueDe {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        if self.values.len() > 1 {
            return self.deserialize_seq(v);
        }
        let s = self.into_single()?;
        // A JSON object or array value (a structured value, or an internally
        // tagged / untagged enum) is handed to serde_json; otherwise it is a
        // plain string.
        match serde_json::from_str::<serde_json::Value>(&s) {
            Ok(j) if j.is_object() || j.is_array() => {
                de::Deserializer::deserialize_any(j, v).map_err(Error::from)
            }
            _ => v.visit_string(s),
        }
    }
    fn deserialize_str<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_str(self.single()?)
    }
    fn deserialize_string<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_string(self.into_single()?)
    }
    fn deserialize_bool<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        let b = self
            .single()?
            .parse()
            .map_err(|_| Error::other("invalid boolean"))?;
        v.visit_bool(b)
    }
    fn deserialize_i64<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        let n = self
            .single()?
            .parse()
            .map_err(|_| Error::other("invalid integer"))?;
        v.visit_i64(n)
    }
    fn deserialize_u64<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        let n = self
            .single()?
            .parse()
            .map_err(|_| Error::other("invalid integer"))?;
        v.visit_u64(n)
    }
    fn deserialize_option<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_some(self) // key present => Some
    }
    fn deserialize_seq<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        if self.values.len() > 1 {
            // Repeated key => sequence of scalar strings.
            return v.visit_seq(StrSeq {
                iter: self.values.into_iter(),
            });
        }
        // A single value may be a JSON array (the structured case, e.g.
        // authorization_details) or a lone scalar requested as a one-element seq.
        match serde_json::from_str::<serde_json::Value>(self.single()?) {
            Ok(j @ serde_json::Value::Array(_)) => {
                de::Deserializer::deserialize_seq(j, v).map_err(Error::from)
            }
            _ => v.visit_seq(StrSeq {
                iter: self.values.into_iter(),
            }),
        }
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_map(v)
    }
    fn deserialize_map<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        let j: serde_json::Value = serde_json::from_str(self.single()?)?;
        de::Deserializer::deserialize_map(j, v).map_err(Error::from)
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, Error> {
        let s = self.into_single()?;
        // A JSON object is a data-carrying variant (externally or adjacently
        // tagged) handled by serde_json; a bare string is a unit variant.
        match serde_json::from_str::<serde_json::Value>(&s) {
            Ok(j @ serde_json::Value::Object(_)) => {
                de::Deserializer::deserialize_enum(j, name, variants, v).map_err(Error::from)
            }
            _ => s.into_deserializer().deserialize_enum(name, variants, v),
        }
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_unit()
    }
    serde::forward_to_deserialize_any! {
        i8 i16 i32 u8 u16 u32 f32 f64 char bytes byte_buf unit unit_struct
        newtype_struct tuple tuple_struct identifier
    }
}

struct StrSeq {
    iter: std::vec::IntoIter<String>,
}
impl<'de> SeqAccess<'de> for StrSeq {
    type Error = Error;
    fn next_element_seed<T: de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        match self.iter.next() {
            Some(s) => seed.deserialize(s.into_deserializer()).map(Some),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::{Error, from_str, push_to_string, to_string};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Detail {
        r#type: String,
        #[serde(flatten)]
        rest: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Payload {
        response_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        state: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        resource: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        authorization_details: Option<Vec<Detail>>,
    }

    fn sample() -> Payload {
        let detail = Detail {
            r#type: "payment_initiation".into(),
            rest: [("actions".to_string(), serde_json::json!(["initiate"]))]
                .into_iter()
                .collect(),
        };
        Payload {
            response_type: "code".into(),
            scope: Some("openid payments".into()),
            state: "af0ifjsldkj".into(),
            resource: Some(vec![
                "https://a.example/".into(),
                "https://b.example/".into(),
            ]),
            authorization_details: Some(vec![detail]),
        }
    }

    #[test]
    fn scalars_and_space_follow_appendix_b() {
        let form = to_string(&sample()).unwrap();
        assert!(form.contains("response_type=code"), "{form}");
        assert!(form.contains("scope=openid+payments"), "{form}");
        assert!(form.contains("state=af0ifjsldkj"), "{form}");
    }

    #[test]
    fn scalar_sequence_is_repeated_keys_not_json() {
        let form = to_string(&sample()).unwrap();
        assert_eq!(form.matches("resource=").count(), 2, "{form}");
        assert!(
            !form.contains("resource=%5B"),
            "must not be a JSON array: {form}"
        );
    }

    #[test]
    fn structured_param_is_one_json_string_value() {
        let form = to_string(&sample()).unwrap();
        assert_eq!(form.matches("authorization_details=").count(), 1, "{form}");
        assert!(form.contains("authorization_details=%5B%7B"), "{form}");
    }

    #[test]
    fn top_level_field_order_is_preserved() {
        let form = to_string(&sample()).unwrap();
        let rt = form.find("response_type").unwrap();
        let st = form.find("state").unwrap();
        assert!(rt < st, "declaration order preserved: {form}");
    }

    #[test]
    fn round_trips() {
        let original = sample();
        let form = to_string(&original).unwrap();
        let back: Payload = from_str(&form).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn duplicate_single_valued_param_errors() {
        // RFC 6749 §3.1, surfaced as a typed variant naming the parameter.
        let r: Result<Payload, _> = from_str("response_type=code&state=a&state=b");
        assert!(
            matches!(r, Err(Error::DuplicateParameter { ref name, count: 2 }) if name == "state"),
            "{r:?}"
        );
    }

    #[test]
    fn single_value_into_vec_is_one_element() {
        let p: Payload =
            from_str("response_type=code&state=s&resource=https%3A%2F%2Fonly").unwrap();
        assert_eq!(p.resource.unwrap().len(), 1);
    }

    #[test]
    fn top_level_sequence_of_pairs() {
        let pairs = vec![("client_id", "abc"), ("client_secret", "s3cr3t")];
        let form = to_string(&pairs).unwrap();
        assert!(form.contains("client_id=abc"), "{form}");
        assert!(form.contains("client_secret=s3cr3t"), "{form}");
    }

    #[test]
    fn push_appends_pairs() {
        let mut body = String::from("grant_type=authorization_code");
        body.push('&');
        push_to_string(&mut body, &vec![("client_id", "abc")]).unwrap();
        assert_eq!(body, "grant_type=authorization_code&client_id=abc");
    }

    #[test]
    fn pair_value_wrapper_streams_through_scalar_path() {
        // A wrapper that serializes as its inner string (like a secret value).
        // It must route through the scalar fast path (newtype -> str), not the
        // structured/`to_value` fallback.
        #[derive(Serialize)]
        struct Secret(String);

        let pairs = vec![("client_secret", Secret("s3cr3t".into()))];
        assert_eq!(to_string(&pairs).unwrap(), "client_secret=s3cr3t");
    }

    #[test]
    fn unit_enum_round_trips() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        #[serde(rename_all = "snake_case")]
        enum Prompt {
            Login,
            Consent,
        }
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct S {
            prompt: Prompt,
        }

        let v = S {
            prompt: Prompt::Consent,
        };
        let form = to_string(&v).unwrap();
        assert_eq!(form, "prompt=consent");
        assert_eq!(from_str::<S>(&form).unwrap(), v);
    }

    #[test]
    fn no_param_forms_serialize_to_empty() {
        // `()`, a unit struct, and `None` denote a request with no body
        // parameters — they serialize to an empty body (client-auth parameters
        // are appended separately via `push_to_string`).
        #[derive(Serialize)]
        struct NoParams;
        assert_eq!(to_string(&()).unwrap(), "");
        assert_eq!(to_string(&NoParams).unwrap(), "");
        assert_eq!(to_string(&Option::<NoParams>::None).unwrap(), "");
    }

    #[test]
    fn externally_tagged_enum_round_trips() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        enum Variant {
            Unit,
            Data { x: u32 },
        }
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct S {
            v: Variant,
        }

        for value in [
            S { v: Variant::Unit },
            S {
                v: Variant::Data { x: 7 },
            },
        ] {
            let form = to_string(&value).unwrap();
            assert_eq!(from_str::<S>(&form).unwrap(), value, "form = {form}");
        }
    }

    #[test]
    fn internally_tagged_enum_round_trips() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        #[serde(tag = "type", rename_all = "snake_case")]
        enum Detail {
            Payment { amount: String },
            Account,
        }
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct S {
            detail: Detail,
        }

        for value in [
            S {
                detail: Detail::Payment {
                    amount: "12.00".into(),
                },
            },
            S {
                detail: Detail::Account,
            },
        ] {
            let form = to_string(&value).unwrap();
            assert_eq!(from_str::<S>(&form).unwrap(), value, "form = {form}");
        }
    }
}
