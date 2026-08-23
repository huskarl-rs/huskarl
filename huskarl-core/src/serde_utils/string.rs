//! Serde helpers for string / array-of-strings duality.
//!
//! Several OIDC and OAuth 2.0 claims (notably JWT `aud`, RFC 7519 §4.1.3) accept
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

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    /// Mirrors the `aud` attributes on
    /// [`JwtClaims`](crate::jwt::JwtClaims) — `default` for an absent claim,
    /// `skip_serializing_if` to omit the empty case.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct WithAud {
        #[serde(
            default,
            skip_serializing_if = "Vec::is_empty",
            with = "super::string_or_vec"
        )]
        aud: Vec<String>,
    }

    /// Without `skip_serializing_if`, to pin the empty → `null` case.
    #[derive(Debug, Serialize)]
    struct AlwaysAud {
        #[serde(with = "super::string_or_vec")]
        aud: Vec<String>,
    }

    // --- accepted shapes ---

    // Audiences are compared verbatim, so nothing here may be trimmed,
    // deduplicated, or reordered.
    #[rstest]
    #[case::empty_array(json!({"aud": []}), vec![])]
    #[case::empty_string_is_an_audience(json!({"aud": ""}), vec![""])]
    #[case::empty_string_in_array(json!({"aud": ["a", ""]}), vec!["a", ""])]
    #[case::duplicates_retained(json!({"aud": ["a", "a"]}), vec!["a", "a"])]
    #[case::order_retained(json!({"aud": ["b", "a"]}), vec!["b", "a"])]
    #[case::surrounding_space_retained(json!({"aud": " a "}), vec![" a "])]
    #[case::interior_nul_retained(json!({"aud": "a\0b"}), vec!["a\0b"])]
    #[case::non_ascii_retained(json!({"aud": "ｈｔｔｐｓ://例.example"}), vec!["ｈｔｔｐｓ://例.example"])]
    fn deserialize_accepts(#[case] input: serde_json::Value, #[case] expected: Vec<&str>) {
        let parsed: WithAud = serde_json::from_value(input).unwrap();
        assert_eq!(parsed.aud, expected);
    }

    #[test]
    fn deserialize_accepts_a_large_array() {
        let audiences: Vec<String> = (0..10_000)
            .map(|n| format!("https://rs{n}.example"))
            .collect();
        let parsed: WithAud = serde_json::from_value(json!({"aud": audiences})).unwrap();
        assert_eq!(parsed.aud.len(), 10_000);
        assert_eq!(parsed.aud[9_999], "https://rs9999.example");
    }

    // --- rejected shapes ---

    // Anything that is not a string or an array of strings must fail the parse
    // outright rather than coerce to a stringified audience that could then match
    // a configured one.
    #[rstest]
    #[case::number(json!({"aud": 1}))]
    #[case::float(json!({"aud": 1.5}))]
    #[case::bool(json!({"aud": true}))]
    #[case::object(json!({"aud": {"aud": "a"}}))]
    #[case::number_in_array(json!({"aud": ["a", 1]}))]
    #[case::bool_in_array(json!({"aud": ["a", true]}))]
    #[case::null_in_array(json!({"aud": ["a", null]}))]
    #[case::nested_array(json!({"aud": [["a"]]}))]
    #[case::object_in_array(json!({"aud": [{"a": 1}]}))]
    fn deserialize_rejects(#[case] input: serde_json::Value) {
        serde_json::from_value::<WithAud>(input).unwrap_err();
    }

    #[test]
    fn deserialize_error_names_the_expected_shape() {
        let err = serde_json::from_value::<WithAud>(json!({"aud": 1})).unwrap_err();
        assert!(
            err.to_string().contains("a string or array of strings"),
            "unexpected message: {err}"
        );
    }

    // --- serialization ---

    #[rstest]
    #[case::empty_is_omitted(vec![], json!({}))]
    #[case::one_is_bare(vec!["a"], json!({"aud": "a"}))]
    #[case::many_is_an_array(vec!["a", "b"], json!({"aud": ["a", "b"]}))]
    fn serialize_shape(#[case] aud: Vec<&str>, #[case] expected: serde_json::Value) {
        let aud = aud.into_iter().map(Into::into).collect();
        assert_eq!(serde_json::to_value(WithAud { aud }).unwrap(), expected);
    }

    // Only `skip_serializing_if` suppresses the empty case; unguarded it emits
    // `null`, which this adapter reads back as empty.
    #[test]
    fn serialize_empty_without_skip_emits_null() {
        let v = serde_json::to_value(AlwaysAud { aud: vec![] }).unwrap();
        assert_eq!(v, json!({"aud": null}));
        let parsed: WithAud = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.aud, Vec::<String>::new());
    }

    // A round trip preserves the audience list but not the wire shape: a
    // one-element array re-serializes as a bare string. Signatures cover the
    // encoded form, so a re-serialized JWT is not byte-identical to the original.
    #[test]
    fn single_element_array_reserializes_as_a_bare_string() {
        let parsed: WithAud = serde_json::from_value(json!({"aud": ["a"]})).unwrap();
        assert_eq!(parsed.aud, vec!["a"]);
        assert_eq!(serde_json::to_value(parsed).unwrap(), json!({"aud": "a"}));
    }
}
