use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

use super::*;

// Example public key from https://www.rfc-editor.org/rfc/rfc7517.html#appendix-A.1
#[test]
fn test_parse_jwks_appendix_a1() {
    let jwks_json = r#"{"keys":[
            {"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"},
            {"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}
        ]}"#;

    let jwks: PublicJwks = serde_json::from_str::<Jwks>(jwks_json).unwrap().into();

    let key1 = PublicJwk::builder()
        .key(
            EcPublicKey::builder()
                .crv("P-256")
                .x(BASE64_URL_SAFE_NO_PAD
                    .decode("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
                    .unwrap())
                .y(BASE64_URL_SAFE_NO_PAD
                    .decode("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
                    .unwrap()),
        )
        .key_use(KeyUse::Encrypt)
        .kid("1")
        .build();

    let key2 = PublicJwk::builder().key(
        RsaPublicKey::builder()
            .n(BASE64_URL_SAFE_NO_PAD.decode(
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
            ).unwrap())
            .e(BASE64_URL_SAFE_NO_PAD.decode("AQAB").unwrap())
    )
    .algorithm("RS256")
    .kid("2011-04-29")
    .build();

    assert_eq!(jwks.keys, vec![key1, key2]);
}

#[test]
fn test_unknown_curve_parses() {
    // Unknown curve should parse successfully
    let unknown_curve = r#"{"kty":"EC","crv":"brainpoolP256r1","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
    let _: PublicJwk = serde_json::from_str(unknown_curve).unwrap();
}

// One unrecognized key in an IdP's JWKS (e.g. a future post-quantum kty) must
// not fail the whole fetch — the recognized keys must remain usable.
#[test]
fn test_jwks_with_unknown_kty_parses() {
    let jwks_json = r#"{"keys":[
            {"kty":"AKP","alg":"ML-DSA-44","pub":"dGVzdA","kid":"pqc-1"},
            {"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}
        ]}"#;

    let jwks: Jwks = serde_json::from_str(jwks_json).unwrap();
    assert_eq!(jwks.keys.len(), 2);
    assert_eq!(jwks.keys[0].key, Key::Unknown);
    assert_eq!(jwks.keys[0].kid.as_deref(), Some("pqc-1"));
    assert!(matches!(&jwks.keys[1].key, Key::Ec(_)));

    // The unknown key is dropped on conversion; the usable key survives.
    let public: PublicJwks = jwks.into();
    assert_eq!(public.keys.len(), 1);
    assert_eq!(public.keys[0].kid.as_deref(), Some("1"));
}

#[test]
fn test_unknown_key_use_parses() {
    let jwk_json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"attest"}"#;
    let jwk: PublicJwk = serde_json::from_str(jwk_json).unwrap();
    assert_eq!(jwk.key_use, Some(KeyUse::Unknown));
}

#[test]
fn test_unknown_key_operation_parses() {
    let jwk_json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","key_ops":["verify","attest"]}"#;
    let jwk: PublicJwk = serde_json::from_str(jwk_json).unwrap();
    assert_eq!(
        jwk.key_operations,
        Some(vec![KeyOperation::Verify, KeyOperation::Unknown])
    );
}

#[test]
fn test_known_key_operations_parse() {
    let ops_json =
        r#"["sign","verify","encrypt","decrypt","wrapKey","unwrapKey","deriveKey","deriveBits"]"#;
    let ops: Vec<KeyOperation> = serde_json::from_str(ops_json).unwrap();
    assert_eq!(
        ops,
        vec![
            KeyOperation::Sign,
            KeyOperation::Verify,
            KeyOperation::Encrypt,
            KeyOperation::Decrypt,
            KeyOperation::WrapKey,
            KeyOperation::UnwrapKey,
            KeyOperation::DeriveKey,
            KeyOperation::DeriveBits,
        ]
    );
}

// Unknown variants carry no wire representation; serializing them must be an
// error rather than emitting a bogus value like "kty":"Unknown".
#[test]
fn test_unknown_variants_do_not_serialize() {
    assert!(serde_json::to_string(&Key::Unknown).is_err());
    assert!(serde_json::to_string(&KeyUse::Unknown).is_err());
    assert!(serde_json::to_string(&KeyOperation::Unknown).is_err());
}

// --- Private key type tests ---

// RFC 7517 Appendix A.2 — JWK Set containing private keys (EC + RSA)
#[test]
fn test_parse_jwks_appendix_a2() {
    let jwks_json = r#"{"keys":
          [
            {"kty":"EC",
             "crv":"P-256",
             "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
             "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
             "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
             "use":"enc",
             "kid":"1"},

            {"kty":"RSA",
             "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
             "e":"AQAB",
             "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
             "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
             "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
             "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
             "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
             "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
             "alg":"RS256",
             "kid":"2011-04-29"}
          ]
        }
"#;

    let jwks: Jwks = serde_json::from_str(jwks_json).unwrap();
    assert_eq!(jwks.keys.len(), 2);

    // First key is EC with private material
    assert!(matches!(&jwks.keys[0].key, Key::Ec(_)));
    assert_eq!(jwks.keys[0].key_use, Some(KeyUse::Encrypt));
    assert_eq!(jwks.keys[0].kid.as_deref(), Some("1"));

    // Second key is RSA with CRT params
    let Key::Rsa(rsa) = &jwks.keys[1].key else {
        unreachable!("Expected RSA key");
    };
    assert!(rsa.p.is_some());
    assert!(rsa.q.is_some());
    assert!(rsa.dp.is_some());
    assert!(rsa.dq.is_some());
    assert!(rsa.qi.is_some());
    assert_eq!(jwks.keys[1].algorithm.as_deref(), Some("RS256"));
    assert_eq!(jwks.keys[1].kid.as_deref(), Some("2011-04-29"));
}

// RFC 7517 Appendix A.3 — Symmetric keys
#[test]
fn test_parse_jwks_appendix_a3() {
    let jwks_json = r#"{"keys":[
            {"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"},
            {"kty":"oct","k":"AyM32fqVEfJG4jS1GDRTE3ElK08OuKBj","kid":"HMAC key used in JWS spec Appendix A.1 example"}
        ]}"#;

    let jwks: Jwks = serde_json::from_str(jwks_json).unwrap();
    assert_eq!(jwks.keys.len(), 2);

    assert!(matches!(&jwks.keys[0].key, Key::Oct(_)));
    assert_eq!(jwks.keys[0].algorithm.as_deref(), Some("A128KW"));

    assert!(matches!(&jwks.keys[1].key, Key::Oct(_)));
    assert_eq!(
        jwks.keys[1].kid.as_deref(),
        Some("HMAC key used in JWS spec Appendix A.1 example")
    );
}

#[test]
fn test_roundtrip_ec_key() {
    let json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let serialized = serde_json::to_string(&jwk).unwrap();
    let deserialized: Jwk = serde_json::from_str(&serialized).unwrap();
    assert_eq!(jwk, deserialized);
}

#[test]
fn test_roundtrip_rsa_key() {
    let json = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYjqxnf7vQoSmcnVQ"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let serialized = serde_json::to_string(&jwk).unwrap();
    let deserialized: Jwk = serde_json::from_str(&serialized).unwrap();
    assert_eq!(jwk, deserialized);
}

// RFC 8037 Appendix A — Ed25519 private key
#[test]
fn test_roundtrip_okp_key() {
    let json = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let serialized = serde_json::to_string(&jwk).unwrap();
    let deserialized: Jwk = serde_json::from_str(&serialized).unwrap();
    assert_eq!(jwk, deserialized);
}

#[test]
fn test_roundtrip_oct_key() {
    let json = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let serialized = serde_json::to_string(&jwk).unwrap();
    let deserialized: Jwk = serde_json::from_str(&serialized).unwrap();
    assert_eq!(jwk, deserialized);
}

#[test]
fn test_public_jwk_strips_private_material() {
    let ec_json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","use":"enc","kid":"1"}"#;
    let jwk: Jwk = serde_json::from_str(ec_json).unwrap();
    let public = jwk.public_jwk().unwrap();

    // Metadata preserved
    assert_eq!(public.kid.as_deref(), Some("1"));
    assert_eq!(public.key_use, Some(KeyUse::Encrypt));

    // No private material in serialized output
    let serialized = serde_json::to_string(&public).unwrap();
    assert!(!serialized.contains("\"d\""));
}

#[test]
fn test_public_jwk_none_for_oct() {
    let oct_json = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg","alg":"A128KW"}"#;
    let jwk: Jwk = serde_json::from_str(oct_json).unwrap();
    assert!(jwk.public_jwk().is_none());
}

#[test]
fn test_jwks_to_public_filters_oct() {
    let jwks_json = r#"{"keys":[
            {"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","kid":"1"},
            {"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg","alg":"A128KW"},
            {"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYjqxnf7vQoSmcnVQ","kid":"2011-04-29"}
        ]}"#;

    let jwks: Jwks = serde_json::from_str(jwks_json).unwrap();
    assert_eq!(jwks.keys.len(), 3);

    let public_jwks: PublicJwks = jwks.into();
    // Oct key filtered out, only EC and RSA remain
    assert_eq!(public_jwks.keys.len(), 2);
    assert_eq!(public_jwks.keys[0].kid.as_deref(), Some("1"));
    assert_eq!(public_jwks.keys[1].kid.as_deref(), Some("2011-04-29"));
}

#[test]
fn test_thumbprint_via_public_jwk() {
    let ec_json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}"#;
    let jwk: Jwk = serde_json::from_str(ec_json).unwrap();
    let public_jwk = jwk.public_jwk().unwrap();

    assert!(!public_jwk.thumbprint().is_empty());
}

#[test]
fn test_rsa_key_without_crt_params() {
    // RSA key with only d, no CRT params
    let json = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYjqxnf7vQoSmcnVQ"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let Key::Rsa(rsa) = &jwk.key else {
        unreachable!("Expected RSA key");
    };
    assert!(rsa.p.is_none());
    assert!(rsa.q.is_none());
    assert!(rsa.dp.is_none());
    assert!(rsa.dq.is_none());
    assert!(rsa.qi.is_none());
    // Round-trip preserves absence of CRT params
    let serialized = serde_json::to_string(&jwk).unwrap();
    assert!(!serialized.contains("\"p\""));
    assert!(!serialized.contains("\"q\""));
}

// --- Validated private key type tests ---

#[test]
fn test_private_key_ec_some() {
    let json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let pk = jwk.private_key();
    assert!(pk.is_some());
    assert!(matches!(pk.unwrap(), PrivateKey::Ec(_)));
}

#[test]
fn test_private_key_rsa_some() {
    let json = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYjqxnf7vQoSmcnVQ"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let pk = jwk.private_key();
    assert!(pk.is_some());
    assert!(matches!(pk.unwrap(), PrivateKey::Rsa(_)));
}

#[test]
fn test_private_key_okp_some() {
    let json = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let pk = jwk.private_key();
    assert!(pk.is_some());
    assert!(matches!(pk.unwrap(), PrivateKey::Okp(_)));
}

#[test]
fn test_private_key_none_when_d_absent() {
    // EC without d
    let ec_json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
    let jwk: Jwk = serde_json::from_str(ec_json).unwrap();
    assert!(jwk.private_key().is_none());

    // RSA without d
    let rsa_json = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}"#;
    let jwk: Jwk = serde_json::from_str(rsa_json).unwrap();
    assert!(jwk.private_key().is_none());

    // OKP without d
    let okp_json =
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    let jwk: Jwk = serde_json::from_str(okp_json).unwrap();
    assert!(jwk.private_key().is_none());
}

#[test]
fn test_private_key_none_for_oct_and_unknown() {
    let oct_json = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;
    let jwk: Jwk = serde_json::from_str(oct_json).unwrap();
    assert!(jwk.private_key().is_none());

    assert!(Key::Unknown.private_key().is_none());
}

#[test]
fn test_private_key_roundtrip_ec() {
    let json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let pk = jwk.private_key().unwrap();
    let key_back: Key = pk.into();
    assert_eq!(jwk.key, key_back);
}

#[test]
fn test_private_key_roundtrip_rsa() {
    let json = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYjqxnf7vQoSmcnVQ"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let pk = jwk.private_key().unwrap();
    let key_back: Key = pk.into();
    assert_eq!(jwk.key, key_back);
}

#[test]
fn test_private_key_roundtrip_okp() {
    let json = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let pk = jwk.private_key().unwrap();
    let key_back: Key = pk.into();
    assert_eq!(jwk.key, key_back);
}

#[test]
fn test_private_key_public_key_strips_material() {
    let json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let pk = jwk.private_key().unwrap();
    let public = pk.public_key();

    // Matches the public key from the full key
    assert_eq!(Some(public.clone()), jwk.key.public_key());

    // Serialized public key has no d
    let serialized = serde_json::to_string(&public).unwrap();
    assert!(!serialized.contains("\"d\""));
}

#[test]
fn test_private_key_debug_hides_secrets() {
    let json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let pk = jwk.private_key().unwrap();
    let debug = format!("{pk:?}");

    // Should not contain the base64-encoded d value
    assert!(!debug.contains("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"));
    // Should contain the type name
    assert!(debug.contains("EcPrivateKey"));
}

// --- OtherPrimeInfo / oth tests ---

#[test]
fn test_rsa_key_with_oth_roundtrip() {
    // RSA key with oth (multi-prime) — synthetic but structurally valid
    let json = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYjqxnf7vQoSmcnVQ","oth":[{"r":"AQAB","d":"AQAB","t":"AQAB"}]}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();

    // oth is present on RsaKey
    let Key::Rsa(rsa) = &jwk.key else {
        unreachable!("Expected RSA key");
    };
    let oth = rsa.oth.as_ref().expect("oth should be present");
    assert_eq!(oth.len(), 1);

    // Round-trip preserves oth
    let serialized = serde_json::to_string(&jwk).unwrap();
    assert!(serialized.contains("\"oth\""));
    let deserialized: Jwk = serde_json::from_str(&serialized).unwrap();
    assert_eq!(jwk, deserialized);

    // oth passes through to RsaPrivateKey
    let pk = jwk.private_key().unwrap();
    let PrivateKey::Rsa(rsa_pk) = pk else {
        unreachable!("Expected RSA private key");
    };
    assert!(rsa_pk.oth.is_some());
    assert_eq!(rsa_pk.oth.as_ref().unwrap().len(), 1);
}

#[test]
fn test_rsa_key_without_oth_has_none() {
    let json = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYjqxnf7vQoSmcnVQ"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let Key::Rsa(rsa) = &jwk.key else {
        unreachable!("Expected RSA key");
    };
    assert!(rsa.oth.is_none());
    // oth not serialized when absent
    let serialized = serde_json::to_string(&jwk).unwrap();
    assert!(!serialized.contains("\"oth\""));
}

#[test]
fn test_other_prime_info_debug_hides_secrets() {
    let info = OtherPrimeInfo::builder()
        .r(vec![1, 2, 3])
        .d(vec![4, 5, 6])
        .t(vec![7, 8, 9])
        .build();
    let debug = format!("{info:?}");
    assert!(debug.contains("OtherPrimeInfo"));
    // Should not contain raw byte values
    assert!(!debug.contains("[1, 2, 3]"));
}

// --- PrivateJwk tests ---

#[test]
fn test_private_jwk_from_ec() {
    let json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","use":"enc","kid":"1"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let private_jwk = jwk.private_jwk().unwrap();

    assert!(matches!(&private_jwk.key, PrivateKey::Ec(_)));
    assert_eq!(private_jwk.key_use, Some(KeyUse::Encrypt));
    assert_eq!(private_jwk.kid.as_deref(), Some("1"));
}

#[test]
fn test_private_jwk_from_rsa() {
    let json = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYjqxnf7vQoSmcnVQ","alg":"RS256","kid":"rsa-1"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let private_jwk = jwk.private_jwk().unwrap();

    assert!(matches!(&private_jwk.key, PrivateKey::Rsa(_)));
    assert_eq!(private_jwk.algorithm.as_deref(), Some("RS256"));
    assert_eq!(private_jwk.kid.as_deref(), Some("rsa-1"));
}

#[test]
fn test_private_jwk_from_okp() {
    let json = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let private_jwk = jwk.private_jwk().unwrap();

    assert!(matches!(&private_jwk.key, PrivateKey::Okp(_)));
}

#[test]
fn test_private_jwk_none_for_public_only() {
    // EC without d
    let json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    assert!(jwk.private_jwk().is_none());
}

#[test]
fn test_private_jwk_none_for_oct() {
    let json = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    assert!(jwk.private_jwk().is_none());
}

#[test]
fn test_private_jwk_to_public_jwk() {
    let json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","use":"enc","kid":"1"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let private_jwk = jwk.private_jwk().unwrap();
    let public_jwk: PublicJwk = private_jwk.clone().into();

    // Metadata preserved
    assert_eq!(public_jwk.kid.as_deref(), Some("1"));
    assert_eq!(public_jwk.key_use, Some(KeyUse::Encrypt));

    // Matches the public_jwk() from Jwk
    assert_eq!(Some(public_jwk), jwk.public_jwk());
}

#[test]
fn test_private_jwk_to_jwk_roundtrip() {
    let json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","kid":"ec-1"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let private_jwk = jwk.private_jwk().unwrap();

    // Convert back to Jwk
    let jwk_back: Jwk = private_jwk.into();
    assert_eq!(jwk, jwk_back);
}

#[test]
fn test_private_jwk_thumbprint_matches_public() {
    let json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    let private_jwk = jwk.private_jwk().unwrap();
    let public_jwk = jwk.public_jwk().unwrap();

    assert_eq!(private_jwk.thumbprint(), public_jwk.thumbprint());
}

#[test]
fn test_private_jwk_builder() {
    let ec_key = EcPrivateKey {
        public: EcPublicKey::builder()
            .crv("P-256")
            .x(vec![1, 2, 3])
            .y(vec![4, 5, 6])
            .build(),
        d: vec![7, 8, 9],
    };
    let pjwk = PrivateJwk::builder()
        .key(ec_key)
        .kid("test-key")
        .algorithm("ES256")
        .build();

    assert_eq!(pjwk.kid.as_deref(), Some("test-key"));
    assert_eq!(pjwk.algorithm.as_deref(), Some("ES256"));
    assert!(matches!(&pjwk.key, PrivateKey::Ec(_)));
}
