//! Fuzzes the compact JWS parser — the unauthenticated hot path on a
//! resource server. `serde_json::Value` for both extra-header and
//! extra-claim slots keeps the full `JwtHeader` surface in play (including
//! embedded `jwk` / `PublicJwk` deserialization) without rejecting inputs a
//! typed profile would.
#![no_main]

use huskarl_core::jwt::parse_compact_jws;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = parse_compact_jws::<serde_json::Value, serde_json::Value>(token) else {
        return;
    };

    // The signing input must be exactly the token up to the second dot —
    // the bytes the signature was computed over (RFC 7515 §5.2).
    let second_dot = token
        .match_indices('.')
        .nth(1)
        .map(|(i, _)| i)
        .expect("a successfully parsed token has at least two dots");
    assert_eq!(
        parsed.signing_input.as_slice(),
        &token.as_bytes()[..second_dot]
    );
});
