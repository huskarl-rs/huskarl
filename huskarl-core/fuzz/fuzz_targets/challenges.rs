//! Fuzzes the RFC 7235 `WWW-Authenticate` challenge parser — a hand-rolled
//! scanner whose interesting failure modes are slicing panics and
//! non-advancing loops (libFuzzer's timeout catches the latter as a hang).
//!
//! Newlines split the input into multiple header values, exercising the
//! cross-header accumulation path.
#![no_main]

use http::{HeaderMap, HeaderValue, header::WWW_AUTHENTICATE};
use huskarl::authorizer::parse_challenges;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut headers = HeaderMap::new();
    for line in data.split(|&b| b == b'\n') {
        if let Ok(value) = HeaderValue::from_bytes(line) {
            headers.append(WWW_AUTHENTICATE, value);
        }
    }

    for challenge in parse_challenges(&headers) {
        // Schemes come from a non-empty token lex; an empty one means the
        // scanner accepted junk as a challenge. (token68/params mutual
        // exclusion needs no assertion: the payload enum makes it
        // unrepresentable.)
        assert!(!challenge.scheme.is_empty());
        // Exercise the case-insensitive param lookup path.
        let _ = challenge.error();
    }
});
