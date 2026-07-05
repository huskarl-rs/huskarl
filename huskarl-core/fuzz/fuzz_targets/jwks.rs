//! Fuzzes JWKS ingestion: JSON deserialization into `Jwks` (the
//! private-capable set), then the paths a real consumer hits afterwards —
//! RFC 7638 thumbprints (base64url decode + minimal-octet trimming) and the
//! private→public conversions (the zeroizing husk pattern).
#![no_main]

use huskarl_core::jwk::{Jwks, PrivateJwk, PublicJwks};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(jwks) = serde_json::from_slice::<Jwks>(data) else {
        return;
    };

    for key in &jwks.keys {
        if let Some(public) = key.public_jwk() {
            let _ = public.thumbprint();
        }
        if let Some(PrivateJwk::Asymmetric(private)) = key.private_jwk() {
            // AsymmetricPrivateJwk thumbprints via its own public projection;
            // must agree with the direct one when both exist. (Symmetric keys
            // have no public projection to cross-check.)
            if let Some(public) = key.public_jwk() {
                assert_eq!(private.thumbprint(), public.thumbprint());
            }
        }
    }

    // From<Jwks> strips private material and filters symmetric keys.
    let _ = PublicJwks::from(jwks);
});
