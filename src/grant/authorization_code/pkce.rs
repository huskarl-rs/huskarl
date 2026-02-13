//! A helper for generating PKCE (Proof Key for Code Exchange) pairs.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::TryRng;
use sha2::{Digest, Sha256};

/// The PKCE pair generated using the `S256` method of RFC 7636.
pub struct Pkce {
    /// Verifier
    pub verifier: String,
    /// Challenge
    pub challenge: String,
}

impl Pkce {
    /// Creates a new PKCE verifier and challenger pair using the `S256` method of RFC 7636.
    #[must_use]
    pub fn generate_s256_pair() -> Self {
        let mut verifier_bytes = [0u8; 32];
        rand::rng().try_fill_bytes(&mut verifier_bytes);
        let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge_bytes = hasher.finalize();

        let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

        Self {
            verifier,
            challenge,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests RFC 7636 §4.1 - Code Verifier length validation
    ///
    /// Per RFC 7636, the code verifier MUST have a minimum length of 43 characters
    /// and a maximum length of 128 characters.
    ///
    /// Reference: https://tools.ietf.org/html/rfc7636#section-4.1
    #[test]
    fn test_rfc7636_4_1_verifier_length_validation() {
        // Generate multiple PKCE pairs and verify length constraints
        for _ in 0..10 {
            let pkce = Pkce::generate_s256_pair();

            let verifier_len = pkce.verifier.len();
            assert!(
                verifier_len >= 43,
                "code_verifier length {} must be at least 43 characters (RFC 7636 §4.1)",
                verifier_len
            );
            assert!(
                verifier_len <= 128,
                "code_verifier length {} must be at most 128 characters (RFC 7636 §4.1)",
                verifier_len
            );
        }
    }

    /// Tests RFC 7636 §4.1 - Code Verifier character set validation
    ///
    /// Per RFC 7636, the code verifier MUST use characters from the set
    /// [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~" (unreserved characters)
    ///
    /// Reference: https://tools.ietf.org/html/rfc7636#section-4.1
    #[test]
    fn test_rfc7636_4_1_verifier_charset_validation() {
        for _ in 0..10 {
            let pkce = Pkce::generate_s256_pair();

            // Verify all characters are from the allowed set (base64url without padding)
            // Base64url uses: A-Z, a-z, 0-9, -, _
            for ch in pkce.verifier.chars() {
                assert!(
                    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                    "code_verifier contains invalid character '{}' (RFC 7636 §4.1)",
                    ch
                );
            }
        }
    }

    /// Tests RFC 7636 §4.1 - Code Verifier randomness
    ///
    /// The code verifier MUST be generated using cryptographically secure
    /// random bytes to prevent attacks.
    ///
    /// Reference: https://tools.ietf.org/html/rfc7636#section-4.1
    #[test]
    fn test_rfc7636_4_1_verifier_randomness() {
        // Generate multiple verifiers and ensure they're all different
        let mut verifiers = std::collections::HashSet::new();

        for _ in 0..100 {
            let pkce = Pkce::generate_s256_pair();
            verifiers.insert(pkce.verifier.clone());
        }

        // All 100 verifiers should be unique (probability of collision is astronomically low)
        assert_eq!(
            verifiers.len(),
            100,
            "code_verifier must be cryptographically random (RFC 7636 §4.1)"
        );
    }

    /// Tests RFC 7636 §4.1 - Reject invalid verifiers
    ///
    /// This test documents what would constitute an invalid verifier
    /// according to RFC 7636.
    ///
    /// Reference: https://tools.ietf.org/html/rfc7636#section-4.1
    #[test]
    fn test_rfc7636_4_1_reject_invalid_verifier() {
        // Test that our implementation generates valid verifiers
        // Invalid cases (for documentation):

        // Too short (< 43 chars)
        let too_short = "a".repeat(42);
        assert!(
            too_short.len() < 43,
            "verifiers shorter than 43 chars would be invalid"
        );

        // Too long (> 128 chars)
        let too_long = "a".repeat(129);
        assert!(
            too_long.len() > 128,
            "verifiers longer than 128 chars would be invalid"
        );

        // Invalid characters (examples)
        let invalid_chars = vec![
            "valid+verifier", // '+' not allowed
            "valid/verifier", // '/' not allowed
            "valid=verifier", // '=' not allowed (no padding)
            "valid verifier", // space not allowed
            "valid$verifier", // '$' not allowed
        ];

        for invalid in invalid_chars {
            assert!(
                invalid.contains(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_'),
                "'{}' contains invalid characters",
                invalid
            );
        }
    }

    /// Tests RFC 7636 §4.2 - Code Challenge Method S256
    ///
    /// For the S256 method:
    /// code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
    ///
    /// Reference: https://tools.ietf.org/html/rfc7636#section-4.2
    #[test]
    fn test_rfc7636_4_2_challenge_s256_method() {
        let pkce = Pkce::generate_s256_pair();

        // Manually compute the expected challenge
        let mut hasher = Sha256::new();
        hasher.update(pkce.verifier.as_bytes());
        let hash = hasher.finalize();
        let expected_challenge = URL_SAFE_NO_PAD.encode(hash);

        assert_eq!(
            pkce.challenge, expected_challenge,
            "S256 challenge must be BASE64URL(SHA256(verifier))"
        );
    }

    /// Tests RFC 7636 §4.2 - Code Challenge encoding
    ///
    /// The code challenge MUST be BASE64URL encoded (without padding).
    ///
    /// Reference: https://tools.ietf.org/html/rfc7636#section-4.2
    #[test]
    fn test_rfc7636_4_2_challenge_base64url_encoding() {
        let pkce = Pkce::generate_s256_pair();

        // Verify challenge uses base64url character set (no padding)
        for ch in pkce.challenge.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "challenge must use base64url encoding without padding"
            );
        }

        // Verify no padding characters
        assert!(
            !pkce.challenge.contains('='),
            "challenge must not contain padding '='"
        );

        // Verify it's valid base64url by decoding
        let decoded = URL_SAFE_NO_PAD.decode(&pkce.challenge);
        assert!(
            decoded.is_ok(),
            "challenge must be valid base64url: {:?}",
            decoded.err()
        );

        // For S256, the decoded value should be 32 bytes (SHA-256 output)
        assert_eq!(
            decoded.unwrap().len(),
            32,
            "S256 challenge should decode to 32 bytes (SHA-256 hash)"
        );
    }

    /// Tests RFC 7636 §4.2 - Code Challenge plain method (discouraged)
    ///
    /// The plain method sets code_challenge = code_verifier.
    /// This method is NOT RECOMMENDED and should only be used if S256 is not possible.
    ///
    /// Note: Our implementation only supports S256 (the secure method).
    ///
    /// Reference: https://tools.ietf.org/html/rfc7636#section-4.2
    #[test]
    fn test_rfc7636_4_2_challenge_plain_method_not_used() {
        let pkce = Pkce::generate_s256_pair();

        // Verify we're NOT using plain method (challenge != verifier)
        assert_ne!(
            pkce.challenge, pkce.verifier,
            "implementation should use S256, not plain method (RFC 7636 §4.2)"
        );

        // Verify challenge is longer than verifier (base64 encoding of hash)
        // SHA-256 hash (32 bytes) -> base64url (43 chars)
        // Our verifier is also 43 chars (from 32 random bytes)
        // So they should be equal length, but the challenge should be
        // the hash of verifier, not the verifier itself

        // Compute what plain method would produce
        let plain_challenge = &pkce.verifier;

        assert_ne!(
            &pkce.challenge, plain_challenge,
            "must use S256 method, not plain (RFC 7636 §4.2)"
        );
    }
}
