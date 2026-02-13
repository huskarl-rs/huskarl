//! UUID v7 generation.
//!
//! Provides a minimal UUID v7 implementation.

use rand::RngExt as _;

const HEX: [u8; 16] = *b"0123456789abcdef";

/// Generates a UUID v7 as a hyphenated string.
///
/// UUID v7 uses a Unix timestamp in milliseconds for the first 48 bits,
/// followed by random data. This provides time-ordered, unique identifiers.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn uuid_v7() -> String {
    let mut bytes = [0u8; 16];

    let ts = crate::platform::SystemTime::now()
        .duration_since(crate::platform::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // First 48 bits: timestamp
    bytes[..6].copy_from_slice(&ts.to_be_bytes()[2..8]);

    // Remaining 74 bits: random
    rand::rng().fill(&mut bytes[6..]);

    // Set version (7) and variant (RFC 4122)
    bytes[6] = (bytes[6] & 0x0F) | 0x70;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    // UUID string is always 36 bytes: 8-4-4-4-12 hex digits + 4 hyphens
    let mut s = String::with_capacity(36);
    for (i, &b) in bytes.iter().enumerate() {
        s.push(char::from(HEX[(b >> 4) as usize]));
        s.push(char::from(HEX[(b & 0x0F) as usize]));
        if matches!(i, 3 | 5 | 7 | 9) {
            s.push('-');
        }
    }
    s
}
