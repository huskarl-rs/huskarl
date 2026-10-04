use crate::core::time::Clock;

/// Local receipt of a token response, retaining its wall timestamp.
///
/// Capture immediately after receiving the response, before parsing or other
/// asynchronous work. Relative lifetimes such as `expires_in` are converted to
/// wall-clock deadlines using this timestamp. Clones retain the original receipt
/// timestamp; parsing, priming, and caching do not restart the lifetime.
#[derive(Debug, Clone, Copy)]
pub struct TokenReceipt {
    pub(super) wall: jiff::Timestamp,
}

impl TokenReceipt {
    /// Capture the receipt's wall time using a borrowed clock.
    #[must_use]
    pub fn capture(clock: &dyn Clock) -> Self {
        Self { wall: clock.now() }
    }

    /// Wall timestamp for expiry, absolute claims, and persistence.
    #[must_use]
    pub fn received_at(&self) -> jiff::Timestamp {
        self.wall
    }
}
