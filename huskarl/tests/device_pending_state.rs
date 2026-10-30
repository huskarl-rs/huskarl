//! Compatibility checks compiled against the public API from outside the crate.

use huskarl::{core::platform::SystemTime, grant::device_authorization::PendingState};

#[test]
fn pending_state_builder_keeps_expiry_optional() {
    let state = PendingState::builder()
        .device_code("x")
        .interval_secs(5)
        .build();
    assert_eq!(state.expires_at, SystemTime::UNIX_EPOCH);
}
