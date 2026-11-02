//! Native polling futures must remain usable with multithreaded executors.
#![cfg(not(target_family = "wasm"))]

use huskarl::grant::{ciba, device_authorization};

fn assert_send(_: impl Send) {}

#[test]
fn ciba_polling_future_is_send_and_spawnable() {
    fn check(grant: ciba::CibaPollGrant, mut state: ciba::PendingState) {
        assert_send(grant.poll_to_completion(&mut state, None));
        let _task = tokio::spawn(async move { grant.poll_to_completion(&mut state, None).await });
    }
    let _ = check;
}

#[test]
fn device_polling_future_is_send_and_spawnable() {
    fn check(
        grant: device_authorization::DeviceAuthorizationGrant,
        mut state: device_authorization::PendingState,
    ) {
        assert_send(grant.poll_to_completion(&mut state, None));
        let _task = tokio::spawn(async move { grant.poll_to_completion(&mut state, None).await });
    }
    let _ = check;
}
