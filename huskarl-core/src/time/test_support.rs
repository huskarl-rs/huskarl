use super::ManualTime;

/// Exercise consecutive forward and backward jumps on the same live state.
pub(crate) async fn assert_wall_jumps_ignored(time: &ManualTime, mut check: impl AsyncFnMut()) {
    for wall in [jiff::Timestamp::MAX, jiff::Timestamp::MIN] {
        time.set_wall_time(wall);
        check().await;
    }
}
