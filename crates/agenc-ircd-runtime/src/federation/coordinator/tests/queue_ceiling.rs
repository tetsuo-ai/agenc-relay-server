#![forbid(unsafe_code)]

//! Requests behind a busy coordinator queue per peer up to a fixed ceiling;
//! the request past the ceiling closes the link.

use super::*;

#[tokio::test]
async fn requests_beyond_the_queue_ceiling_close_the_link() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([42; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 42);
        let mut origin = Origin::new(62);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        for index in 0..=MAX_QUEUED_REQUESTS + 2 {
            let seed = u8::try_from(index + 100)?;
            request(
                &mut edge,
                &mut origin,
                &session_open(seed, &format!("user{seed}")),
            )
            .await?;
        }
        edge.expect_closed().await?;
        Ok(())
    })
    .await
}
