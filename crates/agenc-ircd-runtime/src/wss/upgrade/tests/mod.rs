#![forbid(unsafe_code)]
//! Upgrade admission and cancellation at the TLS completion boundary.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const REQUEST: &[u8] = b"GET /irc HTTP/1.1\r\nHost: chat.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: text.ircv3.net\r\nOrigin: https://chat.example\r\n\r\n";

#[tokio::test]
async fn origin_is_checked_at_completed_upgrade_and_cannot_escape_exact_matching() -> TestResult {
    for allowed in [true, false] {
        let (mut peer, transport) = tokio::io::duplex(32768);
        peer.write_all(REQUEST).await?;
        let budget = MemoryBudget::new(1_048_576);
        let token = CancellationToken::root();
        let result = upgrade(
            transport,
            std::time::Instant::now(),
            &budget,
            |origin| allowed && origin == Some("https://chat.example"),
            &token,
        )
        .await;
        assert_eq!(result.is_ok(), allowed);
        let mut response = [0; 12];
        peer.read_exact(&mut response).await?;
        assert_eq!(
            &response,
            if allowed {
                b"HTTP/1.1 101"
            } else {
                b"HTTP/1.1 403"
            }
        );
        drop(result);
        assert_eq!(budget.charged(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn changed_origin_policy_applies_before_the_last_header_arrives() -> TestResult {
    let (mut peer, mut transport) = tokio::io::duplex(32768);
    let allowed = AtomicBool::new(true);
    let request = async {
        peer.write_all(REQUEST.strip_suffix(b"\r\n").ok_or("delimiter")?)
            .await?;
        allowed.store(false, Ordering::SeqCst);
        peer.write_all(b"\r\n").await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let (sent, parsed) = tokio::join!(
        request,
        read_request(&mut transport, |_| allowed.load(Ordering::SeqCst))
    );
    sent?;
    assert_eq!(parsed.err(), Some(UpgradeError::Origin));
    Ok(())
}

#[tokio::test]
async fn upgrade_budget_starts_at_tls_completion_and_cancellation_releases_memory() -> TestResult {
    let (mut peer, transport) = tokio::io::duplex(32768);
    let budget = MemoryBudget::new(1_048_576);
    let token = CancellationToken::root();
    let completed = std::time::Instant::now()
        .checked_sub(Duration::from_secs(6))
        .ok_or("clock")?;
    assert!(
        upgrade(transport, completed, &budget, |_| true, &token)
            .await
            .is_err()
    );
    let mut response = [0; 12];
    peer.read_exact(&mut response).await?;
    assert_eq!(&response, b"HTTP/1.1 408");
    let (_peer, transport) = tokio::io::duplex(1);
    token.cancel();
    assert!(
        upgrade(
            transport,
            std::time::Instant::now(),
            &budget,
            |_| true,
            &token
        )
        .await
        .is_err()
    );
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[tokio::test]
async fn steady_memory_refusal_never_acknowledges_the_upgrade() -> TestResult {
    let (mut peer, transport) = tokio::io::duplex(32768);
    peer.write_all(REQUEST).await?;
    let budget = MemoryBudget::new(1);
    assert!(
        upgrade(
            transport,
            std::time::Instant::now(),
            &budget,
            |_| true,
            &CancellationToken::root()
        )
        .await
        .is_err()
    );
    assert_eq!(peer.read(&mut [0]).await?, 0);
    assert_eq!(budget.charged(), 0);
    Ok(())
}
