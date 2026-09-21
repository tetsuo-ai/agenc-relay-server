//! Architecture 21.2: a failed connection leaves existing and new clients alive.

#![forbid(unsafe_code)]

use super::*;

#[tokio::test]
async fn a_join_error_keeps_the_listener_and_other_connections_running() -> TestResult {
    let fixture = fixture(79)?;
    let spec = tcp_spec(
        ListenerPurpose::ClientTls,
        4,
        Some(server(
            &fixture,
            TlsEndpointProfile::Client,
            ClientAuth::None,
        )?),
    )?;
    let mut harness = start(vec![spec], HarnessOptions::default())?;
    let address = tcp_address(&harness, 0)?;
    let tls = client(&fixture, CLIENT_ALPN, false)?;
    let survivor = tls_client(address, tls.clone(), b"PING :survivor\r\n".to_vec());
    let (generation, sink) = expect_opened(&mut harness.inbox, ListenerPurpose::ClientTls).await?;
    assert_eq!(expect_line(&mut harness.inbox, generation).await?, "PING");

    harness
        .recorder
        .unwind_next_admission
        .store(true, Ordering::SeqCst);
    let failed = tls_client(address, tls.clone(), b"PING :failed\r\n".to_vec());
    tokio::time::timeout(Duration::from_secs(5), async {
        while !harness.recorder.snapshot().contains(&Observed::Refused(
            ListenerPurpose::ClientTls,
            RefusalReason::TaskTree,
        )) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let _transport_failure = joined(failed).await?;
    assert!(!harness.root.is_cancelled());
    enqueue(&harness.budget, &sink, "still connected")?;

    let newcomer = tls_client(address, tls, b"PING :newcomer\r\n".to_vec());
    let (new_generation, new_sink) =
        expect_opened(&mut harness.inbox, ListenerPurpose::ClientTls).await?;
    assert_eq!(
        expect_line(&mut harness.inbox, new_generation).await?,
        "PING"
    );
    enqueue(&harness.budget, &new_sink, "still accepting")?;
    for sink in [&sink, &new_sink] {
        tokio::time::timeout(Duration::from_secs(5), sink.shutdown_after_flush().wait()).await?;
    }
    assert_eq!(
        joined(survivor).await??,
        b":server.test NOTICE * :still connected\r\n"
    );
    assert_eq!(
        joined(newcomer).await??,
        b":server.test NOTICE * :still accepting\r\n"
    );
    drop((sink, new_sink));
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (2, 1));
    Ok(())
}
