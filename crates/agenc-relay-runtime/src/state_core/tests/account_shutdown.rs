//! Shutdown cancellation of a live local OPAQUE exchange.
#![forbid(unsafe_code)]

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

fn authentication_script() -> TestResult<Vec<(u64, String)>> {
    let envelope = crate::test_support::sealed_authentication_start(
        agenc_relay_types::NetworkId::from_bytes([31; 32]),
        agenc_relay_types::RecoveryEpoch::from_bytes([34; 16]),
        "absent-account",
        191,
    )?;
    let encoded = agenc_relay_client_wire::encode_sasl_payload(&envelope);
    let mut script = vec![
        (1, "CAP LS 302".to_owned()),
        (1, "CAP REQ :sasl".to_owned()),
        (1, "AUTHENTICATE AGENC-OPAQUE".to_owned()),
    ];
    for chunk in encoded.as_bytes().chunks(400) {
        script.push((1, format!("AUTHENTICATE {}", std::str::from_utf8(chunk)?)));
    }
    if encoded.len().is_multiple_of(400) {
        script.push((1, "AUTHENTICATE +".to_owned()));
    }
    Ok(script)
}

async fn wait_for_sealed_authentication_response(sink: &FrameSink) -> TestResult {
    for _ in 0..5_000 {
        let bytes: usize = sink
            .lines()
            .iter()
            .filter_map(|line| {
                line.split_once("AUTHENTICATE ")
                    .map(|(_, data)| data.trim())
            })
            .filter(|data| *data != "+")
            .map(str::len)
            .sum();
        if bytes == agenc_relay_client_wire::SASL_RESPONSE_CHARACTERS {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    Err("local OPAQUE START did not receive its complete sealed challenge".into())
}

#[tokio::test]
async fn shutdown_cancels_a_live_local_opaque_exchange_before_drain() -> TestResult {
    let (exit, (_inbox, completed)) = run_core(true, |inbox, lifecycle, _token| async move {
        let sink = FrameSink::new(ConnectionGeneration::new(1), true);
        let sinks = [sink];
        let result: TestResult<bool> = async {
            open_connections(&inbox, &sinks).await?;
            let script = authentication_script()?;
            let borrowed: Vec<_> = script
                .iter()
                .map(|(id, line)| (*id, line.as_str()))
                .collect();
            drive_script(&inbox, &sinks, &borrowed).await?;
            wait_for_sealed_authentication_response(&sinks[0]).await?;
            lifecycle
                .request(LifecyclePhase::Quiesce)
                .await
                .map_err(|_| "quiesce")?;
            let drained = tokio::time::timeout(
                Duration::from_secs(2),
                lifecycle.request(LifecyclePhase::Drain),
            )
            .await;
            Ok(matches!(drained, Ok(Ok(()))))
        }
        .await;
        let _stopped = lifecycle.request(LifecyclePhase::Stop).await;
        Ok((inbox, result?))
    })
    .await?;
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    assert!(
        completed,
        "Drain must cancel a local unfinished exchange before asking its writer to close"
    );
    Ok(())
}

async fn forward_shutdown_storage_receipts(
    mut input: mpsc::Receiver<crate::bridge::StorageCompletionMessage>,
    output: mpsc::Sender<crate::bridge::StorageCompletionMessage>,
    armed: &AtomicBool,
    injected: &AtomicBool,
    stopped: &CancellationToken,
) -> TestResult {
    loop {
        let receipt = tokio::select! {
            receipt = input.recv() => receipt,
            () = stopped.cancelled() => return Ok(()),
        };
        let Some(mut receipt) = receipt else {
            return Ok(());
        };
        if armed.load(Ordering::SeqCst) && !injected.swap(true, Ordering::SeqCst) {
            assert!(matches!(
                receipt.outcome,
                agenc_relay_storage::CommitOutcome::Committed(_)
            ));
            receipt.outcome = agenc_relay_storage::CommitOutcome::Indeterminate;
        }
        if output.send(receipt).await.is_err() {
            return Ok(());
        }
    }
}

async fn request_indeterminate_cleanup(
    inbox: &mpsc::Sender<StateCoreMessage>,
    lifecycle: &LifecycleControl,
    armed: &AtomicBool,
) -> TestResult<bool> {
    let sinks = [FrameSink::new(ConnectionGeneration::new(1), true)];
    open_connections(inbox, &sinks).await?;
    let script = authentication_script()?;
    let borrowed: Vec<_> = script
        .iter()
        .map(|(id, line)| (*id, line.as_str()))
        .collect();
    drive_script(inbox, &sinks, &borrowed).await?;
    wait_for_sealed_authentication_response(&sinks[0]).await?;
    lifecycle
        .request(LifecyclePhase::Quiesce)
        .await
        .map_err(|_| "quiesce")?;
    // The START receipt and sealed challenge are already delivered. The
    // next commit is the transaction cleanup admitted by begin_shutdown.
    armed.store(true, Ordering::SeqCst);
    let drained = tokio::time::timeout(
        Duration::from_secs(2),
        lifecycle.request(LifecyclePhase::Drain),
    )
    .await;
    let flushed = tokio::time::timeout(
        Duration::from_secs(2),
        lifecycle.request(LifecyclePhase::Flush),
    )
    .await;
    Ok(matches!(drained, Ok(Ok(()))) || matches!(flushed, Ok(Ok(()))))
}

#[tokio::test]
async fn shutdown_cleanup_with_an_indeterminate_receipt_fails_closed() -> TestResult {
    let entropy = (0_u32..65_536)
        .map(|index| u8::try_from((index * 7 + 3) % 256).unwrap_or_default())
        .collect();
    let mut fixture = StateCoreFixture::with_registration_router(entropy)?;
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    let (_close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let (storage_sender, storage_receiver) = mpsc::channel(8);
    let token = CancellationToken::root();
    let run_token = token.clone();
    let relay_stop = CancellationToken::root();
    let armed = AtomicBool::new(false);
    let injected = AtomicBool::new(false);
    let relay = forward_shutdown_storage_receipts(
        parts.storage,
        storage_sender,
        &armed,
        &injected,
        &relay_stop,
    );
    let run = async {
        let exit = parts
            .state
            .run(
                inbox_receiver,
                close_inbox,
                lifecycle_receiver,
                storage_receiver,
                parts.storage_reads,
                parts.checkpoints,
                parts.crypto,
                run_token,
            )
            .await;
        relay_stop.cancel();
        exit
    };
    let driven = async {
        let result = request_indeterminate_cleanup(&inbox, &lifecycle, &armed).await;
        let _stopped = tokio::time::timeout(
            Duration::from_secs(2),
            lifecycle.request(LifecyclePhase::Stop),
        )
        .await;
        token.cancel();
        (inbox, result)
    };
    let (exit, (_inbox, completed), forwarded) = tokio::join!(run, driven, relay);
    forwarded?;
    assert!(
        injected.load(Ordering::SeqCst),
        "the shutdown cleanup must reach storage"
    );
    assert!(
        matches!(
            exit,
            StateCoreExit::Indeterminate(
                crate::state_core::IndeterminateCause::StorageIndeterminate
            )
        ),
        "{exit:?}"
    );
    assert!(
        !completed?,
        "uncertain cleanup must not acknowledge Drain or Flush"
    );
    Ok(())
}
