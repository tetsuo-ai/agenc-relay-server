//! Every way the open handshake of an admitted connection can end (spec 21.2
//! lines 4064-4073, spec 21.8): StateCore accepts, StateCore refuses,
//! StateCore drops the acknowledgement, the tree is cancelled while the
//! answer is pending, and a graceful or critical shutdown after admission.
//! Each outcome closes the transport, carries its own closed label, joins
//! the connection child, and returns the base, queue, handshake, and count
//! permits exactly once.

#![forbid(unsafe_code)]

use super::*;

fn client_spec(
    fixture: &TlsFixture,
    seed_slots: usize,
) -> Result<ListenerSpec, Box<dyn Error + Send + Sync>> {
    tcp_spec(
        ListenerPurpose::ClientTls,
        seed_slots,
        Some(server(
            fixture,
            TlsEndpointProfile::Client,
            ClientAuth::None,
        )?),
    )
}

async fn opened_pending(
    inbox: &mut mpsc::Receiver<StateCoreMessage>,
) -> Result<
    (
        ConnectionGeneration,
        Arc<dyn ClientSink>,
        tokio::sync::oneshot::Sender<ConnectionOpenOutcome>,
    ),
    Box<dyn Error + Send + Sync>,
> {
    match next_message(inbox).await? {
        StateCoreMessage::Opened {
            generation,
            purpose: ListenerPurpose::ClientTls,
            sink,
            acknowledgement,
            ..
        } => Ok((generation, sink, acknowledgement)),
        _ => Err("expected an opened message".into()),
    }
}

/// A connection the server closed before it wrote anything: the client saw
/// either a clean end of stream or a TLS end without close_notify.
fn closed_without_reply(outcome: ClientOutcome) -> bool {
    match outcome {
        Ok(received) => received.is_empty(),
        Err(error) => error.contains("close_notify") || error.contains("eof"),
    }
}

/// Every permit the closed connection held is back while the listener is
/// still accepting: the whole budget (base, queue backing, and TLS setup),
/// the global client slot, and every handshake slot except the one the
/// pending accept pre-holds for the next socket.
fn every_slot_free(harness: &Harness) {
    assert_eq!(harness.budget.available(), harness.budget.capacity());
    assert!(
        harness.handshakes.available() + 1 >= harness.handshakes.capacity(),
        "handshake slots: {} of {}",
        harness.handshakes.available(),
        harness.handshakes.capacity()
    );
    assert_eq!(
        harness.client_slots.available_permits(),
        harness.client_slot_capacity
    );
}

#[tokio::test]
async fn an_accepted_open_serves_the_connection_and_a_quit_closes_it_as_client_quit() -> TestResult
{
    let fixture = fixture(81)?;
    let mut harness = start(vec![client_spec(&fixture, 2)?], HarnessOptions::default())?;
    let address = tcp_address(&harness, 0)?;
    let client = tls_client(
        address,
        client(&fixture, CLIENT_ALPN, false)?,
        b"NICK carol\r\nQUIT :done\r\n".to_vec(),
    );
    let (generation, sink, acknowledgement) = opened_pending(&mut harness.inbox).await?;
    assert!(
        acknowledgement
            .send(ConnectionOpenOutcome::Accepted)
            .is_ok()
    );
    assert_eq!(expect_line(&mut harness.inbox, generation).await?, "NICK");
    assert_eq!(expect_line(&mut harness.inbox, generation).await?, "QUIT");
    // StateCore answers a routed QUIT by closing the sink after the flush.
    let _acknowledged = sink.close_after_flush(CloseReason::ClientQuit);
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::ClientQuit
    );
    assert_eq!(joined(client).await??, b"");
    drop(sink);
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (1, 0));
    Ok(())
}

#[tokio::test]
async fn a_dropped_open_acknowledgement_closes_as_shutdown_and_returns_every_permit() -> TestResult
{
    let fixture = fixture(82)?;
    let mut harness = start(vec![client_spec(&fixture, 1)?], HarnessOptions::default())?;
    let address = tcp_address(&harness, 0)?;
    let client = tls_client(address, client(&fixture, CLIENT_ALPN, false)?, Vec::new());
    let (generation, sink, acknowledgement) = opened_pending(&mut harness.inbox).await?;
    // StateCore went away without answering: the sender drops unsent.
    drop(acknowledgement);
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::Shutdown
    );
    assert!(closed_without_reply(joined(client).await?));
    drop(sink);
    tokio::time::sleep(SETTLE).await;
    every_slot_free(&harness);
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (1, 0));
    Ok(())
}

#[tokio::test]
async fn a_refused_open_closes_as_overload_and_the_next_client_is_still_admitted() -> TestResult {
    let fixture = fixture(83)?;
    let mut harness = start(vec![client_spec(&fixture, 1)?], HarnessOptions::default())?;
    let address = tcp_address(&harness, 0)?;
    let tls = client(&fixture, CLIENT_ALPN, false)?;
    let refused_client = tls_client(address, tls.clone(), Vec::new());
    let (generation, sink, acknowledgement) = opened_pending(&mut harness.inbox).await?;
    assert!(acknowledgement.send(ConnectionOpenOutcome::Refused).is_ok());
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::Overload
    );
    assert!(closed_without_reply(joined(refused_client).await?));
    drop(sink);
    tokio::time::sleep(SETTLE).await;
    every_slot_free(&harness);

    // The refusal consumed nothing: the single listener slot admits again.
    let accepted_client = tls_client(address, tls, b"NICK dave\r\nQUIT\r\n".to_vec());
    let (next, sink, acknowledgement) = opened_pending(&mut harness.inbox).await?;
    assert_ne!(next, generation, "a fresh generation");
    assert!(
        acknowledgement
            .send(ConnectionOpenOutcome::Accepted)
            .is_ok()
    );
    assert_eq!(expect_line(&mut harness.inbox, next).await?, "NICK");
    assert_eq!(expect_line(&mut harness.inbox, next).await?, "QUIT");
    let _acknowledged = sink.close_after_flush(CloseReason::ClientQuit);
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), next).await?,
        CloseReason::ClientQuit
    );
    assert_eq!(joined(accepted_client).await??, b"");
    drop(sink);
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (2, 0));
    Ok(())
}

#[tokio::test]
async fn cancellation_while_the_open_answer_is_pending_closes_as_shutdown() -> TestResult {
    let fixture = fixture(84)?;
    let mut harness = start(vec![client_spec(&fixture, 1)?], HarnessOptions::default())?;
    let address = tcp_address(&harness, 0)?;
    let client = tls_client(address, client(&fixture, CLIENT_ALPN, false)?, Vec::new());
    let (generation, sink, acknowledgement) = opened_pending(&mut harness.inbox).await?;
    harness.set.stop_accepting();
    harness.set.cancel_connections();
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::Shutdown
    );
    // A late answer has no receiver: the connection is already gone.
    assert!(
        acknowledgement
            .send(ConnectionOpenOutcome::Accepted)
            .is_err()
    );
    assert!(closed_without_reply(joined(client).await?));
    drop(sink);
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (1, 0));
    Ok(())
}

#[tokio::test]
async fn a_graceful_shutdown_closes_an_admitted_connection_as_shutdown() -> TestResult {
    let fixture = fixture(85)?;
    let mut harness = start(vec![client_spec(&fixture, 2)?], HarnessOptions::default())?;
    let address = tcp_address(&harness, 0)?;
    let client = tls_client(
        address,
        client(&fixture, CLIENT_ALPN, false)?,
        b"NICK erin\r\n".to_vec(),
    );
    let (generation, sink) = expect_opened(&mut harness.inbox, ListenerPurpose::ClientTls).await?;
    assert_eq!(expect_line(&mut harness.inbox, generation).await?, "NICK");
    harness.set.stop_accepting();
    harness.set.cancel_connections();
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::Shutdown
    );
    assert_eq!(joined(client).await??, b"");
    drop(sink);
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (1, 0));
    Ok(())
}

#[tokio::test]
async fn a_critical_root_cancellation_closes_an_admitted_connection_as_shutdown() -> TestResult {
    let fixture = fixture(86)?;
    let mut harness = start(vec![client_spec(&fixture, 2)?], HarnessOptions::default())?;
    let address = tcp_address(&harness, 0)?;
    let client = tls_client(
        address,
        client(&fixture, CLIENT_ALPN, false)?,
        b"NICK frank\r\n".to_vec(),
    );
    let (generation, sink) = expect_opened(&mut harness.inbox, ListenerPurpose::ClientTls).await?;
    assert_eq!(expect_line(&mut harness.inbox, generation).await?, "NICK");
    // A critical child failure cancels the whole tree from the root.
    harness.root.cancel();
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::Shutdown
    );
    assert_eq!(joined(client).await??, b"");
    drop(sink);
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (1, 0));
    Ok(())
}
