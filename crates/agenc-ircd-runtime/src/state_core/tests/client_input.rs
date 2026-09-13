//! STA-10: the production actor receives admitted connection queues independently.

#![forbid(unsafe_code)]

use super::*;
use crate::state_core::{CommandObservation, CommandRouter, RouteOutcome, StateCoreContext};

struct InputProbe(mpsc::Sender<(ConnectionGeneration, String)>);

impl CommandRouter for InputProbe {
    fn route(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: agenc_ircd_client_wire::ParsedMessage,
        observation: CommandObservation,
    ) -> RouteOutcome {
        let _sent = self.0.try_send((
            generation,
            message.trailing().unwrap_or_default().to_owned(),
        ));
        super::super::DefaultRouter.route(context, generation, message, observation)
    }
}

#[tokio::test]
async fn admitted_input_ports_dispatch_fifo_while_control_inbox_is_full() -> TestResult {
    let (exit, _open) = run_core_with(
        false,
        |fixture| {
            let (observed, observation) = mpsc::channel(4);
            let state = fixture.state_mut()?;
            state.install_client_inputs()?;
            assert!(state.install_client_inputs().is_err());
            state.router = Box::new(InputProbe(observed));
            Ok(observation)
        },
        |inbox, lifecycle, _token, mut observation| async move {
            let generation = ConnectionGeneration::new(1);
            let sink: Arc<dyn ClientSink> = FrameSink::new(generation, true);
            let (acknowledgement, accepted) = oneshot::channel();
            send(
                &inbox,
                StateCoreMessage::Opened {
                    generation,
                    purpose: ListenerPurpose::ClientOnion,
                    source: SourceAddressKey::onion_listener(),
                    sink,
                    acknowledgement,
                },
            )
            .await?;
            let ConnectionOpenOutcome::AcceptedInput(port) = accepted.await? else {
                return Err("production input port missing".into());
            };
            while inbox.capacity() != 0 {
                inbox
                    .try_send(StateCoreMessage::Signal(SignalEvent::Reload))
                    .map_err(|_| "control inbox closed")?;
            }
            for sequence in 1..=4 {
                port.send(StateCoreMessage::Line {
                    generation,
                    sequence,
                    message: Box::new(
                        parse_message(FramedLine::new(&format!("PING :{sequence}"))?)?
                            .ok_or("line")?,
                    ),
                })?;
            }
            for sequence in 1..=4 {
                let actual =
                    tokio::time::timeout(std::time::Duration::from_secs(2), observation.recv())
                        .await?
                        .ok_or("observation closed")?;
                assert_eq!(actual, (generation, sequence.to_string()));
            }
            lifecycle
                .request(LifecyclePhase::Stop)
                .await
                .map_err(|_| "stop")?;
            Ok(inbox)
        },
    )
    .await?;
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    Ok(())
}

struct BusyInputProbe {
    port: Arc<crate::state_core::client_input::ClientInputPort>,
    routed: u64,
    opened: mpsc::Sender<u64>,
}

impl CommandRouter for BusyInputProbe {
    fn connection_opened(
        &mut self,
        _context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        if generation == ConnectionGeneration::new(2) {
            let _sent = self.opened.try_send(self.routed);
        }
    }

    fn route(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: agenc_ircd_client_wire::ParsedMessage,
        observation: CommandObservation,
    ) -> RouteOutcome {
        self.routed += 1;
        if self.routed < 512
            && let Ok(framed) = FramedLine::new("PING :busy")
            && let Ok(Some(message)) = parse_message(framed)
        {
            let _sent = self.port.send(StateCoreMessage::Line {
                generation,
                sequence: self.routed + 1,
                message: Box::new(message),
            });
        }
        super::super::DefaultRouter.route(context, generation, message, observation)
    }
}

#[tokio::test]
async fn continuously_ready_client_input_cannot_starve_an_open_notice() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    state.install_client_inputs()?;
    let (acknowledgement, mut accepted) = oneshot::channel();
    assert!(
        state
            .step_message(StateCoreMessage::Opened {
                generation: ConnectionGeneration::new(1),
                purpose: ListenerPurpose::ClientOnion,
                source: SourceAddressKey::onion_listener(),
                sink: FrameSink::new(ConnectionGeneration::new(1), true),
                acknowledgement,
            })
            .is_none()
    );
    let ConnectionOpenOutcome::AcceptedInput(port) = accepted.try_recv()? else {
        return Err("input port missing".into());
    };
    let port = Arc::new(port);
    port.send(StateCoreMessage::Line {
        generation: ConnectionGeneration::new(1),
        sequence: 1,
        message: Box::new(parse_message(FramedLine::new("PING :busy")?)?.ok_or("line")?),
    })?;
    let (opened, mut observed) = mpsc::channel(1);
    state.router = Box::new(BusyInputProbe {
        port,
        routed: 0,
        opened,
    });
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    let (acknowledgement, accepted) = oneshot::channel();
    inbox
        .try_send(StateCoreMessage::Opened {
            generation: ConnectionGeneration::new(2),
            purpose: ListenerPurpose::ClientOnion,
            source: SourceAddressKey::onion_listener(),
            sink: FrameSink::new(ConnectionGeneration::new(2), true),
            acknowledgement,
        })
        .map_err(|_| "open queue full")?;
    let (_close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let run = parts.state.run(
        inbox_receiver,
        close_inbox,
        lifecycle_receiver,
        parts.storage,
        parts.storage_reads,
        parts.checkpoints,
        parts.crypto,
        CancellationToken::root(),
    );
    let driver = async {
        let before_open = observed.recv().await.ok_or("open observation")?;
        let opened = accepted.await?;
        lifecycle
            .request(LifecyclePhase::Stop)
            .await
            .map_err(|_| "stop")?;
        Ok::<_, Box<dyn std::error::Error>>((before_open, opened, inbox))
    };
    let (exit, output) = tokio::join!(run, driver);
    let (before_open, opened, _inbox) = output?;
    assert!(matches!(exit, StateCoreExit::Stopped));
    assert!(matches!(opened, ConnectionOpenOutcome::AcceptedInput(_)));
    assert!(
        before_open <= 1,
        "open notice waited behind {before_open} client lines"
    );
    Ok(())
}

struct BusyControlProbe {
    inbox: mpsc::Sender<StateCoreMessage>,
    reloads: u64,
    routed: mpsc::Sender<u64>,
}

impl CommandRouter for BusyControlProbe {
    fn reload_requested(&mut self, _context: &mut StateCoreContext) {
        self.reloads += 1;
        if self.reloads < 512 {
            let _sent = self
                .inbox
                .try_send(StateCoreMessage::Signal(SignalEvent::Reload));
        }
    }

    fn route(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: agenc_ircd_client_wire::ParsedMessage,
        observation: CommandObservation,
    ) -> RouteOutcome {
        let _sent = self.routed.try_send(self.reloads);
        super::super::DefaultRouter.route(context, generation, message, observation)
    }
}

#[tokio::test]
async fn continuously_ready_control_input_cannot_starve_a_client() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    state.install_client_inputs()?;
    let (acknowledgement, mut accepted) = oneshot::channel();
    assert!(
        state
            .step_message(StateCoreMessage::Opened {
                generation: ConnectionGeneration::new(1),
                purpose: ListenerPurpose::ClientOnion,
                source: SourceAddressKey::onion_listener(),
                sink: FrameSink::new(ConnectionGeneration::new(1), true),
                acknowledgement,
            })
            .is_none()
    );
    let ConnectionOpenOutcome::AcceptedInput(port) = accepted.try_recv()? else {
        return Err("input port missing".into());
    };
    port.send(StateCoreMessage::Line {
        generation: ConnectionGeneration::new(1),
        sequence: 1,
        message: Box::new(parse_message(FramedLine::new("PING :busy")?)?.ok_or("line")?),
    })?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    inbox
        .try_send(StateCoreMessage::Signal(SignalEvent::Reload))
        .map_err(|_| "control queue")?;
    let (routed, mut observed) = mpsc::channel(1);
    state.router = Box::new(BusyControlProbe {
        inbox: inbox.clone(),
        reloads: 0,
        routed,
    });
    let mut parts = fixture.take_run_parts()?;
    let (_close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let run = parts.state.run(
        inbox_receiver,
        close_inbox,
        lifecycle_receiver,
        parts.storage,
        parts.storage_reads,
        parts.checkpoints,
        parts.crypto,
        CancellationToken::root(),
    );
    let driver = async {
        let before_client = observed.recv().await.ok_or("client observation")?;
        lifecycle
            .request(LifecyclePhase::Stop)
            .await
            .map_err(|_| "stop")?;
        Ok::<_, Box<dyn std::error::Error>>((before_client, inbox))
    };
    let (exit, output) = tokio::join!(run, driver);
    let (before_client, _inbox) = output?;
    assert!(matches!(exit, StateCoreExit::Stopped));
    assert!(
        before_client <= 1,
        "client waited behind {before_client} control messages"
    );
    Ok(())
}
