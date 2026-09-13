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
