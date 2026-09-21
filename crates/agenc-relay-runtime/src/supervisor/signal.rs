//! The signal task (spec 21.2, line 4050; spec 21.8, line 4264).
//!
//! SIGTERM and SIGINT request termination; the first one starts the
//! four-phase shutdown and any later one skips to stop. SIGHUP requests a
//! reload. Events flow into the bounded 64-slot signal channel.

use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

use crate::RuntimeError;
use crate::cancel::CancellationToken;
use crate::state_core::inbox::SignalEvent;

/// Which operating-system signal arrived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceivedSignal {
    /// SIGTERM.
    Terminate,
    /// SIGINT.
    Interrupt,
    /// SIGHUP.
    Hangup,
}

/// Turns raw signals into runtime events, counting termination requests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SignalClassifier {
    terminations: u32,
}

impl SignalClassifier {
    /// Creates a classifier that has seen no signal.
    #[must_use]
    pub const fn new() -> Self {
        Self { terminations: 0 }
    }

    /// Classifies one signal: the first termination request begins
    /// shutdown, every later one skips to stop, and a hangup reloads.
    pub fn classify(&mut self, received: ReceivedSignal) -> SignalEvent {
        match received {
            ReceivedSignal::Hangup => SignalEvent::Reload,
            ReceivedSignal::Terminate | ReceivedSignal::Interrupt => {
                self.terminations = self.terminations.saturating_add(1);
                if self.terminations == 1 {
                    SignalEvent::Terminate
                } else {
                    SignalEvent::Interrupt
                }
            }
        }
    }

    /// Returns how many termination requests have been seen.
    #[must_use]
    pub const fn terminations(self) -> u32 {
        self.terminations
    }
}

/// Runs the signal task until the token is cancelled or the channel closes.
pub async fn run_signal_task(
    token: CancellationToken,
    sender: mpsc::Sender<SignalEvent>,
) -> Result<(), RuntimeError> {
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| RuntimeError::InvalidValue)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| RuntimeError::InvalidValue)?;
    let mut hangup = signal(SignalKind::hangup()).map_err(|_| RuntimeError::InvalidValue)?;
    let mut classifier = SignalClassifier::new();
    loop {
        let received = tokio::select! {
            () = token.cancelled() => return Ok(()),
            _ = terminate.recv() => ReceivedSignal::Terminate,
            _ = interrupt.recv() => ReceivedSignal::Interrupt,
            _ = hangup.recv() => ReceivedSignal::Hangup,
        };
        let event = classifier.classify(received);
        if sender.send(event).await.is_err() {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_termination_starts_shutdown_and_later_ones_interrupt() {
        let mut classifier = SignalClassifier::new();
        assert_eq!(
            classifier.classify(ReceivedSignal::Hangup),
            SignalEvent::Reload
        );
        assert_eq!(classifier.terminations(), 0);
        assert_eq!(
            classifier.classify(ReceivedSignal::Terminate),
            SignalEvent::Terminate
        );
        assert_eq!(
            classifier.classify(ReceivedSignal::Interrupt),
            SignalEvent::Interrupt
        );
        assert_eq!(
            classifier.classify(ReceivedSignal::Terminate),
            SignalEvent::Interrupt
        );
        assert_eq!(
            classifier.classify(ReceivedSignal::Hangup),
            SignalEvent::Reload
        );
        assert_eq!(classifier.terminations(), 3);
        assert_eq!(SignalClassifier::default(), SignalClassifier::new());
    }

    #[tokio::test]
    async fn the_signal_task_registers_handlers_and_stops_on_cancel() -> Result<(), RuntimeError> {
        let token = CancellationToken::root();
        let (sender, receiver) = mpsc::channel(4);
        let task = tokio::spawn(run_signal_task(token.clone(), sender));
        tokio::task::yield_now().await;
        token.cancel();
        task.await.map_err(|_| RuntimeError::Cancelled)??;
        drop(receiver);
        Ok(())
    }
}
