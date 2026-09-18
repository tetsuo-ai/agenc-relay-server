//! The startup retirement refusal path, driven through the owner's own
//! storage-rejection boundary: only a receipt taken at the matching durable
//! head and pinned revision may return its candidate, only a determinate
//! retryable refusal is paced, and a wrong, stale or indeterminate boundary
//! fails the reload closed with every durable fact left where it was.
#![forbid(unsafe_code)]

mod boundaries;
mod pacing;

use super::*;
use crate::bridge::crypto::ChannelKeyVerifierRecord;
use crate::e2ee::coordinator::signer_startup::Reconciliation;
use crate::e2ee::coordinator::tests::support::{key, sequencer_credential_in};
use crate::e2ee::coordinator::{CompanionCoordinator, SignerReport};
use crate::federation::coordinator::CoordinatorConfig;
use crate::test_support::{StateCoreFixture, TestResult};
use agenc_ircd_e2ee::sequencer::SequencerKeySet;

const COORDINATOR_NAME: &str = "coordinator.example";

/// A coordinator whose companion executor carries one installed sequencer
/// credential, so its reload owes exactly one durable signer reconciliation.
fn owner(core: &StateCoreFixture) -> TestResult<FederationCoordinator> {
    let identity = &core.identity;
    let mut coordinator = FederationCoordinator::new(
        CoordinatorConfig {
            network_id: identity.network_id,
            server_id: identity.server_id,
            server_name: COORDINATOR_NAME.into(),
            recovery_epoch: identity.recovery_epoch,
            query_cursor_key: [21; 32],
            process_nonce: [22; 16],
            outbox_bytes_per_edge: 1 << 20,
            outbox_objects_per_edge: 64,
        },
        Vec::new(),
        std::sync::Arc::new(crate::test_support::TestChannelKeyVerifier),
        ChannelKeyVerifierRecord::new([7; 16], [1; 32]),
    );
    let network_id = *identity.network_id.as_bytes();
    let mut executor =
        CompanionCoordinator::new(network_id, identity.server_id, COORDINATOR_NAME.into());
    let secret = key(90);
    let credential = sequencer_credential_in(network_id, &secret, 0, (0, 2_000_000), None)?;
    let key_set = SequencerKeySet::verify(&network_id, std::slice::from_ref(&credential), 0, None)?;
    executor.install_sequencer(secret, key_set, credential)?;
    coordinator.install_companion_executor(executor, identity.server_incarnation)?;
    Ok(coordinator)
}

/// The composed owner parked on one accepted startup retirement receipt.
struct Staged {
    core: StateCoreFixture,
    coordinator: FederationCoordinator,
    /// The durable head the receipt was taken at.
    head: u64,
}

impl Staged {
    /// Runs the real reload until its first startup write is staged. The
    /// construction future is boxed so every test's own future stays small.
    async fn open() -> TestResult<Self> {
        Box::pin(Self::build()).await
    }

    async fn build() -> TestResult<Self> {
        let mut core = StateCoreFixture::with_registration_router(vec![44; 65_536])?;
        let mut coordinator = owner(&core)?;
        coordinator.startup(core.context_mut()?);
        for _ in 0..64 {
            if coordinator.pending.is_some()
                || coordinator.loaded()
                || coordinator.counters().violations != 0
            {
                break;
            }
            let message =
                tokio::time::timeout(std::time::Duration::from_secs(30), core.next_storage_read())
                    .await
                    .map_err(|_| "the startup read never completed")??;
            assert!(coordinator.owns_storage_read(message.read_id));
            coordinator.storage_read_completed(core.context_mut()?, message);
        }
        if !matches!(
            coordinator.pending,
            Some(PendingCommit::CompanionRestore(_))
        ) {
            return Err("the reload staged no startup retirement receipt".into());
        }
        assert_eq!(coordinator.counters().violations, 0);
        assert!(!coordinator.loaded());
        // The registration-router fixture composes the real monotonic clock,
        // so pin it at its current reading: the paced retry deadline is an
        // exact value, not one that may cross a millisecond mid-test.
        let pinned = core.context_mut()?.now().get();
        core.context_mut()?.set_monotonic_for_test(pinned);
        let head = core.context_mut()?.head().storage_commit_sequence;
        assert_eq!(coordinator.loader.pinned_commit, Some(head));
        Ok(Self {
            core,
            coordinator,
            head,
        })
    }

    /// Settles the exact storage refusal through the owner's public boundary.
    fn refuse(&mut self, error: StorageError) -> TestResult {
        self.core
            .state_mut()?
            .reject_fixture_batch_before_submission(error)?;
        let context = self.core.context_mut()?;
        self.coordinator.batch_rejected_with_error(context, error);
        assert!(self.coordinator.pending.is_none());
        Ok(())
    }

    fn now(&mut self) -> TestResult<u64> {
        Ok(self.core.context_mut()?.now().get())
    }

    /// Asserts the reload failed closed, leaving the durable head and the
    /// executor's published signer facts exactly as the refusal found them.
    fn assert_failed_closed(&mut self) -> TestResult {
        assert!(self.coordinator.loader.failed);
        assert!(!self.coordinator.loaded());
        assert_eq!(self.coordinator.counters().violations, 1);
        assert_eq!(
            self.core.context_mut()?.head().storage_commit_sequence,
            self.head
        );
        // A refused reconciliation is never installed, so the report the owner
        // publishes stays what a coordinator that staged nothing reports.
        if let Some(executor) = self.coordinator.companion_exec.as_ref() {
            assert_eq!(executor.signer_report(), SignerReport::default());
        }
        Ok(())
    }
}
