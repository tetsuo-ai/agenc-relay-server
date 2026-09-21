//! Shared observer, plan and fanout helpers for the state-core branch tests.
#![forbid(unsafe_code)]

use std::io;

use agenc_relay_domain::MutationPlan;

use super::*;
use crate::clock::SystemMonotonicClock;
use crate::observe::adapter::RuntimeObserver;
use crate::observe::events::{CorrelationSource, Severity};
use crate::observe::log::{LogFilter, LogRetention, LogTarget, LogWriter};
use crate::observe::metrics::{
    CommandClass, LabelSet, MetricKey, MetricLabel, MetricName, MetricsRegistry, MetricsView,
    ResultClass,
};
use crate::state_core::fanout::FanoutRequest;
use crate::state_core::{StateCore, StateCoreContext};

/// A log target that accepts and forgets every line.
pub(super) struct DiscardLog;

impl LogTarget for DiscardLog {
    fn open_segment(&mut self, _hour: u64) -> io::Result<()> {
        Ok(())
    }

    fn write_line(&mut self, _line: &str) -> io::Result<()> {
        Ok(())
    }

    fn retire_before(&mut self, _hour: u64, _limit: usize) -> io::Result<bool> {
        Ok(true)
    }
}

/// The metrics a core reported through an installed observer.
pub(super) struct Observed {
    metrics: Arc<MetricsRegistry>,
    _writer: LogWriter<DiscardLog>,
}

impl Observed {
    /// The exact counter value of one labelled series, zero when absent.
    pub(super) fn counter(&self, name: MetricName, labels: &[MetricLabel]) -> TestResult<u64> {
        let key = MetricKey {
            name,
            labels: LabelSet::new(labels)?,
        };
        Ok(self
            .metrics
            .snapshot(MetricsView::Operator)
            .counters
            .into_iter()
            .filter(|(candidate, _)| *candidate == key)
            .map(|(_, count)| count)
            .sum())
    }

    /// How many commands of `class` completed with `result`.
    pub(super) fn commands(&self, class: CommandClass, result: ResultClass) -> TestResult<u64> {
        self.counter(
            MetricName::CommandsHandled,
            &[
                MetricLabel::CommandClass(class),
                MetricLabel::ResultClass(result),
            ],
        )
    }
}

/// Installs a process observer on `state` and returns its metrics.
pub(super) fn observe(state: &mut StateCore) -> Observed {
    let server_id = agenc_relay_types::ServerId::from_bytes([9; 16]);
    let correlation = Arc::new(CorrelationSource::new(10));
    let metrics = Arc::new(MetricsRegistry::new());
    let (writer, log) = LogWriter::start(
        DiscardLog,
        LogRetention::DEFAULT,
        LogFilter::new(Severity::Debug),
        server_id,
        Arc::clone(&correlation),
    );
    state.install_observer(Arc::new(RuntimeObserver::new(
        server_id,
        SystemMonotonicClock::start(),
        correlation,
        log,
        Arc::clone(&metrics),
    )));
    Observed {
        metrics,
        _writer: writer,
    }
}

/// A durable account-creation plan against the live revision.
pub(super) fn account_plan(context: &StateCoreContext, seed: u8) -> TestResult<MutationPlan> {
    let account = agenc_relay_domain::AccountState::new(
        agenc_relay_testkit::account_id(seed),
        agenc_relay_testkit::generation(1)?,
        context.domain().revision(),
    );
    Ok(context.domain().plan_account_created(account)?)
}

/// A fanout with no target and no frame.
pub(super) fn empty_fanout() -> TestResult<FanoutRequest> {
    Ok(FanoutRequest::new(Vec::new(), Vec::new())?)
}

/// A signed administrative audit event of `phase` over `command`.
pub(super) fn audit_event(
    phase: agenc_relay_admin::AdminAuditPhase,
    command: &[u8],
) -> TestResult<agenc_relay_admin::AdminAuditEvent> {
    audit_event_at(phase, command, 50)
}

/// A signed administrative audit event created at `created_at`.
pub(super) fn audit_event_at(
    phase: agenc_relay_admin::AdminAuditPhase,
    command: &[u8],
    created_at: u64,
) -> TestResult<agenc_relay_admin::AdminAuditEvent> {
    use agenc_relay_admin::{AdminAuditEvent, AdminAuditEventTbs, AdminCommandTbs, AdminSessionId};
    use agenc_relay_crypto::{Ed25519SecretKey, audit_signing_key_id};
    use agenc_relay_types::{NetworkId, OperatorId, ServerId};

    let operator_key = Ed25519SecretKey::from_bytes([21; 32]);
    let audit_key = Ed25519SecretKey::from_bytes([22; 32]);
    let network_id = NetworkId::from_bytes([1; 32]);
    let server_id = ServerId::from_bytes([2; 16]);
    let command_tbs = AdminCommandTbs::new(
        network_id,
        server_id,
        AdminSessionId::from_bytes([23; 16]),
        0,
        None,
        command,
    )?;
    let operator_signature = command_tbs.sign(&operator_key)?;
    Ok(AdminAuditEvent::sign(
        AdminAuditEventTbs {
            network_id,
            server_id,
            audit_signing_key_id: *audit_signing_key_id(audit_key.public_key().as_bytes())?
                .as_bytes(),
            audit_sequence: 0,
            created_at,
            operator_id: OperatorId::from_bytes([24; 16]),
            command_tbs,
            operator_signature,
            phase,
            previous_event_hash: [0; 32],
        },
        &audit_key,
    )?)
}

/// Returns once the storage owner has taken every request queued before this
/// call. The owner serves its two-slot request queue in order, so a read that
/// completed proves nothing older is still waiting in it.
pub(super) async fn storage_owner_idle(fixture: &mut StateCoreFixture) -> TestResult {
    use agenc_relay_storage::{ReadPlan, StorageError, StoredKey, TableId};
    let read_id = loop {
        let plan = ReadPlan::exact(TableId::OpaqueRecord, StoredKey::new(vec![1])?);
        match fixture.context_mut()?.submit_storage_read(plan) {
            Ok(read_id) => break read_id,
            Err(StorageError::QueueFull) => tokio::task::yield_now().await,
            Err(error) => return Err(error.into()),
        }
    };
    while fixture.next_storage_read().await?.read_id != read_id {}
    Ok(())
}
