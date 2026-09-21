//! Idle expired-object collection runs on a node without peers, deletes the
//! durable body with its account in one transaction, and survives a
//! rejection, a lost receipt and a restart (ENC-09).
#![forbid(unsafe_code)]
use super::*;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use crate::state_core::timers::TimerKind;
use agenc_relay_e2ee::limits::SEQUENCER_RECORD_RETENTION_SECONDS;
use agenc_relay_storage::e2ee_records::{
    EXPIRY_PROGRESS_ROW_KIND, MAILBOX_ROW_KIND, MAILBOX_SEQUENCE_ROW_KIND, MailboxKind, MailboxRow,
    MailboxSequenceRow, OWNER_ROW_KIND, ObjectExpiryProgressRow, ObjectOwnerRow, RetentionClass,
};
use agenc_relay_storage::{ReadPlan, RecordReference, StoredKey};

/// The trusted acceptance and retirement seconds of the seeded account, and
/// a wall clock one second past the ordinary retention window.
const ACCEPTED: u64 = 1_000;
const RETIRED: u64 = 2_000;
const EXPIRED_AT: u64 = RETIRED + SEQUENCER_RECORD_RETENTION_SECONDS + 1;

struct Fixture {
    coordinator: FederationCoordinator,
    core: StateCoreFixture,
    id: [u8; 32],
    bytes: Vec<u8>,
}

fn state_write(key: StoredKey, kind: u16, body: Vec<u8>) -> TestResult<Write> {
    let value = PersistentRecordValue::new(TableId::E2eeState, kind, 1, 0, None, Vec::new(), body)?;
    Ok(Write::put(TableId::E2eeState, key, value.encode()?)?)
}

/// An ownership account naming exactly `owners`, retired at a trusted
/// second when nothing names the object.
fn owner_write(
    id: &[u8; 32],
    kind: ArcWireObjectKind,
    size: u64,
    owners: Vec<StoredKey>,
) -> TestResult<Write> {
    let retired_at = owners.is_empty().then_some(RETIRED);
    let row = ObjectOwnerRow {
        kind: kind.value(),
        size,
        retention: RetentionClass::Ordinary,
        accepted_at: ACCEPTED,
        reconstructed: false,
        retired_at,
    };
    let references = owners
        .into_iter()
        .map(|key| RecordReference::new(TableId::E2eeState, key))
        .collect::<Result<Vec<_>, _>>()?;
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        OWNER_ROW_KIND,
        1,
        0,
        None,
        references,
        row.encode()?,
    )?;
    Ok(Write::put(
        TableId::E2eeState,
        ObjectOwnerRow::key(id)?,
        value.encode()?,
    )?)
}

/// A retained Commit body, which startup keeps resident without a mailbox.
fn commit_object() -> TestResult<Vec<u8>> {
    Ok(ArcWireObject::new(ArcWireObjectKind::CommitMls, vec![31; 96])?.encode()?)
}

/// The mailbox rows that keep one object owned.
fn owning_rows(id: [u8; 32], conversation: [u8; 32]) -> TestResult<Vec<Write>> {
    let owner = MailboxSequenceRow::new([1; 32], [2; 16], MailboxKind::Application, 1)?;
    let item = MailboxRow::Item {
        object_id: id,
        conversation_id: conversation,
        inserted_at: 1,
        expires_at: u64::MAX,
        grant: None,
    };
    Ok(vec![
        state_write(owner.key()?, MAILBOX_SEQUENCE_ROW_KIND, owner.encode()?)?,
        state_write(
            MailboxRow::item_key(&[1; 32], &[2; 16], MailboxKind::Application, 0)?,
            MAILBOX_ROW_KIND,
            item.encode()?,
        )?,
    ])
}

impl Fixture {
    /// One retained object whose account is unowned and retired at
    /// `RETIRED`, or an application payload a live mailbox item still owns.
    async fn new(owned: bool) -> TestResult<Self> {
        let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
        core.context_mut()?.set_wall_for_test(EXPIRED_AT);
        let network = *core.identity.network_id.as_bytes();
        let (bytes, kind) = if owned {
            (application(network)?, ArcWireObjectKind::ApplicationMls)
        } else {
            (commit_object()?, ArcWireObjectKind::CommitMls)
        };
        let id = *ObjectId::compute(&bytes).as_bytes();
        let size = u64::try_from(bytes.len())?;
        let conversation = agenc_relay_e2ee::ids::conversation_id(&network, &[33; 32])?;
        let item_key = MailboxRow::item_key(&[1; 32], &[2; 16], MailboxKind::Application, 0)?;
        let owners = if owned { vec![item_key] } else { Vec::new() };
        let mut writes = vec![
            CompanionCoordinator::object_write(&bytes).map_err(|e| format!("object: {e:?}"))?,
            owner_write(&id, kind, size, owners)?,
        ];
        if owned {
            writes.extend(owning_rows(id, conversation)?);
        }
        helpers::commit(&mut core, writes).await?;
        let mut coordinator = empty_coordinator(&core)?;
        coordinator.startup(core.context_mut()?);
        helpers::drive(&mut coordinator, &mut core).await?;
        assert!(coordinator.loaded());
        assert_eq!(coordinator.counters().violations, 0);
        Ok(Self {
            coordinator,
            core,
            id,
            bytes,
        })
    }

    fn executor(&self) -> TestResult<&CompanionCoordinator> {
        self.coordinator
            .companion_executor()
            .ok_or_else(|| "executor".into())
    }

    /// Fires the collector's own maintenance wake, ignoring the other
    /// bounded maintenance timers.
    fn wake(&mut self) -> TestResult {
        let context = self.core.context_mut()?;
        let now = context.now();
        for _ in 0..32 {
            let entry = context.timers_mut().pop_due(now).ok_or("object timer")?;
            if entry.kind == TimerKind::CompanionObjectMaintenance {
                assert!(self.coordinator.timer_fired(context, entry));
                return Ok(());
            }
        }
        Err("object timer bound".into())
    }

    async fn commit(&mut self) -> TestResult {
        assert!(self.coordinator.pending.is_some());
        self.core.commit_staged_batch().await?;
        self.coordinator.batch_applied(self.core.context_mut()?);
        assert!(self.coordinator.loaded());
        assert_eq!(self.coordinator.counters().violations, 0);
        Ok(())
    }

    async fn restart(&mut self) -> TestResult {
        self.coordinator = empty_coordinator(&self.core)?;
        self.coordinator.startup(self.core.context_mut()?);
        helpers::drive(&mut self.coordinator, &mut self.core).await?;
        assert!(self.coordinator.loaded());
        assert_eq!(self.coordinator.counters().violations, 0);
        Ok(())
    }

    async fn stored(&mut self, table: TableId, key: StoredKey) -> TestResult<Option<Vec<u8>>> {
        let id = self
            .core
            .context_mut()?
            .submit_storage_read(ReadPlan::exact(table, key.clone()))?;
        let message = helpers::next(&mut self.core).await?;
        assert_eq!(message.read_id, id);
        let result = message.result?;
        let Some(row) = result.records.first() else {
            return Ok(None);
        };
        let opened =
            self.core
                .context_mut()?
                .open_storage_plaintext(table, &key, &row.sealed_record)?;
        let value = PersistentRecordValue::decode(table, opened.expose_for_storage_codec())?;
        Ok(Some(value.body().to_vec()))
    }

    async fn object_row(&mut self) -> TestResult<Option<Vec<u8>>> {
        let key = StoredKey::new(self.id.to_vec())?;
        self.stored(TableId::E2eeObject, key).await
    }
}

#[tokio::test]
async fn idle_collection_deletes_an_expired_unowned_object_and_survives_restart() -> TestResult {
    let mut f = Fixture::new(false).await?;
    assert!(
        f.coordinator
            .companion_executor()
            .ok_or("executor")?
            .owner_reconstruction
            .is_clean()
    );
    assert_eq!(f.executor()?.state.objects.get(&f.id), Some(&f.bytes));
    let budget = f.core.context_mut()?.backing_budget_for_test();
    let charged = budget.charged();
    f.wake()?;
    // Staging alone publishes nothing: the body is still resident.
    assert!(f.coordinator.pending.is_some());
    assert!(f.executor()?.state.objects.contains_key(&f.id));
    f.commit().await?;
    let executor = f.executor()?;
    assert!(!executor.state.objects.contains_key(&f.id));
    assert_eq!(executor.state.object_bytes, 0);
    assert!(executor.state.object_memory.is_empty());
    assert!(budget.charged() < charged);
    // The body, its account and the advanced continuation committed together.
    assert!(f.object_row().await?.is_none());
    let owner_key = ObjectOwnerRow::key(&f.id)?;
    assert!(f.stored(TableId::E2eeState, owner_key).await?.is_none());
    let progress = f
        .stored(TableId::E2eeState, ObjectExpiryProgressRow::key()?)
        .await?
        .ok_or("progress row")?;
    let row = ObjectExpiryProgressRow::decode(&progress)?;
    assert_eq!((row.deleted_objects, row.passes), (1, 1));
    assert_eq!(row.deleted_bytes, u64::try_from(f.bytes.len())?);
    f.restart().await?;
    let executor = f.executor()?;
    assert!(!executor.state.objects.contains_key(&f.id));
    assert!(executor.owner_reconstruction.is_clean());
    assert!(f.object_row().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn a_rejected_collection_keeps_the_object_and_retries_the_same_page() -> TestResult {
    let mut f = Fixture::new(false).await?;
    f.wake()?;
    f.core
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_relay_storage::StorageError::QueueFull)?;
    f.coordinator.batch_rejected(f.core.context_mut()?);
    assert!(f.coordinator.pending.is_none());
    // A determinate refusal publishes nothing and advances no continuation.
    assert_eq!(f.executor()?.state.objects.get(&f.id), Some(&f.bytes));
    assert!(f.object_row().await?.is_some());
    assert!(
        f.stored(TableId::E2eeState, ObjectExpiryProgressRow::key()?)
            .await?
            .is_none()
    );
    let now = f.core.context_mut()?.now().get();
    f.core
        .context_mut()?
        .set_monotonic_for_test(now.checked_add(2_000).ok_or("tick")?);
    f.wake()?;
    f.commit().await?;
    assert!(!f.executor()?.state.objects.contains_key(&f.id));
    assert!(f.object_row().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn a_receipt_lost_before_publication_reopens_with_the_object_deleted() -> TestResult {
    let mut f = Fixture::new(false).await?;
    f.wake()?;
    assert!(f.coordinator.pending.is_some());
    // The batch commits but its callback never reaches this coordinator.
    f.core.commit_staged_batch().await?;
    f.restart().await?;
    let executor = f.executor()?;
    assert!(!executor.state.objects.contains_key(&f.id));
    assert!(executor.owner_reconstruction.is_clean());
    assert_eq!(executor.state.object_bytes, 0);
    assert!(f.object_row().await?.is_none());
    let progress = f
        .stored(TableId::E2eeState, ObjectExpiryProgressRow::key()?)
        .await?
        .ok_or("progress row")?;
    assert_eq!(
        ObjectExpiryProgressRow::decode(&progress)?.deleted_objects,
        1
    );
    Ok(())
}

#[tokio::test]
async fn a_still_owned_object_is_never_collected_by_an_idle_pass() -> TestResult {
    let mut f = Fixture::new(true).await?;
    assert_eq!(f.executor()?.state.objects.get(&f.id), Some(&f.bytes));
    // The collector stages nothing at all, so the wake leaves no batch.
    f.wake()?;
    assert!(f.coordinator.pending.is_none());
    assert_eq!(f.executor()?.state.objects.get(&f.id), Some(&f.bytes));
    let body = f.object_row().await?.ok_or("stored object")?;
    assert_eq!(
        agenc_relay_storage::e2ee_records::ObjectRow::decode(&body)?.bytes,
        f.bytes
    );
    assert!(
        f.stored(TableId::E2eeState, ObjectExpiryProgressRow::key()?)
            .await?
            .is_none()
    );
    assert_eq!(
        agenc_relay_storage::e2ee_records::record_kind_for_key(&ObjectExpiryProgressRow::key()?)?,
        EXPIRY_PROGRESS_ROW_KIND
    );
    Ok(())
}
