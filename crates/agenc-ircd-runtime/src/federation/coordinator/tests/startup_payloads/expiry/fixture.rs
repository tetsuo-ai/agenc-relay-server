//! Actual sealed Item, Token, ACK and sequence rows, with a valid application envelope.
#![forbid(unsafe_code)]
use super::*;
use crate::state_core::timers::TimerKind;
use agenc_ircd_storage::e2ee_records::DeliveryGrant;
use agenc_ircd_storage::{ReadPlan, StoredKey};

pub(super) struct Fixture {
    pub(super) coordinator: FederationCoordinator,
    pub(super) core: StateCoreFixture,
    pub(super) id: [u8; 32],
}

pub(super) fn token(sequence: u64) -> [u8; 32] {
    let mut token = [9; 32];
    token[..8].copy_from_slice(&sequence.to_be_bytes());
    token
}

pub(super) fn item_key(sequence: u64) -> TestResult<StoredKey> {
    Ok(MailboxRow::item_key(
        &[1; 32],
        &[2; 16],
        MailboxKind::Application,
        sequence,
    )?)
}

fn write(key: StoredKey, kind: u16, body: Vec<u8>) -> TestResult<Write> {
    let value = PersistentRecordValue::new(TableId::E2eeState, kind, 1, 0, None, Vec::new(), body)?;
    Ok(Write::put(TableId::E2eeState, key, value.encode()?)?)
}

impl Fixture {
    pub(super) async fn new(expired: u64, live_tail: bool, acks: bool) -> TestResult<Self> {
        let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
        core.context_mut()?.set_wall_for_test(2000);
        let network = *core.identity.network_id.as_bytes();
        let bytes = application(network)?;
        let id = *ObjectId::compute(&bytes).as_bytes();
        let conversation_id = agenc_ircd_e2ee::ids::conversation_id(&network, &[33; 32])?;
        let count = expired + u64::from(live_tail);
        let owner =
            MailboxSequenceRow::new([1; 32], [2; 16], MailboxKind::Application, count.max(1))?;
        let mut writes = vec![
            CompanionCoordinator::object_write(&bytes).map_err(|e| format!("object: {e:?}"))?,
            write(owner.key()?, MAILBOX_SEQUENCE_ROW_KIND, owner.encode()?)?,
        ];
        for sequence in 0..count {
            let grant = DeliveryGrant {
                token: token(sequence),
                session_generation: 7,
                expires_at: if sequence < expired { 3000 } else { 1000 },
            };
            let item = MailboxRow::Item {
                object_id: id,
                conversation_id,
                inserted_at: 1,
                expires_at: if sequence < expired { 1000 } else { 4000 },
                grant: Some(grant),
            };
            let token_row = MailboxRow::Token {
                account_digest: [1; 32],
                device_id: [2; 16],
                kind: MailboxKind::Application,
                sequence,
                object_id: id,
                session_generation: grant.session_generation,
                expires_at: grant.expires_at,
            };
            writes.push(write(
                item_key(sequence)?,
                MAILBOX_ROW_KIND,
                item.encode()?,
            )?);
            writes.push(write(
                MailboxRow::token_key(&grant.token)?,
                MAILBOX_ROW_KIND,
                token_row.encode()?,
            )?);
        }
        if acks {
            for (token, retain_until) in [([250; 32], 1000), ([251; 32], 3000)] {
                let row = MailboxRow::Ack {
                    object_id: id,
                    acknowledged_at: 100,
                    retain_until,
                };
                writes.push(write(
                    MailboxRow::ack_key(&[1; 32], &[2; 16], &token)?,
                    MAILBOX_ROW_KIND,
                    row.encode()?,
                )?);
            }
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
        })
    }

    pub(super) fn executor(&self) -> TestResult<&CompanionCoordinator> {
        self.coordinator
            .companion_executor()
            .ok_or_else(|| "executor".into())
    }

    pub(super) fn wake(&mut self) -> TestResult {
        let context = self.core.context_mut()?;
        let now = context.now();
        for _ in 0..32 {
            let entry = context
                .timers_mut()
                .pop_due(now)
                .ok_or("mailbox expiry timer")?;
            if entry.kind == TimerKind::CompanionMailboxMaintenance {
                assert!(self.coordinator.timer_fired(context, entry));
                return Ok(());
            }
        }
        Err("mailbox timer bound".into())
    }

    pub(super) fn retry(&mut self) -> TestResult {
        let now = self.core.context_mut()?.now().get();
        self.core
            .context_mut()?
            .set_monotonic_for_test(now.checked_add(1000).ok_or("tick")?);
        self.wake()
    }

    pub(super) async fn commit(&mut self) -> TestResult {
        assert!(self.coordinator.pending.is_some());
        self.core.commit_staged_batch().await?;
        self.coordinator.batch_applied(self.core.context_mut()?);
        assert!(self.coordinator.loaded());
        assert_eq!(self.coordinator.counters().violations, 0);
        Ok(())
    }

    pub(super) async fn restart(&mut self) -> TestResult {
        self.coordinator = empty_coordinator(&self.core)?;
        self.coordinator.startup(self.core.context_mut()?);
        helpers::drive(&mut self.coordinator, &mut self.core).await?;
        assert!(self.coordinator.loaded());
        assert_eq!(self.coordinator.counters().violations, 0);
        Ok(())
    }
}

pub(super) async fn stored(
    core: &mut StateCoreFixture,
    table: TableId,
    key: StoredKey,
) -> TestResult<Option<PersistentRecordValue>> {
    let id = core
        .context_mut()?
        .submit_storage_read(ReadPlan::exact(table, key.clone()))?;
    let message = helpers::next(core).await?;
    assert_eq!(message.read_id, id);
    let result = message.result?;
    assert!(!result.truncated);
    assert!(result.records.len() <= 1);
    let Some(row) = result.records.first() else {
        return Ok(None);
    };
    assert_eq!(row.table, table);
    assert!(row.key == key);
    let opened = core
        .context_mut()?
        .open_storage_plaintext(table, &key, &row.sealed_record)?;
    Ok(Some(PersistentRecordValue::decode(
        table,
        opened.expose_for_storage_codec(),
    )?))
}
