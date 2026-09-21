//! Authenticated stored state compared after all sessions have closed.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_storage::{
    AccountRecordBody, ChannelRecordBody, ReadPlan, SealedRecord, StorageOpenConfig, StorageOwner,
};
use agenc_relay_types::{MessageId, UtcSecond};

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Snapshot {
    account: Vec<u8>,
    channels: Vec<(String, Vec<u8>)>,
    live_sessions: usize,
    session_tombstones: usize,
}

fn open(fixture: &LiveFixture) -> TestResult<StorageOwner> {
    let config = load_config(&fixture.config_path, ValidationDepth::Host)?;
    Ok(StorageOwner::start(StorageOpenConfig {
        expected_network_id: fixture.network_id,
        expected_server_id: fixture.server_id,
        state_directory: StateDirectory::open(
            &config.storage.state_dir,
            &embedded_storage_qualifications()?,
        )?,
        storage_master_key: StorageMasterKey::from_bytes([7; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes([8; 32]),
        login_index_key: LoginIndexKey::from_bytes([9; 32]),
        previous_login_index_key: None,
        limits: StorageEngineLimits {
            redb_cache_bytes: DEFAULT_REDB_CACHE_BYTES,
            fixed_reserve_bytes: DISK_RESERVE_BYTES,
            reserve_percent: 1,
            database_max_bytes: DATABASE_MAX_BYTES,
            backup_max_bytes: BACKUP_MAX_BYTES,
            integrity_checkpoint_manifests: 10_000,
        },
    })?)
}

fn rows(owner: &StorageOwner, table: TableId) -> TestResult<Vec<PersistentRecordValue>> {
    let recovered = owner.recovered_state();
    let keys = agenc_relay_runtime::state_core::durable::KeyDeriver::new(
        StorageMasterKey::from_bytes([7; 32]),
        recovered.database_binding(),
        recovered.storage_key_generation(),
    )?;
    let read = owner
        .port()
        .try_read(ReadPlan::range(
            table,
            StoredKey::new(vec![0; 16])?,
            StoredKey::new(vec![255; 16])?,
            16,
        )?)?
        .wait()?;
    read.records
        .iter()
        .map(|row| {
            let sealed = SealedRecord::decode(&row.sealed_record)?;
            let opened = keys.open(table, &row.key, &sealed)?;
            Ok(PersistentRecordValue::decode(
                table,
                opened.expose_for_storage_codec(),
            )?)
        })
        .collect()
}

pub(super) fn snapshot(fixture: &LiveFixture, account: AccountId) -> TestResult<Snapshot> {
    let owner = open(fixture)?;
    let accounts = rows(&owner, TableId::Account)?;
    assert_eq!(accounts.len(), 1);
    let mut stored = AccountRecordBody::decode(
        accounts
            .first()
            .ok_or_else(|| failure("account missing"))?
            .body(),
    )?;
    assert_eq!(stored.account_id, account);
    let canonical = AccountId::from_random(AccountRandomId::from_bytes([1; 16]));
    stored.account_id = canonical;
    let account_body = AccountRecordBody::encode(&stored)?;
    let mut channels = Vec::new();
    for row in rows(&owner, TableId::Channel)? {
        let mut channel = ChannelRecordBody::decode(row.body())?;
        assert_eq!(channel.creator.account_id(), Some(account));
        assert!(channel.memberships.is_empty());
        assert_eq!(channel.role_grants.len(), 1);
        for (id, _) in &mut channel.role_grants {
            assert_eq!(*id, account);
            *id = canonical;
        }
        let name = channel.name.presentation().to_owned();
        let seed = match name.as_str() {
            "#public" => 2,
            "#secret" => 3,
            _ => return Err(failure("unexpected durable channel")),
        };
        channel.channel_id = ChannelInstanceId::from_bytes([seed; 16]);
        assert!(channel.created_at.get() > 0);
        channel.created_at = UtcSecond::from_unix_seconds(1);
        let topic = channel
            .topic
            .as_mut()
            .ok_or_else(|| failure("retained topic missing"))?;
        assert_eq!(topic.text, format!("{name} retained topic"));
        assert!(topic.set_at.get() > 0);
        topic.set_at = UtcSecond::from_unix_seconds(1);
        topic.message_id = MessageId::from_bytes([seed; 16]);
        topic.setter = UserId::from_bytes([4; 16]);
        let mut body = ChannelRecordBody::encode(&channel)?;
        replace_creator(&mut body, account, canonical)?;
        let decoded = ChannelRecordBody::decode(&body)?;
        assert_eq!(decoded.creator.account_id(), Some(canonical));
        channels.push((name, body));
    }
    channels.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(channels.len(), 2);
    let sessions = rows(&owner, TableId::Session)?;
    let live_sessions = sessions
        .iter()
        .filter(|row| row.record_kind() == LIVE_RECORD_KIND)
        .count();
    let session_tombstones = sessions.len() - live_sessions;
    assert_eq!(live_sessions, 0);
    owner.shutdown()?;
    Ok(Snapshot {
        account: account_body,
        channels,
        live_sessions,
        session_tombstones,
    })
}

fn replace_creator(body: &mut [u8], actual: AccountId, canonical: AccountId) -> TestResult {
    let positions: Vec<_> = body
        .windows(16)
        .enumerate()
        .filter_map(|(position, bytes)| (bytes == actual.random().as_bytes()).then_some(position))
        .collect();
    assert_eq!(
        positions.len(),
        1,
        "only the already-validated creator remains unnormalized"
    );
    let position = *positions
        .first()
        .ok_or_else(|| failure("creator bytes missing"))?;
    body.get_mut(position..position + 16)
        .ok_or_else(|| failure("creator bounds"))?
        .copy_from_slice(canonical.random().as_bytes());
    Ok(())
}
