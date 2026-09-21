#![forbid(unsafe_code)]

//! The base entitlement the companion profile verifies an ESTATE cut
//! against (companion 12.5, ENC-15): a hosted channel detail and a hosted
//! account stand in the active projection or in the base snapshot generation
//! still being installed, whose cut pairs with the companion transfer.

use agenc_relay_domain::federation::{
    AccountRecord, ChannelDetailRecord, ProjectionRecord, SessionRecord,
};
use agenc_relay_domain::{
    ChannelNameValue, ContentPolicy, DisplayNameValue, HistoryPolicy, NicknameValue,
    PersistencePolicy, Visibility,
};
use agenc_relay_federation_wire::{FederationHash32, SnapshotIdentity};
use agenc_relay_types::{
    AccountId, AccountRandomId, ChannelInstanceId, FederationRole, Generation, NetworkId,
    RecoveryEpoch, Revision, ServerId, ServerIncarnation, SessionId, UserId,
};

use super::SnapshotInstall;
use crate::federation::PeerIdentity;
use crate::federation::edge::{EdgeConfig, EdgeFederation};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const EDGE: ServerId = ServerId::from_bytes([2; 16]);

fn edge() -> EdgeFederation {
    EdgeFederation::new(EdgeConfig {
        network_id: NetworkId::from_bytes([1; 32]),
        server_id: EDGE,
        server_name: "edge.example".to_owned(),
        incarnation: ServerIncarnation::from_bytes([4; 16]),
        coordinator: PeerIdentity::new(
            ServerId::from_bytes([3; 16]),
            "coordinator.example",
            FederationRole::Coordinator,
            RecoveryEpoch::from_bytes([5; 16]),
            agenc_relay_crypto::Ed25519SecretKey::from_bytes([6; 32]).public_key(),
            [7; 32],
        ),
    })
}

fn account(seed: u8) -> AccountId {
    AccountId::from_random(AccountRandomId::from_bytes([seed; 16]))
}

fn channel(seed: u8) -> ChannelInstanceId {
    ChannelInstanceId::from_bytes([seed; 16])
}

/// A listed plaintext channel detail at revision one.
pub(crate) fn detail(channel_id: ChannelInstanceId, name: &str) -> TestResult<ChannelDetailRecord> {
    Ok(ChannelDetailRecord {
        channel_id,
        name: ChannelNameValue::parse(name)?,
        channel_revision: Revision::new(1)?,
        visibility: Visibility::Listed,
        content_policy: ContentPolicy::Plaintext,
        persistence: PersistencePolicy::Ephemeral,
        simple_mode_bits: 4,
        history: HistoryPolicy::Off,
        e2ee_route_binding: None,
    })
}

fn session(seed: u8, held: AccountId) -> TestResult<SessionRecord> {
    Ok(SessionRecord {
        session_id: SessionId::from_bytes([seed; 16]),
        user_id: UserId::from_bytes([seed; 16]),
        home_server_id: EDGE,
        session_revision: Revision::new(1)?,
        account: Some((held, Generation::new(1)?)),
        nickname: NicknameValue::parse("Member")?,
        display_name: DisplayNameValue::prepare("Real Name")?,
        public_cloak: agenc_relay_testkit::deterministic_cloak(seed)?,
        account_label: None,
        user_mode_bits: 1,
        away: None,
    })
}

fn installing(entries: Vec<ProjectionRecord>) -> SnapshotInstall {
    SnapshotInstall {
        identity: SnapshotIdentity {
            snapshot_token: FederationHash32::from_bytes([9; 32]),
            recovery_epoch: RecoveryEpoch::from_bytes([5; 16]),
            projection_generation: 2,
            state_generation: 7,
            snapshot_digest: FederationHash32::from_bytes([8; 32]),
        },
        coordinator_incarnation: ServerIncarnation::from_bytes([17; 16]),
        expected: u64::try_from(entries.len()).unwrap_or(u64::MAX),
        entries,
        ids: Vec::new(),
        bytes: 0,
        verified: false,
        written: 0,
        ready_sent: false,
        cursor: None,
        staged_end: None,
        resync: Vec::new(),
    }
}

#[test]
fn a_base_entitlement_stands_in_the_active_or_the_installing_generation() -> TestResult {
    let mut edge = edge();
    let (hosted, foreign) = (account(40), account(41));
    assert!(!edge.holds_channel(channel(30)));
    assert!(!edge.hosts_account(hosted));
    assert_eq!(edge.hosted_accounts().count(), 0);

    // The installing generation: entries in strict key order.
    let mut entries = vec![
        ProjectionRecord::Session(session(20, hosted)?),
        ProjectionRecord::ChannelDetail(detail(channel(30), "#installing")?),
        ProjectionRecord::Account(AccountRecord {
            account_id: hosted,
            account_session_generation: Generation::new(1)?,
            account_revision: Revision::new(1)?,
        }),
    ];
    entries.sort_by_key(ProjectionRecord::key);
    edge.snapshot = Some(installing(entries));
    assert!(edge.holds_channel(channel(30)));
    assert!(!edge.holds_channel(channel(31)));
    assert!(edge.hosts_account(hosted));
    assert!(!edge.hosts_account(foreign));
    assert_eq!(edge.hosted_accounts().collect::<Vec<_>>(), vec![hosted]);

    // The active generation answers the same way once it stands alone.
    edge.snapshot = None;
    assert!(!edge.holds_channel(channel(30)));
    edge.replica.install_recovered(
        1,
        vec![ProjectionRecord::ChannelDetail(detail(
            channel(31),
            "#active",
        )?)],
    )?;
    assert!(edge.holds_channel(channel(31)));
    assert!(!edge.holds_channel(channel(30)));
    assert!(!edge.hosts_account(hosted));
    Ok(())
}

/// Hosts `channels` in the active projection of `edge` beside whatever it
/// already holds, for companion tests that need a base channel entitlement.
pub(crate) fn host_channels(
    edge: &mut EdgeFederation,
    channels: &[ChannelInstanceId],
) -> TestResult {
    let mut entries: Vec<ProjectionRecord> = edge.replica.entries().collect();
    for channel_id in channels {
        if edge.replica.channel(*channel_id).is_some() {
            continue;
        }
        let name: String = channel_id
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        entries.push(ProjectionRecord::ChannelDetail(detail(
            *channel_id,
            &format!("#c{name}"),
        )?));
    }
    entries.sort_by_key(ProjectionRecord::key);
    let generation = edge.replica.projection_generation();
    edge.replica.install_recovered(generation, entries)?;
    Ok(())
}

/// Drops every standing entry of `edge`, so it hosts nothing.
pub(crate) fn host_nothing(edge: &mut EdgeFederation) -> TestResult {
    let generation = edge.replica.projection_generation();
    edge.replica.install_recovered(generation, Vec::new())?;
    Ok(())
}
