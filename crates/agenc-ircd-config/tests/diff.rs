#![forbid(unsafe_code)]

//! The typed reload diff: every reloadable and every restart-only field flipped
//! one at a time.

mod support;

use agenc_ircd_config::{
    Config, ConfigDiff, DisplayLabel, DnsName, HistoryDefault, HttpsOrigin, LimitKey, ListenerBind,
    ListenerPurpose, NodeRole, PeerConfig, PeerEndpoint, RateKey, RateSpec, RegistrationPolicy,
    ReloadPlan, ReloadRejected, ReloadableChange, RestartOnlyField, ShutdownPhases, SocksEndpoint,
    WssPolicy,
};
use agenc_ircd_types::{AdminPermissionSet, NetworkId, OperatorId, RecoveryEpoch, ServerId};
use support::{DUAL, PUBLIC, parse};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn restart_only(active: &Config, candidate: &Config, field: RestartOnlyField) {
    let diff = ConfigDiff::compute(active, candidate);
    assert!(
        diff.restart_only.contains(&field),
        "{field:?} missing from {diff:?}"
    );
    assert!(matches!(
        ReloadPlan::try_from(diff),
        Err(ReloadRejected::RestartOnly(fields)) if fields.contains(&field)
    ));
}

fn reloadable(active: &Config, candidate: &Config, predicate: impl Fn(&ReloadableChange) -> bool) {
    let diff = ConfigDiff::compute(active, candidate);
    assert!(
        diff.restart_only.is_empty(),
        "unexpected restart-only fields: {diff:?}"
    );
    assert!(
        diff.reloadable.iter().any(predicate),
        "change missing from {diff:?}"
    );
    assert!(ReloadPlan::try_from(diff).is_ok());
}

#[test]
fn identical_documents_produce_an_empty_diff() -> TestResult {
    let active = parse(PUBLIC)?;
    let diff = ConfigDiff::compute(&active, &active.clone());
    assert!(diff.is_empty());
    assert!(ReloadPlan::try_from(diff).is_ok_and(|plan| plan.changes().is_empty()));
    Ok(())
}

#[test]
fn network_and_server_fields_classify_exactly() -> TestResult {
    let active = parse(PUBLIC)?;
    let mut candidate = active.clone();
    candidate.network.display_name = DisplayLabel::parse("other")?;
    reloadable(&active, &candidate, |change| {
        *change == ReloadableChange::DisplayName
    });

    let mut candidate = active.clone();
    candidate.network.network_id = NetworkId::from_bytes([9; 32]);
    restart_only(&active, &candidate, RestartOnlyField::NetworkId);
    let mut candidate = active.clone();
    candidate.network.coordinator_server_id = ServerId::from_bytes([9; 16]);
    restart_only(&active, &candidate, RestartOnlyField::CoordinatorServerId);
    let mut candidate = active.clone();
    candidate.network.dns = None;
    restart_only(&active, &candidate, RestartOnlyField::DnsEndpoint);
    let dual = parse(DUAL)?;
    let mut candidate = dual.clone();
    candidate.network.onion = None;
    restart_only(&dual, &candidate, RestartOnlyField::OnionEndpoint);

    let mut candidate = active.clone();
    candidate.server.server_id = ServerId::from_bytes([9; 16]);
    restart_only(&active, &candidate, RestartOnlyField::ServerId);
    let mut candidate = active.clone();
    candidate.server.name = DnsName::parse("other.example")?;
    restart_only(&active, &candidate, RestartOnlyField::ServerName);
    let mut candidate = active.clone();
    candidate.server.data_dir = "/srv/other".into();
    restart_only(&active, &candidate, RestartOnlyField::DataDir);
    let mut candidate = active.clone();
    candidate.server.runtime_dir = "/run/other".into();
    restart_only(&active, &candidate, RestartOnlyField::RuntimeDir);
    let mut candidate = active.clone();
    candidate.server.memory_budget_bytes += 1;
    restart_only(&active, &candidate, RestartOnlyField::MemoryBudget);
    let mut candidate = active.clone();
    candidate.server.crypto_worker_threads += 1;
    restart_only(&active, &candidate, RestartOnlyField::WorkerThreads);
    let mut candidate = active.clone();
    candidate.server.require_locked_secrets = true;
    restart_only(&active, &candidate, RestartOnlyField::RequireLockedSecrets);
    let mut candidate = active.clone();
    candidate.server.shutdown = ShutdownPhases {
        drain_seconds: 21,
        ..active.server.shutdown
    };
    restart_only(&active, &candidate, RestartOnlyField::ShutdownPhaseRaised);
    let mut candidate = active.clone();
    candidate.server.shutdown = ShutdownPhases {
        drain_seconds: 19,
        ..active.server.shutdown
    };
    reloadable(&active, &candidate, |change| {
        *change == ReloadableChange::ShutdownPhaseLowered
    });
    Ok(())
}

#[test]
fn listener_and_tls_fields_classify_exactly() -> TestResult {
    let active = parse(DUAL)?;
    let mut candidate = active.clone();
    candidate.listeners.pop();
    restart_only(&active, &candidate, RestartOnlyField::ListenerSet);
    let mut candidate = active.clone();
    if let Some(listener) = candidate.listeners.first_mut() {
        listener.enabled = false;
    }
    restart_only(&active, &candidate, RestartOnlyField::ListenerTransport);
    let mut candidate = active.clone();
    if let Some(tls) = candidate
        .listeners
        .first_mut()
        .and_then(|listener| listener.tls.as_mut())
    {
        tls.private_key_file = "/etc/agenc/tls/new.key".into();
    }
    restart_only(&active, &candidate, RestartOnlyField::ListenerKeyMaterial);
    let mut candidate = active.clone();
    if let Some(listener) = candidate.listeners.get_mut(2) {
        listener.client_ca_file = Some("/etc/agenc/tls/new-ca.pem".into());
    }
    restart_only(&active, &candidate, RestartOnlyField::ListenerKeyMaterial);
    let mut candidate = active.clone();
    if let Some(policy) = candidate
        .listeners
        .get_mut(3)
        .and_then(|listener| listener.local_admin.as_mut())
    {
        policy.allowed_uids.push(2000);
    }
    restart_only(&active, &candidate, RestartOnlyField::ListenerLocalAdmin);
    let mut candidate = active.clone();
    if let Some(listener) = candidate.listeners.first_mut() {
        listener.max_connections += 1;
    }
    restart_only(&active, &candidate, RestartOnlyField::ListenerCeilingRaised);
    let mut candidate = active.clone();
    if let Some(listener) = candidate.listeners.first_mut() {
        listener.max_connections -= 1;
    }
    reloadable(
        &active,
        &candidate,
        |change| matches!(change, ReloadableChange::ListenerCeilingLowered { listener, from: 50_000, to: 49_999 } if listener.as_str() == "public"),
    );
    let mut candidate = active.clone();
    if let Some(tls) = candidate
        .listeners
        .first_mut()
        .and_then(|listener| listener.tls.as_mut())
    {
        tls.certificate_file = "/etc/agenc/tls/renewed.crt".into();
    }
    reloadable(&active, &candidate, |change| {
        matches!(change, ReloadableChange::CertificateChain { .. })
    });
    let mut candidate = active.clone();
    if let Some(listener) = candidate.listeners.first_mut() {
        listener.wss = Some(WssPolicy {
            allowed_origins: vec![HttpsOrigin::parse("https://chat.example")?],
            allow_missing_origin: false,
        });
    }
    reloadable(&active, &candidate, |change| {
        matches!(change, ReloadableChange::OriginPolicy { .. })
    });
    let mut candidate = active.clone();
    candidate.tls.session_tickets = false;
    restart_only(&active, &candidate, RestartOnlyField::TlsPolicy);
    Ok(())
}

#[test]
fn federation_and_peer_fields_classify_exactly() -> TestResult {
    let active = parse(DUAL)?;
    let mut candidate = active.clone();
    candidate.federation.enabled = false;
    restart_only(&active, &candidate, RestartOnlyField::FederationProfile);
    let mut candidate = active.clone();
    candidate.federation.tor_socks_endpoint = Some(SocksEndpoint::parse("127.0.0.1:9050")?);
    restart_only(&active, &candidate, RestartOnlyField::FederationProfile);
    let mut candidate = active.clone();
    candidate.federation.connect_timeout_seconds += 1;
    restart_only(&active, &candidate, RestartOnlyField::ConnectTimeoutRaised);
    let mut candidate = active.clone();
    candidate.federation.connect_timeout_seconds -= 1;
    reloadable(&active, &candidate, |change| {
        *change == ReloadableChange::ConnectTimeoutLowered
    });
    let mut candidate = active.clone();
    candidate.federation.peers.clear();
    restart_only(&active, &candidate, RestartOnlyField::PeerSet);
    let mut candidate = active.clone();
    if let Some(peer) = candidate.federation.peers.first_mut() {
        peer.signing_public_key = [9; 32];
    }
    restart_only(&active, &candidate, RestartOnlyField::PeerIdentity);
    let mut candidate = active.clone();
    if let Some(peer) = candidate.federation.peers.first_mut() {
        peer.endpoints = vec![PeerEndpoint::parse("tcp:203.0.113.9:7000")?];
    }
    reloadable(&active, &candidate, |change| {
        matches!(change, ReloadableChange::PeerEndpoints { .. })
    });
    let mut candidate = active.clone();
    if let Some(peer) = candidate.federation.peers.first_mut() {
        peer.enabled = false;
    }
    reloadable(&active, &candidate, |change| {
        matches!(change, ReloadableChange::PeerEnabled { enabled: false, .. })
    });
    Ok(())
}

#[test]
fn storage_accounts_and_limits_classify_exactly() -> TestResult {
    let active = parse(PUBLIC)?;
    let mut candidate = active.clone();
    candidate.storage.state_dir = "/srv/agenc/state2".into();
    restart_only(&active, &candidate, RestartOnlyField::StateDir);
    let mut candidate = active.clone();
    candidate.storage.master_key_file = "/etc/agenc/keys/new.key".into();
    restart_only(&active, &candidate, RestartOnlyField::StorageKeys);
    let mut candidate = active.clone();
    candidate.storage.backup_dir = "/srv/backups2".into();
    restart_only(&active, &candidate, RestartOnlyField::BackupProfile);
    let mut candidate = active.clone();
    candidate.storage.disk_reserve_percent = 6;
    restart_only(&active, &candidate, RestartOnlyField::DiskReserve);
    let mut candidate = active.clone();
    candidate.storage.database_max_bytes -= 1;
    reloadable(&active, &candidate, |change| {
        matches!(change, ReloadableChange::DatabaseCeiling { .. })
    });
    let mut candidate = active.clone();
    candidate.storage.database_max_bytes += 1;
    restart_only(&active, &candidate, RestartOnlyField::DatabaseCeilingRaised);
    let mut candidate = active.clone();
    candidate.storage.backup_max_bytes += 1;
    reloadable(&active, &candidate, |change| {
        matches!(change, ReloadableChange::BackupCeiling { .. })
    });
    let mut candidate = active.clone();
    candidate.storage.integrity_checkpoint_manifests += 1;
    reloadable(&active, &candidate, |change| {
        *change == ReloadableChange::IntegrityCheckpointTarget
    });

    let mut candidate = active.clone();
    candidate.accounts.accept_clients = false;
    restart_only(&active, &candidate, RestartOnlyField::AcceptClients);
    let mut candidate = active.clone();
    candidate.accounts.account_service_hpke_public_key = [9; 32];
    restart_only(&active, &candidate, RestartOnlyField::AccountMaterial);
    let mut candidate = active.clone();
    candidate.accounts.max_reserved_nicknames = 6;
    restart_only(&active, &candidate, RestartOnlyField::AccountFixedLimit);
    let mut candidate = active.clone();
    candidate.accounts.max_contacts += 1;
    restart_only(&active, &candidate, RestartOnlyField::MaxContactsRaised);
    let mut candidate = active.clone();
    candidate.accounts.max_contacts -= 1;
    reloadable(&active, &candidate, |change| {
        *change == ReloadableChange::MaxContactsLowered
    });
    let mut candidate = active.clone();
    candidate.accounts.registration = RegistrationPolicy::Closed;
    candidate.accounts.allow_guests = false;
    candidate.accounts.default_public_presence = true;
    candidate.accounts.default_allow_guest_dm = true;
    candidate.accounts.default_direct_messages = agenc_ircd_config::DirectMessageDefault::Deny;
    let diff = ConfigDiff::compute(&active, &candidate);
    assert_eq!(diff.reloadable.len(), 5);
    assert!(diff.restart_only.is_empty());

    let mut candidate = active.clone();
    candidate.limits.values = candidate
        .limits
        .values
        .with(LimitKey::ClientConnections, 49_999);
    reloadable(&active, &candidate, |change| {
        matches!(
            change,
            ReloadableChange::LimitLowered {
                key: LimitKey::ClientConnections,
                from: 50_000,
                to: 49_999
            }
        )
    });
    let mut candidate = active.clone();
    candidate.limits.values = candidate
        .limits
        .values
        .with(LimitKey::ClientConnections, 50_001);
    let diff = ConfigDiff::compute(&active, &candidate);
    assert!(matches!(
        diff.reloadable.first(),
        Some(ReloadableChange::LimitRaised { .. })
    ));
    assert!(ReloadPlan::try_from(diff).is_ok_and(|plan| plan.requires_budget_check()));
    let mut candidate = active.clone();
    candidate.limits.rates = candidate
        .limits
        .rates
        .with(RateKey::NewDirect, RateSpec::new(2, 1, 8));
    reloadable(&active, &candidate, |change| {
        matches!(
            change,
            ReloadableChange::RateChanged {
                key: RateKey::NewDirect,
                ..
            }
        )
    });
    Ok(())
}

#[test]
fn privacy_moderation_and_e2ee_fields_classify_exactly() -> TestResult {
    let active = parse(PUBLIC)?;
    let mut candidate = active.clone();
    candidate.privacy.history_enabled = true;
    restart_only(&active, &candidate, RestartOnlyField::PrivacyPolicy);
    let mut candidate = active.clone();
    candidate.privacy.log_retention_hours += 1;
    restart_only(&active, &candidate, RestartOnlyField::LogRetentionRaised);
    let mut candidate = active.clone();
    candidate.privacy.log_retention_hours -= 1;
    candidate.privacy.motd_file = Some("/etc/agenc/motd.txt".into());
    candidate.privacy.public_info_file = Some("/etc/agenc/info.txt".into());
    candidate.privacy.history_default = HistoryDefault::SevenDays;
    let diff = ConfigDiff::compute(&active, &candidate);
    assert!(diff.restart_only.is_empty());
    assert_eq!(diff.reloadable.len(), 4);

    let mut candidate = active.clone();
    candidate.moderation.audit_retention_days += 1;
    restart_only(&active, &candidate, RestartOnlyField::AuditProfile);
    let mut candidate = active.clone();
    candidate.moderation.session_sanction_hours += 1;
    reloadable(&active, &candidate, |change| {
        *change == ReloadableChange::SanctionWindows
    });
    let mut candidate = active.clone();
    candidate.moderation.operators.clear();
    restart_only(&active, &candidate, RestartOnlyField::OperatorSet);
    let mut candidate = active.clone();
    if let Some(operator) = candidate.moderation.operators.first_mut() {
        operator.signing_public_key = [9; 32];
    }
    restart_only(&active, &candidate, RestartOnlyField::OperatorIdentity);
    let mut candidate = active.clone();
    if let Some(operator) = candidate.moderation.operators.first_mut() {
        operator.enabled = false;
        operator.permissions = AdminPermissionSet::from_names(["observe"])?;
        operator.display_label = "renamed".to_owned();
    }
    let diff = ConfigDiff::compute(&active, &candidate);
    assert!(diff.restart_only.is_empty());
    let operator_id = OperatorId::from_bytes([4; 16]);
    assert!(
        diff.reloadable
            .contains(&ReloadableChange::OperatorEnabled {
                operator_id,
                enabled: false
            })
    );
    assert!(
        diff.reloadable
            .contains(&ReloadableChange::OperatorPermissions { operator_id })
    );
    assert!(
        diff.reloadable
            .contains(&ReloadableChange::OperatorLabel { operator_id })
    );

    let mut candidate = active.clone();
    candidate.e2ee.max_group_leaves = 100;
    restart_only(&active, &candidate, RestartOnlyField::E2eeProfile);
    Ok(())
}

#[test]
fn every_remaining_restart_only_field_is_detected_alone() -> TestResult {
    let dual = parse(DUAL)?;
    let mut candidate = dual.clone();
    candidate.server.tokio_worker_threads += 1;
    restart_only(&dual, &candidate, RestartOnlyField::WorkerThreads);
    let mut candidate = dual.clone();
    if let Some(listener) = candidate.listeners.first_mut() {
        listener.bind = ListenerBind::Socket("203.0.113.1:6698".parse()?);
    }
    restart_only(&dual, &candidate, RestartOnlyField::ListenerTransport);
    let mut candidate = dual.clone();
    if let Some(listener) = candidate.listeners.first_mut() {
        listener.purpose = ListenerPurpose::ClientWss;
    }
    restart_only(&dual, &candidate, RestartOnlyField::ListenerTransport);
    let mut candidate = dual.clone();
    for listener in candidate.listeners.iter_mut().take(2) {
        if let Some(tls) = listener.tls.as_mut() {
            tls.private_key_file = "/etc/agenc/tls/rotated.key".into();
        }
    }
    let diff = ConfigDiff::compute(&dual, &candidate);
    assert_eq!(
        diff.restart_only
            .iter()
            .filter(|field| **field == RestartOnlyField::ListenerKeyMaterial)
            .count(),
        1
    );
    assert!(!diff.is_empty());

    let mut candidate = dual.clone();
    candidate.federation.private_ca_file = Some("/etc/agenc/tls/other-ca.pem".into());
    restart_only(&dual, &candidate, RestartOnlyField::FederationProfile);
    let mut candidate = dual.clone();
    candidate.federation.signing_private_key_file = Some("/etc/agenc/keys/other.key".into());
    restart_only(&dual, &candidate, RestartOnlyField::FederationProfile);
    let mut candidate = dual.clone();
    candidate.federation.reconnect_max_seconds += 1;
    restart_only(&dual, &candidate, RestartOnlyField::FederationProfile);
    let rename = |peer: &mut PeerConfig| {
        if let Ok(name) = DnsName::parse("renamed.example") {
            peer.server_name = name;
        }
    };
    let edits: [fn(&mut PeerConfig); 4] = [
        rename,
        |peer| peer.role = NodeRole::Coordinator,
        |peer| peer.recovery_epoch = RecoveryEpoch::from_bytes([1; 16]),
        |peer| peer.certificate_spki_sha256 = [1; 32],
    ];
    for edit in edits {
        let mut candidate = dual.clone();
        if let Some(peer) = candidate.federation.peers.first_mut() {
            edit(peer);
        }
        restart_only(&dual, &candidate, RestartOnlyField::PeerIdentity);
    }

    let active = parse(PUBLIC)?;
    let mut candidate = active.clone();
    candidate.storage.rollback_guard_key_file = "/etc/agenc/keys/other.key".into();
    restart_only(&active, &candidate, RestartOnlyField::StorageKeys);
    let mut candidate = active.clone();
    candidate.storage.login_index_key_file = "/etc/agenc/keys/other.key".into();
    restart_only(&active, &candidate, RestartOnlyField::StorageKeys);
    let mut candidate = active.clone();
    candidate.storage.backup_signing_private_key_file = "/etc/agenc/keys/other.key".into();
    restart_only(&active, &candidate, RestartOnlyField::BackupProfile);
    let mut candidate = active.clone();
    candidate.storage.disk_reserve_bytes += 1;
    restart_only(&active, &candidate, RestartOnlyField::DiskReserve);

    let mut candidate = active.clone();
    candidate.accounts.invite_verification_key_file = None;
    restart_only(&active, &candidate, RestartOnlyField::AccountMaterial);
    let mut candidate = active.clone();
    candidate.accounts.access_token_key_file = Some("/etc/agenc/keys/token.key".into());
    restart_only(&active, &candidate, RestartOnlyField::AccountMaterial);
    let mut candidate = active.clone();
    candidate.accounts.account_service_hpke_private_key_file = None;
    restart_only(&active, &candidate, RestartOnlyField::AccountMaterial);
    let mut candidate = active.clone();
    candidate.accounts.opaque_server_setup_file = None;
    restart_only(&active, &candidate, RestartOnlyField::AccountMaterial);
    let mut candidate = active.clone();
    candidate.accounts.auth_transaction_seconds += 1;
    restart_only(&active, &candidate, RestartOnlyField::AccountFixedLimit);
    let mut candidate = active.clone();
    candidate.accounts.create_transaction_seconds += 1;
    restart_only(&active, &candidate, RestartOnlyField::AccountFixedLimit);

    let mut candidate = active.clone();
    candidate.privacy.secret_lookup_floor_milliseconds += 1;
    restart_only(&active, &candidate, RestartOnlyField::PrivacyPolicy);
    let mut candidate = active.clone();
    candidate.privacy.whowas_retention_seconds += 1;
    restart_only(&active, &candidate, RestartOnlyField::PrivacyPolicy);

    let mut candidate = active.clone();
    candidate.moderation.audit_signing_private_key_file = "/etc/agenc/keys/other.key".into();
    restart_only(&active, &candidate, RestartOnlyField::AuditProfile);
    let mut candidate = active.clone();
    candidate.moderation.audit_trust_manifest_file = "/etc/agenc/trust/other.toml".into();
    restart_only(&active, &candidate, RestartOnlyField::AuditProfile);
    let mut candidate = active.clone();
    if let Some(operator) = candidate.moderation.operators.first_mut() {
        operator.certificate_spki_sha256 = Some([1; 32]);
    }
    restart_only(&active, &candidate, RestartOnlyField::OperatorIdentity);
    let mut candidate = active.clone();
    if let Some(operator) = candidate.moderation.operators.first_mut() {
        operator.local_uids.push(1001);
    }
    restart_only(&active, &candidate, RestartOnlyField::OperatorIdentity);
    let restart = ConfigDiff::compute(&active, &candidate);
    assert!(!restart.is_empty() && restart.reloadable.is_empty());
    Ok(())
}
