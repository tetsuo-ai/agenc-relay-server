//! Typed reload diffs: reloadable changes versus restart-only fields (spec 22.6
//! 4582-4596, C.2-C.7 reload classes).

use agenc_ircd_types::{OperatorId, ServerId};

use crate::accounts::AccountsConfig;
use crate::config::Config;
use crate::federation::{FederationConfig, PeerConfig};
use crate::limits::{LIMIT_ROWS, LimitKey, RATE_ROWS, RateKey, RateSpec};
use crate::listeners::{ListenerConfig, ListenerName};
use crate::moderation::OperatorConfig;
use crate::privacy::PrivacyConfig;
use crate::server::ServerConfig;
use crate::storage::StorageConfig;

/// A field whose change requires a restart (spec 4588-4592 and the per-table classes).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RestartOnlyField {
    /// `network.network_id`.
    NetworkId,
    /// `network.role`.
    NetworkRole,
    /// `network.coordinator_server_id`.
    CoordinatorServerId,
    /// `network.dns_name` or `network.dns_port`.
    DnsEndpoint,
    /// `network.onion_address`, `network.onion_port`, or the onion pin.
    OnionEndpoint,
    /// `server.server_id`.
    ServerId,
    /// `server.name`.
    ServerName,
    /// `server.data_dir`.
    DataDir,
    /// `server.runtime_dir`.
    RuntimeDir,
    /// `server.memory_budget_bytes`.
    MemoryBudget,
    /// `server.tokio_worker_threads` or `server.crypto_worker_threads`.
    WorkerThreads,
    /// `server.require_locked_secrets`.
    RequireLockedSecrets,
    /// A shutdown phase raised (only lowering is reloadable).
    ShutdownPhaseRaised,
    /// A listener added or removed by name.
    ListenerSet,
    /// A listener's `enabled`, `purpose`, or `bind`.
    ListenerTransport,
    /// A listener's private key file or client CA file.
    ListenerKeyMaterial,
    /// A listener's local admin policy.
    ListenerLocalAdmin,
    /// A listener ceiling raised.
    ListenerCeilingRaised,
    /// Any `[tls]` key.
    TlsPolicy,
    /// `federation.enabled`, CA, signing key, SOCKS endpoint, or fixed limits.
    FederationProfile,
    /// `federation.connect_timeout_seconds` raised.
    ConnectTimeoutRaised,
    /// A peer added or removed.
    PeerSet,
    /// A peer's identity, role, epoch, pin, or signing key.
    PeerIdentity,
    /// `storage.state_dir`.
    StateDir,
    /// Any storage key file path.
    StorageKeys,
    /// `storage.backup_dir`, backup key, or trust manifest.
    BackupProfile,
    /// `storage.disk_reserve_bytes` or `storage.disk_reserve_percent`.
    DiskReserve,
    /// `storage.database_max_bytes` raised (only lowering is reloadable).
    DatabaseCeilingRaised,
    /// `accounts.accept_clients`.
    AcceptClients,
    /// Invitation, access token, HPKE, or OPAQUE files and pins.
    AccountMaterial,
    /// A fixed account limit.
    AccountFixedLimit,
    /// `accounts.max_contacts` raised.
    MaxContactsRaised,
    /// `privacy.history_enabled`, WHOWAS, or the secret lookup floor.
    PrivacyPolicy,
    /// `privacy.log_retention_hours` raised.
    LogRetentionRaised,
    /// Audit signing key, trust manifest, retention, or reason ceiling.
    AuditProfile,
    /// Any `[e2ee]` key.
    E2eeProfile,
    /// An operator added or removed.
    OperatorSet,
    /// An operator's signing key, pin, or OS identity mappings.
    OperatorIdentity,
    /// A resource limit raised without the budget check being requested.
    LimitRaisedUnchecked,
}

/// One change the running daemon can apply at a single state revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReloadableChange {
    /// `network.display_name`.
    DisplayName,
    /// A shutdown phase lowered.
    ShutdownPhaseLowered,
    /// A resource limit lowered.
    LimitLowered {
        /// The limit.
        key: LimitKey,
        /// Old value.
        from: u64,
        /// New value.
        to: u64,
    },
    /// A resource limit raised; the runtime must pass the budget check first.
    LimitRaised {
        /// The limit.
        key: LimitKey,
        /// Old value.
        from: u64,
        /// New value.
        to: u64,
    },
    /// A rate changed; lowering clamps credit, raising creates none (spec 9162-9164).
    RateChanged {
        /// The rate.
        key: RateKey,
        /// Old value.
        from: RateSpec,
        /// New value.
        to: RateSpec,
    },
    /// A listener's origin allowlist or missing-origin policy.
    OriginPolicy {
        /// The listener.
        listener: ListenerName,
    },
    /// A listener's certificate chain; the runtime must confirm the key identity.
    CertificateChain {
        /// The listener.
        listener: ListenerName,
    },
    /// A listener ceiling lowered.
    ListenerCeilingLowered {
        /// The listener.
        listener: ListenerName,
        /// Old value.
        from: u64,
        /// New value.
        to: u64,
    },
    /// `accounts.registration`.
    RegistrationPolicy,
    /// `accounts.allow_guests`.
    AllowGuests,
    /// `accounts.default_public_presence`.
    DefaultPublicPresence,
    /// `accounts.default_allow_guest_dm`.
    DefaultAllowGuestDm,
    /// `accounts.default_direct_messages`.
    DefaultDirectMessages,
    /// `accounts.max_contacts` lowered.
    MaxContactsLowered,
    /// A peer's endpoints.
    PeerEndpoints {
        /// The peer.
        server_id: ServerId,
    },
    /// A peer enabled or disabled.
    PeerEnabled {
        /// The peer.
        server_id: ServerId,
        /// New state.
        enabled: bool,
    },
    /// `federation.connect_timeout_seconds` lowered.
    ConnectTimeoutLowered,
    /// `privacy.log_retention_hours` lowered.
    LogRetentionLowered,
    /// `privacy.motd_file`.
    MotdFile,
    /// `privacy.public_info_file`.
    PublicInfoFile,
    /// `privacy.history_default`.
    HistoryDefault,
    /// `storage.database_max_bytes`; the runtime checks the current counter.
    DatabaseCeiling {
        /// Old value.
        from: u64,
        /// New value.
        to: u64,
    },
    /// `storage.backup_max_bytes`; the runtime checks the current counter.
    BackupCeiling {
        /// Old value.
        from: u64,
        /// New value.
        to: u64,
    },
    /// `storage.integrity_checkpoint_manifests`.
    IntegrityCheckpointTarget,
    /// `moderation.session_sanction_hours` or `moderation.account_sanction_days`.
    SanctionWindows,
    /// An operator enabled or disabled; disabling terminates its sessions.
    OperatorEnabled {
        /// The operator.
        operator_id: OperatorId,
        /// New state.
        enabled: bool,
    },
    /// An operator's permission set.
    OperatorPermissions {
        /// The operator.
        operator_id: OperatorId,
    },
    /// An operator's display label.
    OperatorLabel {
        /// The operator.
        operator_id: OperatorId,
    },
}

/// The typed difference between the active and candidate configurations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfigDiff {
    /// Changes the runtime may apply.
    pub reloadable: Vec<ReloadableChange>,
    /// Fields whose change requires a restart.
    pub restart_only: Vec<RestartOnlyField>,
}

impl ConfigDiff {
    /// Computes the diff between the active configuration and a validated candidate.
    #[must_use]
    pub fn compute(active: &Config, candidate: &Config) -> Self {
        let mut diff = Self::default();
        diff.network(active, candidate);
        diff.server(&active.server, &candidate.server);
        diff.listeners(&active.listeners, &candidate.listeners);
        diff.push_restart(active.tls != candidate.tls, RestartOnlyField::TlsPolicy);
        diff.federation(&active.federation, &candidate.federation);
        diff.storage(&active.storage, &candidate.storage);
        diff.accounts(&active.accounts, &candidate.accounts);
        diff.limits(active, candidate);
        diff.privacy(&active.privacy, &candidate.privacy);
        diff.moderation(active, candidate);
        diff.push_restart(active.e2ee != candidate.e2ee, RestartOnlyField::E2eeProfile);
        diff
    }

    /// Returns whether nothing changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.reloadable.is_empty() && self.restart_only.is_empty()
    }

    fn push_restart(&mut self, changed: bool, field: RestartOnlyField) {
        if changed && !self.restart_only.contains(&field) {
            self.restart_only.push(field);
        }
    }

    fn push_change(&mut self, changed: bool, change: ReloadableChange) {
        if changed {
            self.reloadable.push(change);
        }
    }

    fn network(&mut self, active: &Config, candidate: &Config) {
        let (a, c) = (&active.network, &candidate.network);
        self.push_change(
            a.display_name != c.display_name,
            ReloadableChange::DisplayName,
        );
        self.push_restart(a.network_id != c.network_id, RestartOnlyField::NetworkId);
        self.push_restart(a.role != c.role, RestartOnlyField::NetworkRole);
        self.push_restart(
            a.coordinator_server_id != c.coordinator_server_id,
            RestartOnlyField::CoordinatorServerId,
        );
        self.push_restart(a.dns != c.dns, RestartOnlyField::DnsEndpoint);
        self.push_restart(a.onion != c.onion, RestartOnlyField::OnionEndpoint);
    }

    fn server(&mut self, a: &ServerConfig, c: &ServerConfig) {
        self.push_restart(a.server_id != c.server_id, RestartOnlyField::ServerId);
        self.push_restart(a.name != c.name, RestartOnlyField::ServerName);
        self.push_restart(a.data_dir != c.data_dir, RestartOnlyField::DataDir);
        self.push_restart(a.runtime_dir != c.runtime_dir, RestartOnlyField::RuntimeDir);
        self.push_restart(
            a.memory_budget_bytes != c.memory_budget_bytes,
            RestartOnlyField::MemoryBudget,
        );
        self.push_restart(
            a.tokio_worker_threads != c.tokio_worker_threads
                || a.crypto_worker_threads != c.crypto_worker_threads,
            RestartOnlyField::WorkerThreads,
        );
        self.push_restart(
            a.require_locked_secrets != c.require_locked_secrets,
            RestartOnlyField::RequireLockedSecrets,
        );
        let phases = [
            (a.shutdown.quiesce_seconds, c.shutdown.quiesce_seconds),
            (a.shutdown.drain_seconds, c.shutdown.drain_seconds),
            (a.shutdown.flush_seconds, c.shutdown.flush_seconds),
            (a.shutdown.stop_seconds, c.shutdown.stop_seconds),
        ];
        for (from, to) in phases {
            self.push_change(to < from, ReloadableChange::ShutdownPhaseLowered);
            self.push_restart(to > from, RestartOnlyField::ShutdownPhaseRaised);
        }
    }

    fn listeners(&mut self, active: &[ListenerConfig], candidate: &[ListenerConfig]) {
        let names_match = active.len() == candidate.len()
            && active
                .iter()
                .all(|a| candidate.iter().any(|c| c.name == a.name));
        self.push_restart(!names_match, RestartOnlyField::ListenerSet);
        for a in active {
            let Some(c) = candidate.iter().find(|c| c.name == a.name) else {
                continue;
            };
            self.listener(a, c);
        }
    }

    fn listener(&mut self, a: &ListenerConfig, c: &ListenerConfig) {
        self.push_restart(
            a.enabled != c.enabled || a.purpose != c.purpose || a.bind != c.bind,
            RestartOnlyField::ListenerTransport,
        );
        let key_changed = match (&a.tls, &c.tls) {
            (Some(at), Some(ct)) => at.private_key_file != ct.private_key_file,
            (None, None) => false,
            _ => true,
        };
        self.push_restart(
            key_changed || a.client_ca_file != c.client_ca_file,
            RestartOnlyField::ListenerKeyMaterial,
        );
        let chain_changed = match (&a.tls, &c.tls) {
            (Some(at), Some(ct)) => at.certificate_file != ct.certificate_file,
            _ => false,
        };
        self.push_change(
            chain_changed,
            ReloadableChange::CertificateChain {
                listener: c.name.clone(),
            },
        );
        self.push_change(
            a.wss != c.wss,
            ReloadableChange::OriginPolicy {
                listener: c.name.clone(),
            },
        );
        self.push_restart(
            a.local_admin != c.local_admin,
            RestartOnlyField::ListenerLocalAdmin,
        );
        self.push_change(
            c.max_connections < a.max_connections,
            ReloadableChange::ListenerCeilingLowered {
                listener: c.name.clone(),
                from: a.max_connections,
                to: c.max_connections,
            },
        );
        self.push_restart(
            c.max_connections > a.max_connections,
            RestartOnlyField::ListenerCeilingRaised,
        );
    }

    fn federation(&mut self, a: &FederationConfig, c: &FederationConfig) {
        let profile_changed = a.enabled != c.enabled
            || a.private_ca_file != c.private_ca_file
            || a.signing_private_key_file != c.signing_private_key_file
            || a.tor_socks_endpoint != c.tor_socks_endpoint
            || a.reconnect_max_seconds != c.reconnect_max_seconds
            || a.max_peers != c.max_peers;
        self.push_restart(profile_changed, RestartOnlyField::FederationProfile);
        self.push_change(
            c.connect_timeout_seconds < a.connect_timeout_seconds,
            ReloadableChange::ConnectTimeoutLowered,
        );
        self.push_restart(
            c.connect_timeout_seconds > a.connect_timeout_seconds,
            RestartOnlyField::ConnectTimeoutRaised,
        );
        let ids_match = a.peers.len() == c.peers.len()
            && a.peers
                .iter()
                .all(|ap| c.peers.iter().any(|cp| cp.server_id == ap.server_id));
        self.push_restart(!ids_match, RestartOnlyField::PeerSet);
        for ap in &a.peers {
            if let Some(cp) = c.peers.iter().find(|cp| cp.server_id == ap.server_id) {
                self.peer(ap, cp);
            }
        }
    }

    fn peer(&mut self, a: &PeerConfig, c: &PeerConfig) {
        let identity_changed = a.server_name != c.server_name
            || a.role != c.role
            || a.recovery_epoch != c.recovery_epoch
            || a.certificate_spki_sha256 != c.certificate_spki_sha256
            || a.signing_public_key != c.signing_public_key;
        self.push_restart(identity_changed, RestartOnlyField::PeerIdentity);
        self.push_change(
            a.endpoints != c.endpoints,
            ReloadableChange::PeerEndpoints {
                server_id: c.server_id,
            },
        );
        self.push_change(
            a.enabled != c.enabled,
            ReloadableChange::PeerEnabled {
                server_id: c.server_id,
                enabled: c.enabled,
            },
        );
    }

    fn storage(&mut self, a: &StorageConfig, c: &StorageConfig) {
        self.push_restart(a.state_dir != c.state_dir, RestartOnlyField::StateDir);
        let keys_changed = a.master_key_file != c.master_key_file
            || a.rollback_guard_key_file != c.rollback_guard_key_file
            || a.login_index_key_file != c.login_index_key_file
            || a.login_index_previous_key_file != c.login_index_previous_key_file;
        self.push_restart(keys_changed, RestartOnlyField::StorageKeys);
        let backup_changed = a.backup_dir != c.backup_dir
            || a.backup_signing_private_key_file != c.backup_signing_private_key_file
            || a.backup_trust_manifest_file != c.backup_trust_manifest_file;
        self.push_restart(backup_changed, RestartOnlyField::BackupProfile);
        self.push_restart(
            a.disk_reserve_bytes != c.disk_reserve_bytes
                || a.disk_reserve_percent != c.disk_reserve_percent,
            RestartOnlyField::DiskReserve,
        );
        self.push_restart(
            c.database_max_bytes > a.database_max_bytes,
            RestartOnlyField::DatabaseCeilingRaised,
        );
        self.push_change(
            c.database_max_bytes < a.database_max_bytes,
            ReloadableChange::DatabaseCeiling {
                from: a.database_max_bytes,
                to: c.database_max_bytes,
            },
        );
        self.push_change(
            a.backup_max_bytes != c.backup_max_bytes,
            ReloadableChange::BackupCeiling {
                from: a.backup_max_bytes,
                to: c.backup_max_bytes,
            },
        );
        self.push_change(
            a.integrity_checkpoint_manifests != c.integrity_checkpoint_manifests,
            ReloadableChange::IntegrityCheckpointTarget,
        );
    }

    fn accounts(&mut self, a: &AccountsConfig, c: &AccountsConfig) {
        self.push_restart(
            a.accept_clients != c.accept_clients,
            RestartOnlyField::AcceptClients,
        );
        let material_changed = a.invite_verification_key_file != c.invite_verification_key_file
            || a.access_token_key_file != c.access_token_key_file
            || a.account_service_hpke_public_key != c.account_service_hpke_public_key
            || a.account_service_hpke_private_key_file != c.account_service_hpke_private_key_file
            || a.opaque_server_setup_file != c.opaque_server_setup_file
            || a.opaque_fake_credential_key_file != c.opaque_fake_credential_key_file;
        self.push_restart(material_changed, RestartOnlyField::AccountMaterial);
        let fixed_changed = a.max_reserved_nicknames != c.max_reserved_nicknames
            || a.auth_transaction_seconds != c.auth_transaction_seconds
            || a.create_transaction_seconds != c.create_transaction_seconds
            || a.credential_change_transaction_seconds != c.credential_change_transaction_seconds;
        self.push_restart(fixed_changed, RestartOnlyField::AccountFixedLimit);
        self.push_change(
            a.registration != c.registration,
            ReloadableChange::RegistrationPolicy,
        );
        self.push_change(
            a.allow_guests != c.allow_guests,
            ReloadableChange::AllowGuests,
        );
        self.push_change(
            a.default_public_presence != c.default_public_presence,
            ReloadableChange::DefaultPublicPresence,
        );
        self.push_change(
            a.default_allow_guest_dm != c.default_allow_guest_dm,
            ReloadableChange::DefaultAllowGuestDm,
        );
        self.push_change(
            a.default_direct_messages != c.default_direct_messages,
            ReloadableChange::DefaultDirectMessages,
        );
        self.push_change(
            c.max_contacts < a.max_contacts,
            ReloadableChange::MaxContactsLowered,
        );
        self.push_restart(
            c.max_contacts > a.max_contacts,
            RestartOnlyField::MaxContactsRaised,
        );
    }

    fn limits(&mut self, active: &Config, candidate: &Config) {
        for row in &LIMIT_ROWS {
            let from = active.limits.values.get(row.key);
            let to = candidate.limits.values.get(row.key);
            let change = match to.cmp(&from) {
                std::cmp::Ordering::Less => ReloadableChange::LimitLowered {
                    key: row.key,
                    from,
                    to,
                },
                std::cmp::Ordering::Greater => ReloadableChange::LimitRaised {
                    key: row.key,
                    from,
                    to,
                },
                std::cmp::Ordering::Equal => continue,
            };
            self.reloadable.push(change);
        }
        for row in &RATE_ROWS {
            let from = active.limits.rates.get(row.key);
            let to = candidate.limits.rates.get(row.key);
            self.push_change(
                from != to,
                ReloadableChange::RateChanged {
                    key: row.key,
                    from,
                    to,
                },
            );
        }
    }

    fn privacy(&mut self, a: &PrivacyConfig, c: &PrivacyConfig) {
        let policy_changed = a.history_enabled != c.history_enabled
            || a.secret_lookup_floor_milliseconds != c.secret_lookup_floor_milliseconds
            || a.whowas_retention_seconds != c.whowas_retention_seconds
            || a.whowas_records != c.whowas_records;
        self.push_restart(policy_changed, RestartOnlyField::PrivacyPolicy);
        self.push_change(
            c.log_retention_hours < a.log_retention_hours,
            ReloadableChange::LogRetentionLowered,
        );
        self.push_restart(
            c.log_retention_hours > a.log_retention_hours,
            RestartOnlyField::LogRetentionRaised,
        );
        self.push_change(a.motd_file != c.motd_file, ReloadableChange::MotdFile);
        self.push_change(
            a.public_info_file != c.public_info_file,
            ReloadableChange::PublicInfoFile,
        );
        self.push_change(
            a.history_default != c.history_default,
            ReloadableChange::HistoryDefault,
        );
    }

    fn moderation(&mut self, active: &Config, candidate: &Config) {
        let (a, c) = (&active.moderation, &candidate.moderation);
        let audit_changed = a.audit_signing_private_key_file != c.audit_signing_private_key_file
            || a.audit_trust_manifest_file != c.audit_trust_manifest_file
            || a.audit_retention_days != c.audit_retention_days
            || a.free_reason_bytes != c.free_reason_bytes;
        self.push_restart(audit_changed, RestartOnlyField::AuditProfile);
        self.push_change(
            a.session_sanction_hours != c.session_sanction_hours
                || a.account_sanction_days != c.account_sanction_days,
            ReloadableChange::SanctionWindows,
        );
        let ids_match = a.operators.len() == c.operators.len()
            && a.operators.iter().all(|ao| {
                c.operators
                    .iter()
                    .any(|co| co.operator_id == ao.operator_id)
            });
        self.push_restart(!ids_match, RestartOnlyField::OperatorSet);
        for ao in &a.operators {
            if let Some(co) = c
                .operators
                .iter()
                .find(|co| co.operator_id == ao.operator_id)
            {
                self.operator(ao, co);
            }
        }
    }

    fn operator(&mut self, a: &OperatorConfig, c: &OperatorConfig) {
        let identity_changed = a.signing_public_key != c.signing_public_key
            || a.certificate_spki_sha256 != c.certificate_spki_sha256
            || a.local_uids != c.local_uids
            || a.local_gids != c.local_gids;
        self.push_restart(identity_changed, RestartOnlyField::OperatorIdentity);
        self.push_change(
            a.enabled != c.enabled,
            ReloadableChange::OperatorEnabled {
                operator_id: c.operator_id,
                enabled: c.enabled,
            },
        );
        self.push_change(
            a.permissions != c.permissions,
            ReloadableChange::OperatorPermissions {
                operator_id: c.operator_id,
            },
        );
        self.push_change(
            a.display_label != c.display_label,
            ReloadableChange::OperatorLabel {
                operator_id: c.operator_id,
            },
        );
    }
}

/// Why a candidate cannot be applied by reload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReloadRejected {
    /// At least one restart-only field changed.
    RestartOnly(Vec<RestartOnlyField>),
}

/// The ordered set of reloadable changes the runtime applies at one revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadPlan {
    changes: Vec<ReloadableChange>,
}

impl ReloadPlan {
    /// Borrows the changes in diff order.
    #[must_use]
    pub fn changes(&self) -> &[ReloadableChange] {
        &self.changes
    }

    /// Returns whether the plan raises any resource limit and therefore needs the
    /// Section 19 budget and working-set check before activation (spec 9120-9123).
    #[must_use]
    pub fn requires_budget_check(&self) -> bool {
        self.changes
            .iter()
            .any(|change| matches!(change, ReloadableChange::LimitRaised { .. }))
    }
}

impl TryFrom<ConfigDiff> for ReloadPlan {
    type Error = ReloadRejected;

    fn try_from(diff: ConfigDiff) -> Result<Self, Self::Error> {
        if !diff.restart_only.is_empty() {
            return Err(ReloadRejected::RestartOnly(diff.restart_only));
        }
        Ok(Self {
            changes: diff.reloadable,
        })
    }
}
