//! Cross-table validation stages 5 through 8 (spec C.8 9280-9282).

use std::collections::BTreeSet;
use std::path::Path;

use crate::bounds::{
    ADMIN_TLS_WORKING_SET_FLOOR, CLIENT_BASE_CHARGE, CLIENT_COMMAND_BYTES,
    CLIENT_PHYSICAL_LINE_BYTES, CLIENT_TLS_WORKING_SET_FLOOR, CLIENT_WSS_WORKING_SET_FLOOR,
    CRYPTO_WORKER_BYTES, FEDERATION_BASE_CHARGE, FEDERATION_FRAME_BYTES,
    FEDERATION_WORKING_SET_FLOOR, HEADROOM_FLOOR_BYTES, MAX_BURST_SECONDS_OF_RATE,
    MAX_FEDERATED_SERVER_NAME_BYTES, MAX_FEDERATION_OR_ADMIN_CONNECTIONS, MAX_PEER_ENDPOINTS,
    STORAGE_SLOT_BYTES, STORAGE_SLOTS, allocation_charge,
};
use crate::config::Config;
use crate::error::{ConfigError, IssueSink, SchemaKey, ValidationStage};
use crate::federation::PeerConfig;
use crate::limits::LimitKey;
use crate::listeners::{ListenerConfig, ListenerPurpose};
use crate::network::NodeRole;
use crate::paths::{index_u16, is_within};
use crate::scalar::PeerEndpoint;

/// Runs stages 5 through 8 in order, accumulating every issue.
pub(crate) fn validate(config: &Config, sink: &mut IssueSink) {
    identity(config, sink);
    listener_union(config, sink);
    topology(config, sink);
    resources(config, sink);
}

fn issue(sink: &mut IssueSink, stage: ValidationStage, table: &'static str, field: &'static str) {
    sink.push(stage, SchemaKey::new(table, field), ConfigError::Topology);
}

/// Stage 5: local identity consistency (spec 8893-8901, 8913-8918, 9022-9026, 9040, 9198).
fn identity(config: &Config, sink: &mut IssueSink) {
    let stage = ValidationStage::LocalIdentity;
    let local_is_coordinator = config.network.coordinator_server_id == config.server.server_id;
    let coordinator_role = config.network.role == NodeRole::Coordinator;
    if local_is_coordinator != coordinator_role {
        issue(sink, stage, "network", "coordinator_server_id");
    }
    if config.e2ee.enabled
        && config.e2ee.coordinator_server_id != Some(config.network.coordinator_server_id)
    {
        issue(sink, stage, "e2ee", "coordinator_server_id");
    }
    if config.federation.enabled
        && config.server.name.as_str().len() > MAX_FEDERATED_SERVER_NAME_BYTES
    {
        issue(sink, stage, "server", "name");
    }
    onboarding_listeners(config, sink);
    coordinator_material(config, sink);
    directory_layout(config, sink);
}

/// At least one enabled client listener must correspond to the onboarding endpoints
/// unless the node is an edge with `accept_clients = false` (spec 8916-8918).
fn onboarding_listeners(config: &Config, sink: &mut IssueSink) {
    if config.network.role == NodeRole::Edge && !config.accounts.accept_clients {
        return;
    }
    let any_client = ListenerPurpose::ALL
        .iter()
        .any(|purpose| purpose.is_client() && listener_enabled(config, *purpose));
    if !any_client {
        issue(
            sink,
            ValidationStage::LocalIdentity,
            "listeners",
            "endpoint",
        );
    }
    onboarding_endpoints(config, sink);
}

fn listener_enabled(config: &Config, purpose: ListenerPurpose) -> bool {
    config
        .listeners
        .iter()
        .any(|listener| listener.enabled && listener.purpose == purpose)
}

/// Each configured onboarding endpoint needs a matching enabled listener.
fn onboarding_endpoints(config: &Config, sink: &mut IssueSink) {
    let stage = ValidationStage::LocalIdentity;
    let dns_served = listener_enabled(config, ListenerPurpose::ClientTls)
        || listener_enabled(config, ListenerPurpose::ClientWss);
    if config.network.dns.is_none() && config.network.onion.is_none() {
        issue(sink, stage, "network", "dns_name");
    }
    if config.network.dns.is_some() && !dns_served {
        issue(sink, stage, "network", "dns_name");
    }
    if config.network.onion.is_some() && !listener_enabled(config, ListenerPurpose::ClientOnion) {
        issue(sink, stage, "network", "onion_address");
    }
}

/// Coordinator-only secrets are required there and forbidden on edges (spec 9028-9031,
/// 9066-9069, 9199); invite registration needs its verification key (spec 9024).
fn coordinator_material(config: &Config, sink: &mut IssueSink) {
    let stage = ValidationStage::LocalIdentity;
    let coordinator = config.network.role == NodeRole::Coordinator;
    let accounts = &config.accounts;
    let material = [
        (
            "account_service_hpke_private_key_file",
            accounts.account_service_hpke_private_key_file.is_some(),
        ),
        (
            "opaque_server_setup_file",
            accounts.opaque_server_setup_file.is_some(),
        ),
        (
            "opaque_fake_credential_key_file",
            accounts.opaque_fake_credential_key_file.is_some(),
        ),
    ];
    for (field, present) in material {
        if present != coordinator {
            issue(sink, stage, "accounts", field);
        }
    }
    if accounts.registration == crate::accounts::RegistrationPolicy::Invite
        && accounts.invite_verification_key_file.is_none()
    {
        issue(sink, stage, "accounts", "invite_verification_key_file");
    }
    let e2ee_coordinator =
        config.e2ee.enabled && config.e2ee.coordinator_server_id == Some(config.server.server_id);
    if config.e2ee.sequencer_private_key_file.is_some() != e2ee_coordinator {
        issue(sink, stage, "e2ee", "sequencer_private_key_file");
    }
}

/// State, data, runtime, and backup directories are distinct and nested as required
/// (spec 9009, 9040-9042, 9013).
fn directory_layout(config: &Config, sink: &mut IssueSink) {
    let stage = ValidationStage::LocalIdentity;
    let data = config.server.data_dir.as_path();
    let runtime = config.server.runtime_dir.as_path();
    let state = config.storage.state_dir.as_path();
    let backup = config.storage.backup_dir.as_path();
    let state_ok = is_within(state, data)
        && state != data
        && !overlaps(state, runtime)
        && !overlaps(state, backup);
    if !state_ok {
        issue(sink, stage, "storage", "state_dir");
    }
    if overlaps(backup, runtime) || backup == data {
        issue(sink, stage, "storage", "backup_dir");
    }
    if runtime == data {
        issue(sink, stage, "server", "runtime_dir");
    }
    secret_locations(config, sink);
}

/// Secret files live outside the state, backup, and runtime directories (spec 4330).
fn secret_locations(config: &Config, sink: &mut IssueSink) {
    let roots = [
        config.storage.state_dir.as_path(),
        config.storage.backup_dir.as_path(),
        config.server.runtime_dir.as_path(),
    ];
    for (key, path) in config.secret_paths() {
        if roots.iter().any(|root| is_within(&path, root)) {
            sink.push(ValidationStage::LocalIdentity, key, ConfigError::Topology);
        }
    }
}

fn overlaps(left: &Path, right: &Path) -> bool {
    is_within(left, right) || is_within(right, left)
}

/// Stage 6: listener union constraints (spec 8920-8961).
fn listener_union(config: &Config, sink: &mut IssueSink) {
    let stage = ValidationStage::ListenerUnion;
    let mut names = BTreeSet::new();
    let mut binds = BTreeSet::new();
    for (index, listener) in config.listeners.iter().enumerate() {
        let key = |field| SchemaKey::indexed("listeners.endpoint", index_u16(index), field);
        if !names.insert(listener.name.as_str().to_owned()) {
            sink.push(stage, key("name"), ConfigError::Topology);
        }
        if !binds.insert(format!("{:?}", listener.bind)) {
            sink.push(stage, key("bind"), ConfigError::Topology);
        }
        if let Err(error) = max_connections_bound(config, listener) {
            sink.push(stage, key("max_connections"), error);
        }
        if listener.enabled && listener.purpose == ListenerPurpose::ClientWss {
            sink.push(stage, key("enabled"), ConfigError::DeferredTransport);
        }
        if let Some(wss) = &listener.wss
            && wss.allowed_origins.is_empty()
            && !wss.allow_missing_origin
        {
            sink.push(stage, key("allowed_origins"), ConfigError::InvalidValue);
        }
    }
    ocsp_staple_policy(config, sink);
    listener_key_reuse(config, sink);
    listener_counts(config, sink);
}

/// Required public-DNS stapling is backed by one prepared response per
/// configured public TLS certificate.
fn ocsp_staple_policy(config: &Config, sink: &mut IssueSink) {
    if !config.tls.require_ocsp_staple {
        return;
    }
    for (index, listener) in config.listeners.iter().enumerate() {
        if listener.purpose == ListenerPurpose::ClientTls
            && listener
                .tls
                .as_ref()
                .is_none_or(|tls| tls.ocsp_staple_file.is_none())
        {
            sink.push(
                ValidationStage::ListenerUnion,
                SchemaKey::indexed(
                    "listeners.endpoint",
                    index_u16(index),
                    "tls_ocsp_staple_file",
                ),
                ConfigError::MissingValue,
            );
        }
    }
}

/// Purpose-specific `max_connections` ceilings (spec 8940-8943).
fn max_connections_bound(config: &Config, listener: &ListenerConfig) -> Result<(), ConfigError> {
    let ceiling = match listener.purpose {
        purpose if purpose.is_client() => config.limits.values.get(LimitKey::ClientConnections),
        ListenerPurpose::Federation => {
            MAX_FEDERATION_OR_ADMIN_CONNECTIONS.min(config.federation.max_peers)
        }
        _ => MAX_FEDERATION_OR_ADMIN_CONNECTIONS,
    };
    if listener.max_connections > ceiling {
        return Err(ConfigError::InvalidValue);
    }
    Ok(())
}

/// A key, certificate, or CA path cannot be reused across the client, federation,
/// and admin classes (spec 8954, 505-507).
fn listener_key_reuse(config: &Config, sink: &mut IssueSink) {
    let stage = ValidationStage::ListenerUnion;
    let mut seen: Vec<(u8, &Path, &'static str)> = Vec::new();
    for (index, listener) in config.listeners.iter().enumerate() {
        let class = listener.purpose.key_class();
        let mut files: Vec<(&Path, &'static str)> = Vec::new();
        if let Some(tls) = &listener.tls {
            files.push((tls.private_key_file.as_path(), "tls_private_key_file"));
            files.push((tls.certificate_file.as_path(), "tls_certificate_file"));
        }
        if let Some(ca) = &listener.client_ca_file {
            files.push((ca.as_path(), "client_ca_file"));
        }
        for (path, field) in files {
            let clash = seen
                .iter()
                .any(|(other_class, other, _)| *other == path && *other_class != class);
            if clash {
                let key = SchemaKey::indexed("listeners.endpoint", index_u16(index), field);
                sink.push(stage, key, ConfigError::Topology);
            }
            seen.push((class, path, field));
        }
    }
}

/// Federation listener count by role and at most one listener per admin purpose
/// (spec 8957-8960).
fn listener_counts(config: &Config, sink: &mut IssueSink) {
    let stage = ValidationStage::ListenerUnion;
    let count = |purpose: ListenerPurpose| {
        config
            .listeners
            .iter()
            .filter(|listener| listener.enabled && listener.purpose == purpose)
            .count()
    };
    let total = |purpose: ListenerPurpose| {
        config
            .listeners
            .iter()
            .filter(|listener| listener.purpose == purpose)
            .count()
    };
    let expected_federation =
        usize::from(config.federation.enabled && config.network.role == NodeRole::Coordinator);
    if count(ListenerPurpose::Federation) != expected_federation {
        issue(sink, stage, "listeners", "endpoint");
    }
    if total(ListenerPurpose::AdminLocal) > 1 || total(ListenerPurpose::AdminTls) > 1 {
        issue(sink, stage, "listeners", "endpoint");
    }
}

/// Stage 7: role and peer topology plus operator uniqueness (spec 8973-9004, 9258-9276).
fn topology(config: &Config, sink: &mut IssueSink) {
    federation_material(config, sink);
    peer_records(config, sink);
    operator_records(config, sink);
}

fn federation_material(config: &Config, sink: &mut IssueSink) {
    let stage = ValidationStage::Topology;
    let federation = &config.federation;
    if federation.enabled && federation.private_ca_file.is_none() {
        sink.push(
            stage,
            SchemaKey::new("federation", "private_ca_file"),
            ConfigError::MissingValue,
        );
    }
    if federation.enabled && federation.signing_private_key_file.is_none() {
        sink.push(
            stage,
            SchemaKey::new("federation", "signing_private_key_file"),
            ConfigError::MissingValue,
        );
    }
    let onion_dial = federation.peers.iter().any(|peer| {
        peer.endpoints
            .iter()
            .any(|endpoint| matches!(endpoint, PeerEndpoint::Onion { .. }))
    });
    if onion_dial && federation.tor_socks_endpoint.is_none() {
        sink.push(
            stage,
            SchemaKey::new("federation", "tor_socks_endpoint"),
            ConfigError::MissingValue,
        );
    }
    if !federation.enabled && !federation.peers.is_empty() {
        issue(sink, stage, "federation", "peer");
    }
}

fn peer_records(config: &Config, sink: &mut IssueSink) {
    let stage = ValidationStage::Topology;
    let peers = &config.federation.peers;
    let edge = config.network.role == NodeRole::Edge;
    if config.federation.enabled && edge && peers.len() != 1 {
        issue(sink, stage, "federation", "peer");
    }
    let mut sets = PeerSets::default();
    for (index, peer) in peers.iter().enumerate() {
        peer_uniqueness(config, peer, index_u16(index), &mut sets, sink);
        peer_role(config, peer, index_u16(index), sink);
    }
}

/// Identities, names, pins, keys, and endpoints seen across peer records.
#[derive(Default)]
struct PeerSets {
    ids: BTreeSet<[u8; 16]>,
    names: BTreeSet<String>,
    pins: BTreeSet<[u8; 32]>,
    keys: BTreeSet<[u8; 32]>,
    endpoints: BTreeSet<PeerEndpoint>,
}

/// Peer identities are unique, distinct from the local node, and never reuse a
/// certificate pin as a signing key (spec 8988-8991, 9003-9004).
fn peer_uniqueness(
    config: &Config,
    peer: &PeerConfig,
    index: u16,
    sets: &mut PeerSets,
    sink: &mut IssueSink,
) {
    let stage = ValidationStage::Topology;
    let key = |field| SchemaKey::indexed("federation.peer", index, field);
    if !sets.ids.insert(*peer.server_id.as_bytes()) || peer.server_id == config.server.server_id {
        sink.push(stage, key("server_id"), ConfigError::Topology);
    }
    if !sets.names.insert(peer.server_name.as_str().to_owned())
        || peer.server_name == config.server.name
    {
        sink.push(stage, key("server_name"), ConfigError::Topology);
    }
    if !sets.pins.insert(peer.certificate_spki_sha256) {
        sink.push(stage, key("certificate_spki_sha256"), ConfigError::Topology);
    }
    if !sets.keys.insert(peer.signing_public_key)
        || peer.signing_public_key == peer.certificate_spki_sha256
    {
        sink.push(stage, key("signing_public_key"), ConfigError::Topology);
    }
    if peer
        .endpoints
        .iter()
        .any(|endpoint| !sets.endpoints.insert(endpoint.clone()))
    {
        sink.push(stage, key("endpoints"), ConfigError::Topology);
    }
}

/// The peer role is the inverse of the local role; an edge's coordinator record is
/// the network coordinator with 1..8 endpoints and a coordinator's edge records have
/// none (spec 8990, 8993, 8999-9000).
fn peer_role(config: &Config, peer: &PeerConfig, index: u16, sink: &mut IssueSink) {
    let stage = ValidationStage::Topology;
    let key = |field| SchemaKey::indexed("federation.peer", index, field);
    match config.network.role {
        NodeRole::Coordinator => {
            if peer.role != NodeRole::Edge {
                sink.push(stage, key("role"), ConfigError::Topology);
            }
            if !peer.endpoints.is_empty() {
                sink.push(stage, key("endpoints"), ConfigError::Topology);
            }
        }
        NodeRole::Edge => {
            if peer.role != NodeRole::Coordinator
                || peer.server_id != config.network.coordinator_server_id
            {
                sink.push(stage, key("role"), ConfigError::Topology);
            }
            if peer.endpoints.is_empty() || peer.endpoints.len() > MAX_PEER_ENDPOINTS {
                sink.push(stage, key("endpoints"), ConfigError::Topology);
            }
        }
    }
}

// agenc-review: focus owner=config reviewed=2026-08-30 reason=single bounded operator pass cross-checks every unique identity and local-or-remote admission authority without accepting a partial record
fn operator_records(config: &Config, sink: &mut IssueSink) {
    let stage = ValidationStage::Topology;
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut pins = BTreeSet::new();
    let mut uids = BTreeSet::new();
    let mut gids = BTreeSet::new();
    let (allowed_uids, allowed_gids, has_local) = local_admin_identity_policy(config);
    for (index, operator) in config.moderation.operators.iter().enumerate() {
        let key = |field| SchemaKey::indexed("moderation.operator", index_u16(index), field);
        if !ids.insert(*operator.operator_id.as_bytes()) {
            sink.push(stage, key("operator_id"), ConfigError::Topology);
        }
        if !keys.insert(operator.signing_public_key) {
            sink.push(stage, key("signing_public_key"), ConfigError::Topology);
        }
        if operator
            .certificate_spki_sha256
            .is_some_and(|pin| !pins.insert(pin))
        {
            sink.push(stage, key("certificate_spki_sha256"), ConfigError::Topology);
        }
        if operator.local_uids.iter().any(|uid| !uids.insert(*uid)) {
            sink.push(stage, key("local_uids"), ConfigError::Topology);
        }
        if operator.local_gids.iter().any(|gid| !gids.insert(*gid)) {
            sink.push(stage, key("local_gids"), ConfigError::Topology);
        }
        if has_local
            && operator
                .local_uids
                .iter()
                .any(|uid| !allowed_uids.contains(uid))
        {
            sink.push(stage, key("local_uids"), ConfigError::Topology);
        }
        if has_local
            && operator
                .local_gids
                .iter()
                .any(|gid| !allowed_gids.contains(gid))
        {
            sink.push(stage, key("local_gids"), ConfigError::Topology);
        }
    }
    remote_admin_operator(config, sink);
}

fn local_admin_identity_policy(config: &Config) -> (BTreeSet<u32>, BTreeSet<u32>, bool) {
    let policies: Vec<_> = config
        .listeners
        .iter()
        .filter_map(|listener| listener.local_admin.as_ref())
        .collect();
    let allowed_uids = policies
        .iter()
        .flat_map(|policy| policy.allowed_uids.iter().copied())
        .collect();
    let allowed_gids = policies
        .iter()
        .flat_map(|policy| policy.allowed_gids.iter().copied())
        .collect();
    let has_local = config
        .listeners
        .iter()
        .any(|listener| listener.purpose == ListenerPurpose::AdminLocal);
    (allowed_uids, allowed_gids, has_local)
}

/// An enabled remote admin listener needs at least one enabled operator with a pin
/// (spec 9265, 9274-9275).
fn remote_admin_operator(config: &Config, sink: &mut IssueSink) {
    let remote = config
        .listeners
        .iter()
        .any(|listener| listener.enabled && listener.purpose == ListenerPurpose::AdminTls);
    let pinned = config
        .moderation
        .operators
        .iter()
        .any(|operator| operator.enabled && operator.certificate_spki_sha256.is_some());
    if remote && !pinned {
        issue(sink, ValidationStage::Topology, "moderation", "operator");
    }
}

/// Stage 8: resource arithmetic (spec 8906, 9120-9132, 9235, 2762-2783).
fn resources(config: &Config, sink: &mut IssueSink) {
    let stage = ValidationStage::ResourceArithmetic;
    let values = &config.limits.values;
    let get = |key| values.get(key);
    let mut check = |ok: bool, table: &'static str, field: &'static str| {
        if !ok {
            sink.push(
                stage,
                SchemaKey::new(table, field),
                ConfigError::InvalidValue,
            );
        }
    };
    let jobs = get(LimitKey::ChannelKeyJobs).saturating_add(get(LimitKey::OpaqueJobs));
    check(
        config.server.crypto_worker_threads <= jobs,
        "server",
        "crypto_worker_threads",
    );
    let output = get(LimitKey::ClientOutputBytes);
    let control = get(LimitKey::ClientControlOutputBytes);
    check(
        output >= get(LimitKey::ResponseBatchBytes),
        "limits",
        "client_output_bytes",
    );
    check(control < output, "limits", "client_control_output_bytes");
    let invites_global = get(LimitKey::InvitesGlobal);
    check(
        get(LimitKey::InvitesPerChannel) <= invites_global,
        "limits",
        "invites_per_channel",
    );
    check(
        get(LimitKey::InvitesPerPrincipal) <= invites_global,
        "limits",
        "invites_per_principal",
    );
    check(
        get(LimitKey::QuerySnapshotRows) <= get(LimitKey::QuerySnapshotRowsGlobal),
        "limits",
        "query_snapshot_rows",
    );
    check(
        config.storage.database_max_bytes <= config.storage.backup_max_bytes,
        "storage",
        "database_max_bytes",
    );
    e2ee_burst(config, sink);
    memory_budget(config, sink);
}

fn e2ee_burst(config: &Config, sink: &mut IssueSink) {
    let rate = config.e2ee.federation_peer_bytes_per_second;
    let ceiling = rate.checked_mul(MAX_BURST_SECONDS_OF_RATE);
    let ok = ceiling.is_some_and(|ceiling| config.e2ee.federation_peer_burst_bytes <= ceiling);
    if !ok {
        sink.push(
            ValidationStage::ResourceArithmetic,
            SchemaKey::new("e2ee", "federation_peer_burst_bytes"),
            if ceiling.is_none() {
                ConfigError::Overflow
            } else {
                ConfigError::InvalidValue
            },
        );
    }
}

/// The Section 19.2 startup arithmetic and minimum working sets (spec 2762-2783).
fn memory_budget(config: &Config, sink: &mut IssueSink) {
    let stage = ValidationStage::ResourceArithmetic;
    let budget = config.server.memory_budget_bytes;
    let pool = match protocol_pool(budget, config.server.crypto_worker_threads) {
        Ok(pool) => pool,
        Err(error) => {
            sink.push(
                stage,
                SchemaKey::new("server", "memory_budget_bytes"),
                error,
            );
            return;
        }
    };
    let arena = config.limits.values.get(LimitKey::ParsedArenaBytes);
    let floor = config
        .enabled_purposes()
        .into_iter()
        .map(|purpose| working_set(purpose, arena))
        .try_fold(0_u64, |floor, set| set.map(|set| floor.max(set)));
    match floor {
        Some(floor) if floor <= pool => {}
        _ => sink.push(
            stage,
            SchemaKey::new("server", "memory_budget_bytes"),
            ConfigError::InvalidValue,
        ),
    }
    if config.limits.values.get(LimitKey::QuerySnapshotBytesGlobal) > pool {
        sink.push(
            stage,
            SchemaKey::new("limits", "query_snapshot_bytes_global"),
            ConfigError::InvalidValue,
        );
    }
}

/// Computes `P = B - H - D - C` with underflow rejected (spec 2762-2766).
pub fn protocol_pool(budget: u64, crypto_workers: u64) -> Result<u64, ConfigError> {
    let headroom = HEADROOM_FLOOR_BYTES.max(budget.div_ceil(8));
    let storage = STORAGE_SLOTS
        .checked_mul(STORAGE_SLOT_BYTES)
        .ok_or(ConfigError::Overflow)?;
    let crypto = crypto_workers
        .checked_mul(CRYPTO_WORKER_BYTES)
        .ok_or(ConfigError::Overflow)?;
    budget
        .checked_sub(headroom)
        .and_then(|rest| rest.checked_sub(storage))
        .and_then(|rest| rest.checked_sub(crypto))
        .ok_or(ConfigError::InvalidValue)
}

/// The minimum working set for one enabled purpose (spec 2777-2783).
pub fn working_set(purpose: ListenerPurpose, parsed_arena_bytes: u64) -> Option<u64> {
    let arena = allocation_charge(parsed_arena_bytes)?;
    let line = allocation_charge(CLIENT_PHYSICAL_LINE_BYTES)?;
    match purpose {
        ListenerPurpose::ClientTls | ListenerPurpose::ClientOnion => CLIENT_BASE_CHARGE
            .checked_add(CLIENT_TLS_WORKING_SET_FLOOR.max(arena.checked_add(line)?)),
        ListenerPurpose::ClientWss => {
            let command = allocation_charge(CLIENT_COMMAND_BYTES)?;
            CLIENT_BASE_CHARGE
                .checked_add(CLIENT_WSS_WORKING_SET_FLOOR.max(arena.checked_add(command)?))
        }
        ListenerPurpose::Federation => FEDERATION_BASE_CHARGE.checked_add(
            FEDERATION_WORKING_SET_FLOOR.max(allocation_charge(FEDERATION_FRAME_BYTES)?),
        ),
        ListenerPurpose::AdminLocal => CLIENT_BASE_CHARGE.checked_add(line),
        ListenerPurpose::AdminTls => {
            CLIENT_BASE_CHARGE.checked_add(ADMIN_TLS_WORKING_SET_FLOOR.max(line))
        }
    }
}
