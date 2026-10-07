#![forbid(unsafe_code)]

//! In-process handler tests: one companion coordinator with a sequencer
//! and one attached origin executes requests directly through the opcode
//! dispatcher, applying each committed effect by hand.

use std::error::Error;

use agenc_relay_crypto::SignatureDomain;
use agenc_relay_domain::e2ee::projection::{EmptyKind, EventKind, StoreKind};
use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::federation::frames::Correlation;
use agenc_relay_e2ee::ids::{account_id_digest, conversation_id, leaf_capabilities_digest};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::aad::ArcApplicationAad;
use agenc_relay_e2ee::objects::attach::{ArcDeviceAttach, ArcDeviceAttachChallenge};
use agenc_relay_e2ee::objects::conversation::{ArcConversationKind, ArcPolicy};
use agenc_relay_e2ee::objects::federation::{ArcFederationOpcode as Op, ArcFederationRequest};
use agenc_relay_e2ee::objects::identity::ArcCredentialBundle;
use agenc_relay_e2ee::route::channel_route_binding;
use agenc_relay_e2ee::sequencer::SequencerKeySet;
use agenc_relay_e2ee::tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::e2ee_records::ReplayRow;
use agenc_relay_types::{
    AccountId, AccountRandomId, ChannelInstanceId, EntropyError, EntropySource, ServerId,
};
use support::{
    BindingSpec, DeviceSpec, KeyPackageSpec, LeafSpec, NETWORK, PolicySpec, Principal,
    binding_package, capabilities, certificate, channel_route, default_capabilities,
    encoded_capabilities, key, key_package, leaf_authorization, policy, policy_id_of, principal,
    private_message_bytes, root_fingerprint, sequencer_credential, sign,
};

use super::ops::{self, Exec, Fail};
use super::request::{self, Classified, Outcome, ResultBody};
use super::{CompanionCoordinator, CompanionOrigin, CompanionOriginKey, CompleteRequest};

mod barrier;
mod binding_faults;
mod claims;
pub(crate) mod direct_release;
mod directory_faults;
mod live_payloads;
mod request_envelope;
mod sequence;
pub(crate) mod support;
pub(crate) mod sync;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const HOME: [u8; 16] = [2; 16];
const COORDINATOR: [u8; 16] = [3; 16];
const INCARNATION: [u8; 16] = [4; 16];
const ORIGIN: [u8; 16] = [5; 16];
const NONCE: [u8; 32] = [6; 32];
const DEVICE: u8 = 7;
const DEVICE_ID: [u8; 16] = [DEVICE; 16];
const ROOT_SEED: u8 = 40;
const LEAF_SEED: u8 = 30;
pub(super) const NOW: u64 = 500;
const STATE_GENERATION: u64 = 7;
const LEAF_INTERVAL: (u64, u64) = (100, 100_000);
const GROUP: [u8; 32] = [33; 32];
const INSTANCE: [u8; 16] = [8; 16];

fn account_bytes(seed: u8) -> TestResult<[u8; 24]> {
    let text = AccountId::from_random(AccountRandomId::from_bytes([seed; 16])).to_text();
    Ok(text.as_bytes().try_into()?)
}

/// Deterministic entropy: every byte is the next counter value.
struct Counter(u8);

impl EntropySource for Counter {
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination.iter_mut() {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}

fn wire(kind: ArcWireObjectKind, value: &impl TlsEncode) -> TestResult<Vec<u8>> {
    Ok(ArcWireObject::new(kind, value.encode()?)?.encode()?)
}

fn wire_raw(kind: ArcWireObjectKind, body: Vec<u8>) -> TestResult<Vec<u8>> {
    Ok(ArcWireObject::new(kind, body)?.encode()?)
}

fn object_id(bytes: &[u8]) -> [u8; 32] {
    *ObjectId::compute(bytes).as_bytes()
}

fn ok(outcome: Result<Outcome, Fail>) -> TestResult<Outcome> {
    outcome.map_err(|fail| format!("handler failed with {:?}", fail.code).into())
}

fn code(outcome: Result<Outcome, Fail>) -> Option<E2eeReplyCode> {
    outcome.err().map(|fail| fail.code)
}

fn origin_key() -> CompanionOriginKey {
    CompanionOriginKey {
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
    }
}

struct Harness {
    query_sessions: crate::state_core::session::SessionTable,
    query_limits: crate::runtime_config::RuntimeResourceLimits,
    backing: crate::budget::BackingReservationPort,
    monotonic_millis: u64,
    /// The trusted UTC second every request is admitted with.
    now: u64,
    coordinator: CompanionCoordinator,
    entropy: Counter,
    sequence: u64,
    account: [u8; 24],
    principal: Principal,
    /// The generation-zero and generation-one policies of `#room`.
    initial_policy: ArcPolicy,
    operational_policy: ArcPolicy,
    /// The final logical row image after every successful handler outcome.
    writes: Vec<crate::state_core::durable::AccountServiceDurableWrite>,
    /// The principal's device seeds, so a reload rebuilds the same policies.
    devices: Vec<u8>,
    /// Whether the base profile counts the origin as a member of every channel.
    channel_member: bool,
    /// The successor the last finalized ReInit Commit authorized; attempts
    /// carry its target.
    reinit: Option<sequence::reinit_successor::Successor>,
}

impl Harness {
    fn new() -> TestResult<Self> {
        Self::with_devices(&[DEVICE])
    }

    /// A harness whose principal holds `devices`, all on the council.
    fn with_devices(devices: &[u8]) -> TestResult<Self> {
        Self::with_councils(devices, devices, devices)
    }

    /// A harness whose principal holds `devices`, with the bootstrap and
    /// the operational council each naming the given subsets of them.
    fn with_councils(
        devices: &[u8],
        bootstrap_council: &[u8],
        operational_council: &[u8],
    ) -> TestResult<Self> {
        let account = account_bytes(9)?;
        let principal = principal(ROOT_SEED, &account, devices)?;
        let conversation = conversation_id(&NETWORK, &GROUP)?;
        let mut bootstrap = PolicySpec::bootstrap(
            std::slice::from_ref(&principal),
            conversation,
            ArcConversationKind::Channel,
        );
        bootstrap.council = bootstrap_council
            .iter()
            .map(|device| (0, *device))
            .collect();
        let initial_policy = policy(&bootstrap)?;
        let mut operational = bootstrap.successor(policy_id_of(&initial_policy)?);
        operational.council = operational_council
            .iter()
            .map(|device| (0, *device))
            .collect();
        let operational_policy = policy(&operational)?;
        let mut coordinator = CompanionCoordinator::new(
            NETWORK,
            ServerId::from_bytes(COORDINATOR),
            "coordinator.example".into(),
        );
        coordinator.configure_delivery_identity(
            agenc_relay_types::ServerIncarnation::from_bytes([91; 16]),
            agenc_relay_types::RecoveryEpoch::from_bytes([92; 16]),
        )?;
        let sequencer = key(90);
        let credential = sequencer_credential(&sequencer, 0, (0, 2_000_000), None)?;
        let key_set =
            SequencerKeySet::verify(&NETWORK, std::slice::from_ref(&credential), 0, None)?;
        coordinator.install_sequencer(sequencer, key_set, credential)?;
        coordinator.restore_origin(CompanionOrigin {
            home_server_id: HOME,
            server_incarnation: INCARNATION,
            origin_id: ORIGIN,
            generation: 0,
            next_sequence: 0,
            account_id: Some(account),
            account_digest: Some(account_id_digest(&NETWORK, &account)?),
            device: None,
            connection_nonce: NONCE,
            connection_id: [11; 16],
            object_id: [0; 32],
            state_id: [0; 32],
            previous_state_id: [0; 32],
            suspended: false,
            fenced: false,
        });
        Ok(Self {
            query_sessions: crate::state_core::session::SessionTable::new(),
            query_limits: crate::runtime_config::RuntimeResourceLimits::HARD_MAX,
            monotonic_millis: NOW * 1_000,
            now: NOW,
            backing: crate::budget::BackingReservationPort::new(crate::sync::Arc::new(
                crate::budget::MemoryBudget::new(512 * 1024 * 1024),
            )),
            coordinator,
            entropy: Counter(0),
            sequence: 0,
            account,
            principal,
            initial_policy,
            operational_policy,
            writes: Vec::new(),
            devices: devices.to_vec(),
            channel_member: true,
            reinit: None,
        })
    }

    /// A fresh harness whose coordinator is rebuilt from every row this
    /// harness staged, as the daemon rebuilds it at startup; it continues
    /// the request sequence.
    fn reloaded(&self) -> TestResult<Harness> {
        self.reloaded_with(|_| Ok(()))
    }

    /// [`Self::reloaded`] with `install` run on the fresh coordinator before
    /// any row is admitted, as the daemon installs the configured signers
    /// before the durable reload.
    fn reloaded_with(
        &self,
        install: impl FnOnce(&mut CompanionCoordinator) -> TestResult,
    ) -> TestResult<Harness> {
        use crate::state_core::durable::AccountServiceDurableWrite as Write;
        let mut fresh = Harness::with_devices(&self.devices)?;
        install(&mut fresh.coordinator)?;
        for write in &self.writes {
            let Write::Put {
                table,
                key,
                plaintext,
            } = write
            else {
                continue;
            };
            let value = agenc_relay_storage::PersistentRecordValue::decode(*table, plaintext)?;
            fresh
                .coordinator
                .admit_restored_with_backing(*table, key, &value, &fresh.backing);
            fresh
                .writes
                .push(Write::put(*table, key.clone(), plaintext.to_vec())?);
        }
        fresh
            .coordinator
            .finish_restore_with_backing(fresh.backing.clone())?;
        fresh.sequence = self.sequence;
        fresh.reinit.clone_from(&self.reinit);
        // Companion origins are not durable: the edge re-declares the
        // attached device after a reload, which the harness copies over.
        let device = self.device();
        if let Some(origin) = fresh.coordinator.state.origins.get_mut(&origin_key()) {
            origin.next_sequence = self.sequence;
            origin.device = device;
        }
        Ok(fresh)
    }

    /// The binding's initial policy identifier.
    fn initial_policy_id(&self) -> TestResult<[u8; 32]> {
        Ok(policy_id_of(&self.initial_policy)?)
    }

    /// Publishes one policy and returns its retained object identifier.
    fn publish_policy(
        &mut self,
        conversation: [u8; 32],
        policy: &ArcPolicy,
    ) -> TestResult<[u8; 32]> {
        let bytes = wire(ArcWireObjectKind::Policy, policy)?;
        let outcome = ok(self.run(Op::SubmitPolicy, &conversation, Some(&bytes))?)?;
        assert_eq!(
            outcome.result,
            ResultBody::Stored(StoreKind::Policy, object_id(&bytes))
        );
        Ok(object_id(&bytes))
    }

    fn request_id(&self) -> TestResult<[u8; 16]> {
        Ok([u8::try_from(self.sequence)?; 16])
    }

    fn request(
        &self,
        opcode: Op,
        params: &[u8],
        payload: Option<&[u8]>,
    ) -> TestResult<CompleteRequest> {
        let request_id = self.request_id()?;
        let payload_id = payload
            .map(|bytes| object_id(bytes).to_vec())
            .unwrap_or_default();
        let request = ArcFederationRequest {
            profile_version: 1,
            network_id: NETWORK,
            home_server_id: HOME,
            server_incarnation: INCARNATION,
            origin_id: ORIGIN,
            origin_generation: 0,
            operation_sequence: self.sequence,
            request_id,
            opcode,
            encoded_parameters: Opaque::new(params.to_vec())?,
            payload_object_id: Opaque::new(payload_id)?,
        };
        Ok(CompleteRequest {
            correlation: Correlation {
                peer_server_id: HOME,
                server_incarnation: INCARNATION,
                origin_id: ORIGIN,
                origin_generation: 0,
                operation_sequence: self.sequence,
                request_id,
            },
            request: wire(ArcWireObjectKind::FederationRequest, &request)?,
            payload: payload.map(<[u8]>::to_vec),
            refusal: None,
        })
    }

    /// Executes one request against the committed state and applies its
    /// effects, as the coordinator does after the batch commits.
    fn run(
        &mut self,
        opcode: Op,
        params: &[u8],
        payload: Option<&[u8]>,
    ) -> TestResult<Result<Outcome, Fail>> {
        let complete = self.request(opcode, params, payload)?;
        let decoded = request::decode(&self.coordinator, &complete)
            .map_err(|code| format!("decode failed with {code:?}"))?;
        assert_eq!(
            request::classify(&self.coordinator.state, HOME, &decoded),
            Classified::Fresh
        );
        let origin = self
            .coordinator
            .state
            .origins
            .get(&origin_key())
            .cloned()
            .ok_or("the origin is registered")?;
        let home = ServerId::from_bytes(HOME);
        let peers = [home, ServerId::from_bytes([12; 16])];
        let holds = |_: ServerId, _: ChannelInstanceId| true;
        let hosting = |_: ChannelInstanceId| vec![home];
        let attached = |_: &[u8; 32]| vec![home];
        let channel_member = self.channel_member;
        let member = move |_: ChannelInstanceId| channel_member;
        // The harness carries no base channel state; the coordinator glue
        // supplies the binding plan there.
        let plan_binding = |_: ChannelInstanceId, _: &[[u8; 24]]| Ok(None);
        let mut exec = Exec {
            object_source: super::object_read::Source::CompleteMemory,
            queries: Some(self.query_sessions.query_reservations(
                agenc_relay_types::UserId::from_bytes(ORIGIN),
                self.query_limits,
                self.backing.clone(),
            )),
            backing: self.backing.clone(),
            monotonic_millis: self.monotonic_millis,
            coordinator: &self.coordinator,
            home,
            origin: &origin,
            decoded: &decoded,
            now: NOW,
            entropy: &mut self.entropy,
            peers: &peers,
            holds_channel: &holds,
            hosting: &hosting,
            attached_edges: &attached,
            channel_member: &member,
            plan_binding: &plan_binding,
            state_generation: STATE_GENERATION,
            source_view: Vec::new(),
        };
        exec.now = self.now;
        // The base profile of this harness hosts no account: a direct
        // standing is hosted by a declared, attached companion origin only.
        let outcome = ops::execute(&mut exec)
            .and_then(ops::Prepared::complete)
            .map(|mut outcome| {
                super::direct_release::plan_releases(&exec, &|_, _| false, &mut outcome);
                outcome
            });
        self.sequence += 1;
        if let Some(origin) = self.coordinator.state.origins.get_mut(&origin_key()) {
            origin.next_sequence = self.sequence;
        }
        let mut outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => return Ok(Err(error)),
        };
        let resident = match super::resident::prepare(
            &self.coordinator.state,
            &outcome.writes,
            &self.backing,
            None,
        ) {
            Ok(prepared) => prepared,
            Err(code) => return Ok(Err(code.into())),
        };
        // The owner rows ride the same batch; the harness keeps them out of
        // the operation's own writes so each test sees exactly those.
        let operation_writes = outcome.writes.len();
        let owners = match self.coordinator.stage_owners(
            &mut outcome.writes,
            self.now,
            outcome.security_mutation,
            STATE_GENERATION,
        ) {
            Ok(staged) => staged,
            Err(code) => return Ok(Err(code.into())),
        };
        let owner_rows = outcome.writes.split_off(operation_writes);
        resident.apply(&mut self.coordinator.state);
        owners.apply(&mut self.coordinator.state);
        for effect in std::mem::take(&mut outcome.effects) {
            effect(&mut self.coordinator.state);
        }
        for write in outcome.writes.iter().chain(&owner_rows) {
            self.apply_logical_write(write)?;
        }
        Ok(Ok(outcome))
    }

    fn apply_logical_write(
        &mut self,
        write: &crate::state_core::durable::AccountServiceDurableWrite,
    ) -> TestResult {
        use crate::state_core::durable::AccountServiceDurableWrite as Write;
        let (table, key) = match write {
            Write::Put { table, key, .. } | Write::Delete { table, key } => (table, key),
        };
        self.writes.retain(|stored| {
            !matches!(stored, Write::Put { table: stored_table, key: stored_key, .. }
                if stored_table == table && stored_key == key)
        });
        if let Write::Put { plaintext, .. } = write {
            self.writes
                .push(Write::put(*table, key.clone(), plaintext.to_vec())?);
        }
        Ok(())
    }

    fn publish_identity_and_roster(&mut self) -> TestResult {
        let root = wire(ArcWireObjectKind::RootIdentity, &self.principal.root)?;
        let outcome = ok(self.run(Op::PublishIdentity, &[], Some(&root))?)?;
        assert_eq!(
            outcome.result,
            ResultBody::Stored(StoreKind::Identity, object_id(&root))
        );
        assert!(outcome.security_mutation);
        let roster = wire(ArcWireObjectKind::DeviceRoster, &self.principal.roster)?;
        let outcome = ok(self.run(Op::PublishRoster, &[], Some(&roster))?)?;
        assert_eq!(
            outcome.result,
            ResultBody::Stored(StoreKind::Roster, object_id(&roster))
        );
        Ok(())
    }

    /// Runs the attach challenge and returns the new session generation
    /// with the attach object that finished it.
    fn attach(&mut self) -> TestResult<(u64, Vec<u8>)> {
        self.attach_as(DEVICE)
    }

    /// Attaches the principal's device `seed` to the origin in place of
    /// the currently attached one.
    fn attach_as(&mut self, seed: u8) -> TestResult<(u64, Vec<u8>)> {
        let device_id = [seed; 16];
        let outcome = ok(self.run(Op::AttachBegin, &device_id, None)?)?;
        let ResultBody::AttachChallenge(named, challenge_object) = outcome.result else {
            return Err("expected an attach challenge".into());
        };
        assert_eq!(named, device_id);
        let response = outcome.responses.first().ok_or("challenge response")?;
        assert_eq!(object_id(&response.bytes), challenge_object);
        let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
        let object = ArcWireObject::decode_kind(
            &response.bytes,
            Some(ArcWireObjectKind::DeviceAttachChallenge),
            &mut budget,
        )?;
        let challenge = ArcDeviceAttachChallenge::decode_exact(object.body(), &mut budget)?;
        assert_eq!(challenge.tbs.connection_nonce, NONCE);
        let device_signature = sign(
            &key(seed),
            SignatureDomain::DeviceAttachPossession,
            &challenge.tbs,
        )?;
        let attach = wire(
            ArcWireObjectKind::DeviceAttach,
            &ArcDeviceAttach {
                challenge,
                device_signature,
            },
        )?;
        let outcome = ok(self.run(Op::AttachFinish, &device_id, Some(&attach))?)?;
        let ResultBody::Attached(named, generation) = outcome.result else {
            return Err("expected an attached result".into());
        };
        assert_eq!(named, device_id);
        // The edge follows with the base generation transition and the
        // EORIGIN UPDATE that carries the attachment; mirror its outcome.
        if let Some(origin) = self.coordinator.state.origins.get_mut(&origin_key()) {
            origin.device = Some((device_id, generation));
        }
        Ok((generation, attach))
    }

    /// Publishes one leaf-membership proof as the attached device and
    /// returns its retained object identifier.
    fn publish_membership(
        &mut self,
        conversation: [u8; 32],
        proof: &agenc_relay_e2ee::objects::membership::ArcLeafMembershipProof,
    ) -> TestResult<[u8; 32]> {
        let bytes = wire(ArcWireObjectKind::LeafMembershipProof, proof)?;
        let outcome = ok(self.run(Op::SubmitMembership, &conversation, Some(&bytes))?)?;
        assert_eq!(
            outcome.result,
            ResultBody::Stored(StoreKind::Membership, object_id(&bytes))
        );
        Ok(object_id(&bytes))
    }

    /// The attached device's continuing proof for old leaf `leaf_index`
    /// under leaf key `leaf_seed`.
    fn leaf_proof(
        &self,
        conversation: [u8; 32],
        device: u8,
        leaf_seed: u8,
        leaf_index: u32,
    ) -> TestResult<agenc_relay_e2ee::objects::membership::ArcLeafMembershipProof> {
        Ok(support::membership_proof(
            &support::MembershipSpec::continuing(
                &self.principal,
                conversation,
                device,
                leaf_seed,
                leaf_index,
            ),
        )?)
    }

    fn binding_bytes(&self) -> TestResult<Vec<u8>> {
        let fingerprint = root_fingerprint(&self.principal.root)?;
        let package = binding_package(&BindingSpec {
            principals: std::slice::from_ref(&self.principal),
            route: channel_route(b"#room", fingerprint)?,
            channel_instance_id: Some(INSTANCE),
            conversation_nonce: None,
            group_id: GROUP,
            generation: 0,
            previous_binding_id: [0; 32],
            lock_sequence: 0,
            plan_devices: vec![(&self.account, fingerprint, DEVICE)],
            initial_policy_id: policy_id_of(&self.initial_policy)?,
            required_operational_policy_id: policy_id_of(&self.operational_policy)?,
            sequencer_credential_id: self.pinned_credential(),
        })?;
        wire(ArcWireObjectKind::ConversationBinding, &package)
    }

    /// Binds the channel and publishes its two policies and the attached
    /// device's leaf-membership proof, as a client does before its first
    /// Commit (companion 9.3 and 13.7.3).
    /// The credential new bindings pin: the active signer's.
    pub(crate) fn pinned_credential(&self) -> [u8; 32] {
        self.coordinator
            .signer()
            .map_or([31; 32], |signer| signer.credential_id)
    }

    fn bind_channel(&mut self) -> TestResult<[u8; 32]> {
        let conversation = self.bind_channel_unpublished()?;
        let initial = self.initial_policy.clone();
        let operational = self.operational_policy.clone();
        self.publish_policy(conversation, &initial)?;
        self.publish_policy(conversation, &operational)?;
        self.publish_leaf_zero(conversation)?;
        Ok(conversation)
    }

    /// The attached device holds old leaf 0 under `LEAF_SEED`; its proof
    /// precedes every ACK it signs (companion 13.7.3).
    fn publish_leaf_zero(&mut self, conversation: [u8; 32]) -> TestResult<[u8; 32]> {
        let proof = self.leaf_proof(conversation, DEVICE, LEAF_SEED, 0)?;
        self.publish_membership(conversation, &proof)
    }

    /// Publishes the principal, attaches its device, reserves the channel,
    /// and binds it without publishing a policy; returns the conversation
    /// identifier.
    fn bind_channel_unpublished(&mut self) -> TestResult<[u8; 32]> {
        self.publish_identity_and_roster()?;
        self.attach()?;
        let mut reserve = INSTANCE.to_vec();
        reserve.push(5);
        reserve.extend_from_slice(b"#room");
        let outcome = ok(self.run(Op::ReserveChannel, &reserve, None)?)?;
        let ResultBody::Reserved(reservation_id, _) = outcome.result else {
            return Err("expected a reservation".into());
        };
        let binding = self.binding_bytes()?;
        let conversation = conversation_id(&NETWORK, &GROUP)?;
        let mut bind = reservation_id.to_vec();
        bind.extend_from_slice(&conversation);
        bind.extend_from_slice(&[44; 32]);
        let outcome = ok(self.run(Op::BindGroup, &bind, Some(&binding))?)?;
        assert!(matches!(outcome.result, ResultBody::Bound { .. }));
        Ok(conversation)
    }

    fn device(&self) -> Option<([u8; 16], u64)> {
        self.coordinator
            .state
            .origins
            .get(&origin_key())
            .and_then(|origin| origin.device)
    }
}

fn account_param(account: &[u8; 24]) -> Vec<u8> {
    let mut bytes = vec![24];
    bytes.extend_from_slice(account);
    bytes
}

#[test]
fn reload_preserves_published_policies_after_a_council_device_retires() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, DEVICE + 1])?;
    let conversation = harness.bind_channel()?;
    let retained_certificate = harness
        .principal
        .roster
        .tbs
        .active_devices
        .as_slice()
        .iter()
        .find(|entry| entry.device_id == DEVICE_ID)
        .ok_or("retained certificate")?
        .certificate
        .clone();
    let successor = support::roster(
        &harness.principal.root_secret,
        &harness.principal.root,
        1,
        support::roster_id(&harness.principal.roster)?,
        (100, 100 + 6 * 24 * 3600),
        vec![retained_certificate],
        Vec::new(),
    )?;
    let bytes = wire(ArcWireObjectKind::DeviceRoster, &successor)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&bytes))?)?;
    let reloaded = harness.reloaded()?;
    let before = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?;
    let after = reloaded
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("reloaded conversation")?;
    assert_eq!(after.policies, before.policies);
    Ok(())
}

fn retire_council_device(harness: &mut Harness, retired: [u8; 16]) -> TestResult {
    let certificates = harness
        .principal
        .roster
        .tbs
        .active_devices
        .as_slice()
        .iter()
        .filter(|entry| entry.device_id != retired)
        .map(|entry| entry.certificate.clone())
        .collect();
    let successor = support::roster(
        &harness.principal.root_secret,
        &harness.principal.root,
        1,
        support::roster_id(&harness.principal.roster)?,
        (100, 100 + 6 * 24 * 3600),
        certificates,
        Vec::new(),
    )?;
    let bytes = wire(ArcWireObjectKind::DeviceRoster, &successor)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&bytes))?)?;
    Ok(())
}

#[test]
fn reload_preserves_published_policies_after_root_rotation() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let secret = key(ROOT_SEED + 1);
    let root = support::root(
        &secret,
        &harness.account,
        1,
        (0, 2_000_000),
        Some((&harness.principal.root_secret, &harness.principal.root)),
    )?;
    let bytes = wire(ArcWireObjectKind::RootIdentity, &root)?;
    ok(harness.run(Op::PublishIdentity, &[], Some(&bytes))?)?;
    let mut device = DeviceSpec::new(DEVICE);
    device.target_roster_generation = 1;
    let roster = support::roster(
        &secret,
        &root,
        1,
        support::roster_id(&harness.principal.roster)?,
        (100, 100 + 6 * 24 * 3600),
        vec![certificate(&secret, &root, &device)?],
        Vec::new(),
    )?;
    let bytes = wire(ArcWireObjectKind::DeviceRoster, &roster)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&bytes))?)?;
    let reloaded = harness.reloaded()?;
    let before = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?;
    let after = reloaded
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("reloaded conversation")?;
    assert_eq!(after.policies, before.policies);
    assert_eq!(after.current_policy_id, before.current_policy_id);
    Ok(())
}

#[test]
fn reload_rejects_a_forged_historical_roster() -> TestResult {
    use crate::state_core::durable::AccountServiceDurableWrite as Write;
    let mut harness = Harness::with_devices(&[DEVICE, DEVICE + 1])?;
    let conversation = harness.bind_channel()?;
    let original = wire(ArcWireObjectKind::DeviceRoster, &harness.principal.roster)?;
    let original_key = agenc_relay_storage::e2ee_records::object_key(&object_id(&original))?;
    retire_council_device(&mut harness, [DEVICE + 1; 16])?;
    harness.writes.retain(|write| {
        !matches!(write, Write::Put { table: agenc_relay_storage::TableId::E2eeObject, key, .. } if *key == original_key)
    });
    let mut forged = harness.principal.roster.clone();
    if let Some(byte) = forged.root_signature.first_mut() {
        *byte ^= 1;
    }
    let forged = wire(ArcWireObjectKind::DeviceRoster, &forged)?;
    harness.writes.push(
        CompanionCoordinator::object_write(&forged)
            .map_err(|code| format!("object write: {code:?}"))?,
    );
    let reloaded = harness.reloaded()?;
    let restored = reloaded
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?;
    assert!(restored.policies.is_empty());
    Ok(())
}

#[test]
fn whoami_reports_the_account_and_refuses_parameters() -> TestResult {
    let mut harness = Harness::new()?;
    let outcome = ok(harness.run(Op::Whoami, &[], None)?)?;
    assert_eq!(outcome.result, ResultBody::Account(harness.account, 0));
    assert!(outcome.writes.is_empty());
    assert_eq!(
        code(harness.run(Op::Whoami, &[1], None)?),
        Some(E2eeReplyCode::InvalidFragment)
    );
    Ok(())
}

#[test]
fn attachment_needs_a_published_roster() -> TestResult {
    let mut harness = Harness::new()?;
    assert_eq!(
        code(harness.run(Op::AttachBegin, &DEVICE_ID, None)?),
        Some(E2eeReplyCode::DeviceRequired)
    );
    let roster = wire(ArcWireObjectKind::DeviceRoster, &harness.principal.roster)?;
    assert_eq!(
        code(harness.run(Op::PublishRoster, &[], Some(&roster))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    assert_eq!(
        code(harness.run(Op::PublishCapabilities, &DEVICE_ID, Some(&roster))?),
        Some(E2eeReplyCode::DeviceRequired)
    );
    Ok(())
}

#[test]
fn devices_attach_by_compare_and_swap() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    let root = wire(ArcWireObjectKind::RootIdentity, &harness.principal.root)?;
    let outcome = ok(harness.run(Op::FetchIdentity, &account_param(&harness.account), None)?)?;
    assert_eq!(outcome.result, ResultBody::ObjectPage);
    assert_eq!(
        outcome
            .responses
            .first()
            .map(|response| response.bytes.clone()),
        Some(root)
    );
    let (generation, stale) = harness.attach()?;
    assert_eq!(generation, 1);
    assert_eq!(harness.device(), Some((DEVICE_ID, 1)));
    let outcome = ok(harness.run(Op::Whoami, &[], None)?)?;
    assert_eq!(outcome.result, ResultBody::Account(harness.account, 1));
    let (generation, _) = harness.attach()?;
    assert_eq!(generation, 2);
    assert_eq!(
        code(harness.run(Op::AttachFinish, &DEVICE_ID, Some(&stale))?),
        Some(E2eeReplyCode::DeviceRequired)
    );
    assert_eq!(harness.device(), Some((DEVICE_ID, 2)));
    Ok(())
}

fn key_package_bytes(harness: &Harness) -> TestResult<Vec<u8>> {
    let vectors = default_capabilities();
    let capabilities_hash = leaf_capabilities_digest(&encoded_capabilities(&vectors)?)?;
    let bundle = ArcCredentialBundle {
        root: harness.principal.root.clone(),
        device_certificate: certificate(
            &harness.principal.root_secret,
            &harness.principal.root,
            &DeviceSpec::new(DEVICE),
        )?,
        leaf_authorization: leaf_authorization(
            &harness.principal.roster,
            &LeafSpec {
                capabilities_hash,
                interval: LEAF_INTERVAL,
                ..LeafSpec::new(DEVICE, LEAF_SEED)
            },
        )?,
    };
    let identity = bundle.encode()?;
    let package = key_package(&KeyPackageSpec {
        identity: &identity,
        leaf_seed: LEAF_SEED,
        suite: 1,
        lifetime: LEAF_INTERVAL,
        capabilities: vectors,
        leaf_extensions: Vec::new(),
    })?;
    wire_raw(ArcWireObjectKind::KeyPackageMls, package)
}

#[test]
fn packages_publish_once_and_claim_once_per_operation() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let capabilities = capabilities(
        DEVICE,
        &harness.principal.roster,
        0,
        [0; 32],
        (100, 200),
        vec![1, 3],
    )?;
    let capability_bytes = wire(ArcWireObjectKind::DeviceCapabilities, &capabilities)?;
    let outcome = ok(harness.run(Op::PublishCapabilities, &DEVICE_ID, Some(&capability_bytes))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::Stored(StoreKind::Capabilities, object_id(&capability_bytes))
    );
    let outcome = ok(harness.run(
        Op::FetchCapabilities,
        &[account_param(&harness.account), vec![0]].concat(),
        None,
    )?)?;
    assert_eq!(outcome.result, ResultBody::ObjectPage);
    assert_eq!(outcome.responses.len(), 1);

    let package = key_package_bytes(&harness)?;
    let mut publish = DEVICE_ID.to_vec();
    publish.extend_from_slice(&1_u16.to_be_bytes());
    publish.extend_from_slice(&50_000_u64.to_be_bytes());
    let outcome = ok(harness.run(Op::PublishPackage, &publish, Some(&package))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::Stored(StoreKind::Package, object_id(&package))
    );
    assert_eq!(
        code(harness.run(Op::PublishPackage, &publish, Some(&package))?),
        Some(E2eeReplyCode::OperationConflict)
    );

    let mut claim = account_param(&harness.account);
    claim.extend_from_slice(&DEVICE_ID);
    claim.extend_from_slice(&1_u16.to_be_bytes());
    claim.extend_from_slice(&[9; 16]);
    let first = ok(harness.run(Op::ClaimPackage, &claim, None)?)?;
    let ResultBody::Claimed(device, reference, claimed_object) = first.result.clone() else {
        return Err("expected a claimed result".into());
    };
    assert_eq!(device, DEVICE_ID);
    assert_eq!(claimed_object, object_id(&package));
    assert_eq!(reference.len(), 32);
    assert_eq!(
        first
            .responses
            .first()
            .map(|response| response.bytes.clone()),
        Some(package.clone())
    );
    let again = ok(harness.run(Op::ClaimPackage, &claim, None)?)?;
    assert_eq!(again.result, first.result);
    assert!(again.writes.is_empty());
    let status = ok(harness.run(Op::ClaimStatus, &[9; 16], None)?)?;
    assert_eq!(status.result, first.result);

    let mut other = account_param(&harness.account);
    other.extend_from_slice(&DEVICE_ID);
    other.extend_from_slice(&1_u16.to_be_bytes());
    other.extend_from_slice(&[10; 16]);
    let exhausted = ok(harness.run(Op::ClaimPackage, &other, None)?)?;
    assert_eq!(exhausted.result, ResultBody::Empty(EmptyKind::Package));
    let mut revoke = vec![32];
    revoke.extend_from_slice(&reference);
    assert_eq!(
        code(harness.run(Op::RevokePackage, &revoke, None)?),
        Some(E2eeReplyCode::KeyUnavailable)
    );
    Ok(())
}

#[test]
fn channel_routes_reserve_bind_and_carry_application_traffic() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let mut reserve = INSTANCE.to_vec();
    reserve.push(5);
    reserve.extend_from_slice(b"#room");
    let outcome = ok(harness.run(Op::ReserveChannel, &reserve, None)?)?;
    let ResultBody::Reserved(reservation_id, reservation_object) = outcome.result else {
        return Err("expected a reservation".into());
    };
    assert_eq!(
        outcome
            .responses
            .first()
            .map(|response| object_id(&response.bytes)),
        Some(reservation_object)
    );
    assert_eq!(
        code(harness.run(Op::ReserveChannel, &reserve, None)?),
        Some(E2eeReplyCode::GroupConflict)
    );

    let binding = harness.binding_bytes()?;
    let conversation = conversation_id(&NETWORK, &GROUP)?;
    let mut bind = reservation_id.to_vec();
    bind.extend_from_slice(&conversation);
    bind.extend_from_slice(&[44; 32]);
    let outcome = ok(harness.run(Op::BindGroup, &bind, Some(&binding))?)?;
    let ResultBody::Bound {
        conversation_id: bound,
        binding_object_id,
        ..
    } = outcome.result
    else {
        return Err("expected a bound result".into());
    };
    assert_eq!(bound, conversation);
    assert_eq!(binding_object_id, object_id(&binding));
    assert!(outcome.security_mutation);
    assert_eq!(outcome.events.len(), 2);
    assert!(
        outcome
            .events
            .iter()
            .all(|event| event.planned.kind == EventKind::RouteStateChanged)
    );
    assert_eq!(
        code(harness.run(Op::BindGroup, &bind, Some(&binding))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );

    let aad = ArcApplicationAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        route_binding: channel_route_binding(&NETWORK, &INSTANCE)?,
        latest_state_id: [22; 32],
    }
    .encode()?;
    let message = wire_raw(
        ArcWireObjectKind::ApplicationMls,
        private_message_bytes(&GROUP, 1, &aad)?,
    )?;
    let mut send = conversation.to_vec();
    send.extend_from_slice(&INSTANCE);
    // A bootstrapping group carries no application traffic until its
    // bootstrap activation certificate (companion 7.4, 13.2); the
    // finalization path is covered by the sequencing tests, so activate the
    // lifecycle directly.
    assert_eq!(
        code(harness.run(Op::ApplicationChannel, &send, Some(&message))?),
        Some(E2eeReplyCode::FinalityRequired)
    );
    harness
        .coordinator
        .state
        .lifecycles
        .get_mut(&conversation)
        .ok_or("the bound lifecycle")?
        .bootstrap_activated()?;
    let outcome = ok(harness.run(Op::ApplicationChannel, &send, Some(&message))?)?;
    assert_eq!(outcome.result, ResultBody::AcceptedEvent);
    assert_eq!(outcome.events.len(), 1);
    let event = outcome.events.first().ok_or("one fanout copy")?;
    assert_eq!(event.planned.kind, EventKind::ChannelApplication);
    assert_eq!(event.payload.as_deref(), Some(message.as_slice()));
    let other_group = wire_raw(
        ArcWireObjectKind::ApplicationMls,
        private_message_bytes(&[1; 32], 1, &aad)?,
    )?;
    assert_eq!(
        code(harness.run(Op::ApplicationChannel, &send, Some(&other_group))?),
        Some(E2eeReplyCode::RouteInvalid)
    );

    let outcome = ok(harness.run(Op::QueryChannel, &reserve, None)?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Bound { conversation_id, .. } if conversation_id == conversation
    ));
    Ok(())
}

#[test]
fn mailbox_items_are_fetched_with_tokens_and_acknowledged_once() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let binding = harness.binding_bytes()?;
    let mut deliver = account_param(&harness.account);
    deliver.extend_from_slice(&DEVICE_ID);
    let outcome = ok(harness.run(Op::DeliverBinding, &deliver, Some(&binding))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::Stored(StoreKind::Binding, object_id(&binding))
    );
    let page = ok(harness.run(Op::FetchMailbox, &[2, 0], None)?)?;
    assert_eq!(page.result, ResultBody::MailboxPage);
    let delivery = page.responses.first().ok_or("one mailbox item")?;
    assert_eq!(delivery.bytes, binding);
    assert_eq!(delivery.target_device_id, Some(DEVICE_ID));
    let token = delivery.delivery_token.ok_or("a delivery token")?;
    let mut ack = token.to_vec();
    ack.extend_from_slice(&object_id(&binding));
    let outcome = ok(harness.run(Op::AcknowledgeMailbox, &ack, None)?)?;
    assert_eq!(
        outcome.result,
        ResultBody::MailboxAcked(token, object_id(&binding))
    );
    assert_exact_mailbox_retirement(
        &harness.account,
        token,
        object_id(&binding),
        &outcome.writes,
    )?;
    let again = ok(harness.run(Op::AcknowledgeMailbox, &ack, None)?)?;
    assert_eq!(again.result, outcome.result);
    assert!(again.writes.is_empty());
    let empty = ok(harness.run(Op::FetchMailbox, &[2, 0], None)?)?;
    assert_eq!(empty.result, ResultBody::Empty(EmptyKind::Binding));
    Ok(())
}

fn assert_exact_mailbox_retirement(
    account: &[u8; 24],
    token: [u8; 32],
    object: [u8; 32],
    writes: &[crate::state_core::durable::AccountServiceDurableWrite],
) -> TestResult {
    use crate::state_core::durable::AccountServiceDurableWrite as Write;
    use agenc_relay_storage::e2ee_records::{MAILBOX_ROW_KIND, MailboxKind, MailboxRow};
    use agenc_relay_storage::{PersistentRecordValue, TableId};
    let [
        Write::Put {
            table: TableId::E2eeState,
            key: ack,
            plaintext,
        },
        Write::Delete {
            table: TableId::E2eeState,
            key: item,
        },
        Write::Delete {
            table: TableId::E2eeState,
            key: token_row,
        },
    ] = writes
    else {
        return Err("ACK must persist evidence and retire exactly its Item and Token".into());
    };
    let digest = account_id_digest(&NETWORK, account)?;
    assert_eq!(
        ack.as_bytes(),
        MailboxRow::ack_key(&digest, &DEVICE_ID, &token)?.as_bytes()
    );
    assert_eq!(
        item.as_bytes(),
        MailboxRow::item_key(&digest, &DEVICE_ID, MailboxKind::Binding, 0)?.as_bytes()
    );
    assert_eq!(
        token_row.as_bytes(),
        MailboxRow::token_key(&token)?.as_bytes()
    );
    let evidence = PersistentRecordValue::decode(TableId::E2eeState, plaintext)?;
    assert_eq!(evidence.record_kind(), MAILBOX_ROW_KIND);
    assert_eq!(
        MailboxRow::decode(evidence.body())?,
        MailboxRow::Ack {
            object_id: object,
            acknowledged_at: NOW,
            retain_until: NOW + agenc_relay_domain::e2ee::limits::MAILBOX_ACK_RETENTION_SECONDS,
        }
    );
    Ok(())
}

#[test]
fn replay_rows_answer_exact_duplicates_and_refuse_conflicts() -> TestResult {
    let harness = Harness::new()?;
    let complete = harness.request(Op::Whoami, &[], None)?;
    let decoded = request::decode(&harness.coordinator, &complete)
        .map_err(|code| format!("decode failed with {code:?}"))?;
    let conflicting = harness.request(Op::Whoami, &[1], None)?;
    let conflicting = request::decode(&harness.coordinator, &conflicting)
        .map_err(|code| format!("decode failed with {code:?}"))?;
    let key = request::replay_key(HOME, &decoded.request);
    let mut state = harness.coordinator.state;
    state.replays.insert(
        key,
        ReplayRow {
            request_id: decoded.request.request_id,
            request_object_id: decoded.request_object_id,
            result_object_id: Some([1; 32]),
            response_object_ids: vec![[2; 32]],
            security_mutation: false,
            retain_until: NOW + 60,
        },
    );
    super::results::Prepared::capture(&[1, 2, 3], [[2; 32]].into_iter(), &harness.backing)?
        .apply(&mut state.results, decoded.request_object_id);
    state.objects.insert([2; 32], vec![9, 9]);
    assert_eq!(
        request::classify(&state, HOME, &decoded),
        Classified::Replay(vec![1, 2, 3], vec![vec![9, 9]])
    );
    assert_eq!(
        request::classify(&state, HOME, &conflicting),
        Classified::Violation
    );
    state.replays.clear();
    if let Some(origin) = state.origins.get_mut(&origin_key()) {
        origin.next_sequence = 5;
    }
    assert_eq!(
        request::classify(&state, HOME, &decoded),
        Classified::Violation
    );
    Ok(())
}

/// A valid attached-origin Commit fixture for the root storage actor tests.
pub(crate) struct FreshFetchFixture {
    pub(crate) executor: CompanionCoordinator,
    pub(crate) complete: CompleteRequest,
    pub(crate) conversation: [u8; 32],
    pub(crate) object_id: [u8; 32],
    pub(crate) bytes: Vec<u8>,
}

pub(crate) fn fresh_fetch_fixture() -> TestResult<FreshFetchFixture> {
    sequence::fresh_fetch_fixture()
}
