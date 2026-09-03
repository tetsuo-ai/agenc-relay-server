#![forbid(unsafe_code)]

//! In-process handler tests: one companion coordinator with a sequencer
//! and one attached origin executes requests directly through the opcode
//! dispatcher, applying each committed effect by hand.

use std::error::Error;

use agenc_ircd_crypto::SignatureDomain;
use agenc_ircd_domain::e2ee::projection::{EmptyKind, EventKind, StoreKind};
use agenc_ircd_e2ee::ObjectId;
use agenc_ircd_e2ee::federation::frames::Correlation;
use agenc_ircd_e2ee::ids::{account_id_digest, conversation_id, leaf_capabilities_digest};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::aad::IrcApplicationAad;
use agenc_ircd_e2ee::objects::attach::{IrcDeviceAttach, IrcDeviceAttachChallenge};
use agenc_ircd_e2ee::objects::federation::{IrcFederationOpcode as Op, IrcFederationRequest};
use agenc_ircd_e2ee::objects::identity::IrcCredentialBundle;
use agenc_ircd_e2ee::route::channel_route_binding;
use agenc_ircd_e2ee::sequencer::SequencerKeySet;
use agenc_ircd_e2ee::tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_storage::e2ee_records::ReplayRow;
use agenc_ircd_types::{
    AccountId, AccountRandomId, ChannelInstanceId, EntropyError, EntropySource, ServerId,
};
use support::{
    BindingSpec, DeviceSpec, KeyPackageSpec, LeafSpec, NETWORK, Principal, binding_package,
    capabilities, certificate, channel_route, default_capabilities, encoded_capabilities, key,
    key_package, leaf_authorization, principal, private_message_bytes, root_fingerprint,
    sequencer_credential, sign,
};

use super::ops::{self, Exec, Fail};
use super::request::{self, Classified, Outcome, ResultBody};
use super::{
    CompanionCoordinator, CompanionOrigin, CompanionOriginKey, CompleteRequest, StoredResult,
};

mod support;

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
const NOW: u64 = 500;
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

fn wire(kind: IrcWireObjectKind, value: &impl TlsEncode) -> TestResult<Vec<u8>> {
    Ok(IrcWireObject::new(kind, value.encode()?)?.encode()?)
}

fn wire_raw(kind: IrcWireObjectKind, body: Vec<u8>) -> TestResult<Vec<u8>> {
    Ok(IrcWireObject::new(kind, body)?.encode()?)
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
    coordinator: CompanionCoordinator,
    entropy: Counter,
    sequence: u64,
    account: [u8; 24],
    principal: Principal,
}

impl Harness {
    fn new() -> TestResult<Self> {
        let account = account_bytes(9)?;
        let principal = principal(ROOT_SEED, &account, &[DEVICE])?;
        let mut coordinator = CompanionCoordinator::new(
            NETWORK,
            ServerId::from_bytes(COORDINATOR),
            "coordinator.example".into(),
        );
        let sequencer = key(90);
        let credential = sequencer_credential(&sequencer, 0, (0, 2_000_000), None)?;
        let key_set =
            SequencerKeySet::verify(&NETWORK, std::slice::from_ref(&credential), 0, None)?;
        coordinator.install_sequencer(sequencer, key_set, credential);
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
            connection_id: 11,
        });
        Ok(Self {
            coordinator,
            entropy: Counter(0),
            sequence: 0,
            account,
            principal,
        })
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
        let request = IrcFederationRequest {
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
            request: wire(IrcWireObjectKind::FederationRequest, &request)?,
            payload: payload.map(<[u8]>::to_vec),
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
        let member = |_: ChannelInstanceId| true;
        let mut exec = Exec {
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
            state_generation: STATE_GENERATION,
            source_view: Vec::new(),
        };
        let outcome = ops::execute(&mut exec);
        self.sequence += 1;
        if let Some(origin) = self.coordinator.state.origins.get_mut(&origin_key()) {
            origin.next_sequence = self.sequence;
        }
        Ok(outcome.map(|mut outcome| {
            for effect in std::mem::take(&mut outcome.effects) {
                effect(&mut self.coordinator.state);
            }
            outcome
        }))
    }

    fn publish_identity_and_roster(&mut self) -> TestResult {
        let root = wire(IrcWireObjectKind::RootIdentity, &self.principal.root)?;
        let outcome = ok(self.run(Op::PublishIdentity, &[], Some(&root))?)?;
        assert_eq!(
            outcome.result,
            ResultBody::Stored(StoreKind::Identity, object_id(&root))
        );
        assert!(outcome.security_mutation);
        let roster = wire(IrcWireObjectKind::DeviceRoster, &self.principal.roster)?;
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
        let outcome = ok(self.run(Op::AttachBegin, &DEVICE_ID, None)?)?;
        let ResultBody::AttachChallenge(named, challenge_object) = outcome.result else {
            return Err("expected an attach challenge".into());
        };
        assert_eq!(named, DEVICE_ID);
        let response = outcome.responses.first().ok_or("challenge response")?;
        assert_eq!(object_id(&response.bytes), challenge_object);
        let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
        let object = IrcWireObject::decode_kind(
            &response.bytes,
            Some(IrcWireObjectKind::DeviceAttachChallenge),
            &mut budget,
        )?;
        let challenge = IrcDeviceAttachChallenge::decode_exact(object.body(), &mut budget)?;
        assert_eq!(challenge.tbs.connection_nonce, NONCE);
        let device_signature = sign(
            &key(DEVICE),
            SignatureDomain::DeviceAttachPossession,
            &challenge.tbs,
        )?;
        let attach = wire(
            IrcWireObjectKind::DeviceAttach,
            &IrcDeviceAttach {
                challenge,
                device_signature,
            },
        )?;
        let outcome = ok(self.run(Op::AttachFinish, &DEVICE_ID, Some(&attach))?)?;
        let ResultBody::Attached(named, generation) = outcome.result else {
            return Err("expected an attached result".into());
        };
        assert_eq!(named, DEVICE_ID);
        Ok((generation, attach))
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
        })?;
        wire(IrcWireObjectKind::ConversationBinding, &package)
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
    let roster = wire(IrcWireObjectKind::DeviceRoster, &harness.principal.roster)?;
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
    let root = wire(IrcWireObjectKind::RootIdentity, &harness.principal.root)?;
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
    let bundle = IrcCredentialBundle {
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
    wire_raw(IrcWireObjectKind::KeyPackageMls, package)
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
    let capability_bytes = wire(IrcWireObjectKind::DeviceCapabilities, &capabilities)?;
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

    let aad = IrcApplicationAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        route_binding: channel_route_binding(&NETWORK, &INSTANCE)?,
        latest_state_id: [22; 32],
    }
    .encode()?;
    let message = wire_raw(
        IrcWireObjectKind::ApplicationMls,
        private_message_bytes(&GROUP, 1, &aad)?,
    )?;
    let mut send = conversation.to_vec();
    send.extend_from_slice(&INSTANCE);
    // A bootstrapping group carries no application traffic until its first
    // finalization activates it (companion 13.1); the finalization path is
    // covered by the sequencing tests, so activate the lifecycle directly.
    assert_eq!(
        code(harness.run(Op::ApplicationChannel, &send, Some(&message))?),
        Some(E2eeReplyCode::RouteInvalid)
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
        IrcWireObjectKind::ApplicationMls,
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
    assert_eq!(outcome.writes.len(), 2);
    let again = ok(harness.run(Op::AcknowledgeMailbox, &ack, None)?)?;
    assert_eq!(again.result, outcome.result);
    assert!(again.writes.is_empty());
    let empty = ok(harness.run(Op::FetchMailbox, &[2, 0], None)?)?;
    assert_eq!(empty.result, ResultBody::Empty(EmptyKind::Binding));
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
    state.results.insert(
        decoded.request_object_id,
        StoredResult {
            result: vec![1, 2, 3],
            responses: vec![[2; 32]],
        },
    );
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
