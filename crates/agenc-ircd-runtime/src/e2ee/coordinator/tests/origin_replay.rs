#![forbid(unsafe_code)]

//! Durable request assembly and restart without retained replay results.

#[path = "origin_replay/response_completeness.rs"]
mod response_completeness;

#[path = "origin_replay/resident_admission.rs"]
mod resident_admission;

use agenc_ircd_domain::e2ee::projection::EmptyKind;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::federation::{
    IrcFederationOpcode, IrcFederationOrigin, IrcFederationRequest,
};
use agenc_ircd_e2ee::tls::{Opaque, TlsEncode};
use agenc_ircd_storage::PersistentRecordValue;
use agenc_ircd_storage::e2ee_records::prefix;
use agenc_ircd_types::{EntropyError, EntropySource};

use super::super::CompanionFault;
use super::super::sync::{BaseOriginView, CompanionHost, OriginDescriptor};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NETWORK: [u8; 32] = [1; 32];
const HOME: [u8; 16] = [2; 16];
const COORDINATOR: [u8; 16] = [3; 16];
const INCARNATION: [u8; 16] = [4; 16];
const ORIGIN: [u8; 16] = [5; 16];

struct Host(u64);

impl CompanionHost for Host {
    fn live_incarnation(&self, _peer: ServerId) -> Option<[u8; 16]> {
        Some(INCARNATION)
    }

    fn base_origin(&self, _key: &CompanionOriginKey) -> Option<BaseOriginView> {
        Some(BaseOriginView {
            generation: self.0,
            connection_id: [6; 16],
            connection_nonce: [7; 32],
            session: None,
            account: None,
        })
    }

    fn base_origins_ready(&self, _peer: ServerId) -> bool {
        true
    }
    fn base_resync_epoch(&self, _peer: ServerId) -> u64 {
        0
    }
    fn state_generation(&self) -> u64 {
        1
    }
    fn holds_channel(&self, _instance: [u8; 16]) -> bool {
        false
    }
    fn hosts_account(&self, _account: &[u8; 24]) -> bool {
        false
    }
}

struct Entropy;

impl EntropySource for Entropy {
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(42);
        Ok(())
    }
}

fn coordinator() -> CompanionCoordinator {
    CompanionCoordinator::new(
        NETWORK,
        ServerId::from_bytes(COORDINATOR),
        "coordinator.example".into(),
    )
}

fn origin_key() -> CompanionOriginKey {
    CompanionOriginKey {
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
    }
}

fn declare(coordinator: &mut CompanionCoordinator, generation: u64) -> TestResult {
    let host = Host(generation);
    let home = ServerId::from_bytes(HOME);
    coordinator.origin_reset(home, COORDINATOR, INCARNATION, &host)?;
    let origin = IrcFederationOrigin {
        profile_version: 1,
        network_id: NETWORK,
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        origin_generation: generation,
        previous_origin_state_id: if generation == 0 { [0; 32] } else { [8; 32] },
        connection_id: [6; 16],
        session_id: Opaque::new(Vec::new())?,
        user_id: Opaque::new(Vec::new())?,
        account_id: Opaque::new(Vec::new())?,
        account_session_generation: 0,
        connection_nonce: [7; 32],
        attached_device_id: Opaque::new(Vec::new())?,
        device_session_generation: 0,
    };
    let bytes =
        IrcWireObject::new(IrcWireObjectKind::FederationOrigin, origin.encode()?)?.encode()?;
    let descriptor = OriginDescriptor {
        coordinator_server_id: COORDINATOR,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        origin_generation: generation,
        object_id: *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes(),
    };
    for fragment in fragment_object(&bytes)? {
        coordinator.origin_state(home, generation != 0, descriptor, fragment, 500_000, &host)?;
    }
    Ok(())
}

fn decoded(generation: u64, sequence: u64) -> TestResult<Decoded> {
    let request = IrcFederationRequest {
        profile_version: 1,
        network_id: NETWORK,
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        origin_generation: generation,
        operation_sequence: sequence,
        request_id: [9; 16],
        opcode: IrcFederationOpcode::FetchIdentity,
        encoded_parameters: Opaque::new(vec![0; 24])?,
        payload_object_id: Opaque::new(Vec::new())?,
    };
    let bytes =
        IrcWireObject::new(IrcWireObjectKind::FederationRequest, request.encode()?)?.encode()?;
    Ok(Decoded {
        request_object_id: *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes(),
        request,
        payload: None,
        payload_bytes: None,
    })
}

fn backing() -> crate::budget::BackingReservationPort {
    crate::budget::BackingReservationPort::new(std::sync::Arc::new(
        crate::budget::MemoryBudget::new(1_048_576),
    ))
}

fn batch(coordinator: &CompanionCoordinator, request: &Decoded) -> TestResult<Assembled> {
    let mut entropy = Entropy;
    assemble(
        coordinator,
        HOME,
        ServerId::from_bytes(HOME),
        request,
        Outcome::scalar(request::ResultBody::Empty(EmptyKind::Identity)),
        1,
        500,
        None,
        BarrierInputs {
            backing: backing(),
            base_counts: None,
            base_capacity: &|_, _, _| true,
            entropy: &mut entropy,
        },
    )
    .map_err(|error| format!("{error:?}").into())
}

fn reload(
    writes: &[AccountServiceDurableWrite],
    expire_replays: bool,
    legacy: bool,
) -> TestResult<CompanionCoordinator> {
    let mut restored = coordinator();
    for write in writes {
        let AccountServiceDurableWrite::Put {
            table,
            key,
            plaintext,
        } = write
        else {
            continue;
        };
        if (expire_replays && key.as_bytes().starts_with(prefix::REPLAY))
            || (legacy && key.as_bytes().starts_with(prefix::ORIGIN_SEQUENCE))
        {
            continue;
        }
        let value = PersistentRecordValue::decode(*table, plaintext)?;
        restored.admit_restored(*table, key, &value);
    }
    restored.finish_restore()?;
    Ok(restored)
}

#[test]
fn restart_keeps_origin_sequences_after_replay_results_expire() -> TestResult {
    for generation in [0, 1] {
        let original = coordinator();
        let completed = decoded(generation, 4)?;
        let staged = batch(&original, &completed)?;
        let mut restored = reload(&staged.writes, true, false)?;
        assert!(restored.state.replays.is_empty());
        declare(&mut restored, generation)?;
        assert_eq!(
            restored
                .state
                .origins
                .get(&origin_key())
                .map(|origin| origin.next_sequence),
            Some(5)
        );
        assert_eq!(
            request::classify(&restored.state, HOME, &decoded(generation, 5)?),
            Classified::Fresh
        );
        assert_eq!(
            request::classify(&restored.state, HOME, &decoded(generation, 0)?),
            Classified::Violation
        );
        assert_eq!(
            request::classify(&restored.state, HOME, &completed),
            Classified::Violation
        );
    }
    Ok(())
}

fn legacy_history_after_partial_expiry(generation: u64) -> TestResult<CompanionCoordinator> {
    let original = coordinator();
    let earlier = decoded(generation, 0)?;
    let mut outcome = Outcome::scalar(request::ResultBody::Empty(EmptyKind::Identity));
    outcome.security_mutation = true;
    let mut entropy = Entropy;
    let mut retained = assemble(
        &original,
        HOME,
        ServerId::from_bytes(HOME),
        &earlier,
        outcome,
        1,
        500,
        None,
        BarrierInputs {
            backing: backing(),
            base_counts: None,
            base_capacity: &|_, _, _| true,
            entropy: &mut entropy,
        },
    )
    .map_err(|error| format!("{error:?}"))?;
    let latest = decoded(generation, 1)?;
    let expired_key = agenc_ircd_storage::e2ee_records::ReplayRow::key(&request::replay_key(
        HOME,
        &latest.request,
    ))?;
    retained.writes.extend(batch(&original, &latest)?.writes);
    // The later ordinary result expires while the earlier security mutation
    // remains. Pre-floor storage has no record of the actual next sequence, 2.
    retained.writes.retain(|write| {
        !matches!(write, AccountServiceDurableWrite::Put { key, .. } if *key == expired_key)
    });
    reload(&retained.writes, false, true)
}

#[test]
fn restart_rejects_legacy_origin_with_partial_replay_history() -> TestResult {
    for generation in [0, 1] {
        let mut restored = legacy_history_after_partial_expiry(generation)?;
        assert_eq!(restored.state.replays.len(), 1);
        assert!(restored.state.origin_sequences.is_empty());
        let error = declare(&mut restored, generation)
            .err()
            .ok_or("legacy sequence was accepted despite ambiguous history")?;
        assert!(matches!(
            error.downcast_ref::<CompanionFault>(),
            Some(CompanionFault::Protocol)
        ));
        assert!(!restored.state.origins.contains_key(&origin_key()));
        assert_eq!(
            request::classify(&restored.state, HOME, &decoded(generation, 1)?),
            Classified::Violation
        );

        // An authenticated, previously unused generation has its own sequence.
        declare(&mut restored, generation + 1)?;
        assert_eq!(
            request::classify(&restored.state, HOME, &decoded(generation + 1, 0)?),
            Classified::Fresh
        );
    }
    Ok(())
}

#[test]
fn request_commit_retains_sequence_floor_with_its_replay_result() -> TestResult {
    let mut original = coordinator();
    declare(&mut original, 0)?;
    let staged = batch(&original, &decoded(0, 0)?)?;
    assert!(original.state.origin_sequences.is_empty());
    assert_eq!(
        original
            .state
            .origins
            .get(&origin_key())
            .map(|origin| origin.next_sequence),
        Some(0)
    );
    let restored = reload(&staged.writes, false, false)?;
    assert_eq!(restored.state.replays.len(), 1);
    assert_eq!(
        restored
            .state
            .origin_sequences
            .get(&origin_key())
            .map(|row| row.next_sequence),
        Some(1)
    );
    for effect in staged.effects {
        effect(&mut original.state);
    }
    assert_eq!(
        original.state.origin_sequences,
        restored.state.origin_sequences
    );
    assert_eq!(
        original
            .state
            .origins
            .get(&origin_key())
            .map(|origin| origin.next_sequence),
        Some(1)
    );
    Ok(())
}

#[test]
fn exhausted_origin_sequence_rejects_fresh_requests() -> TestResult {
    let mut original = coordinator();
    declare(&mut original, 0)?;
    original
        .state
        .origins
        .get_mut(&origin_key())
        .ok_or("missing origin")?
        .next_sequence = u64::MAX;
    let request = decoded(0, u64::MAX)?;
    assert_eq!(
        request::classify(&original.state, HOME, &request),
        Classified::Violation
    );
    assert!(batch(&original, &request).is_err());
    Ok(())
}

#[test]
fn origin_sequence_floor_rejects_generation_rollback_and_isolates_incarnations() -> TestResult {
    let staged = batch(&coordinator(), &decoded(1, 4)?)?;
    let mut restored = reload(&staged.writes, true, false)?;
    assert!(declare(&mut restored, 0).is_err());
    assert!(!restored.state.origins.contains_key(&origin_key()));

    let mut new_generation = reload(&staged.writes, true, false)?;
    declare(&mut new_generation, 2)?;
    assert_eq!(
        request::classify(&new_generation.state, HOME, &decoded(2, 0)?),
        Classified::Fresh
    );

    let mut other_incarnation = coordinator();
    let original_key = origin_key();
    let mut isolated_key = original_key;
    isolated_key.server_incarnation = [99; 16];
    other_incarnation.state.origin_sequences.insert(
        isolated_key,
        agenc_ircd_storage::e2ee_records::origin::OriginSequenceRow {
            origin_generation: 99,
            next_sequence: 99,
        },
    );
    declare(&mut other_incarnation, 0)?;
    assert_eq!(
        request::classify(&other_incarnation.state, HOME, &decoded(0, 0)?),
        Classified::Fresh
    );
    Ok(())
}
