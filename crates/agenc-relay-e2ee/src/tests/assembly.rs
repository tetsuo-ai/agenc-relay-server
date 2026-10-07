#![forbid(unsafe_code)]

//! Fragment reassembly.

use std::error::Error;

use super::*;
use crate::object::ArcWireObjectKind;
use crate::wire::carrier::DeadlineClass;
use crate::wire::fragment::fragment_object;

type TestResult = Result<(), Box<dyn Error>>;

fn object(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

fn local_key(object_id: ObjectId) -> AssemblyKey {
    AssemblyKey {
        direction: Direction::LocalIngress,
        sender: Sender::Connection {
            connection: 1,
            session_generation: 1,
        },
        command: CarrierCommand::Tagmsg,
        route: [3; 32],
        scope: None,
        object_id,
    }
}

fn remote_key(object_id: ObjectId) -> AssemblyKey {
    AssemblyKey {
        direction: Direction::Remote,
        sender: Sender::Peer([4; 16]),
        command: CarrierCommand::Federation(ArcWireObjectKind::FederationRequest),
        route: [3; 32],
        scope: None,
        object_id,
    }
}

fn scopes() -> QuotaScopes {
    QuotaScopes {
        connection: Some(1),
        account: Some([2; 32]),
        route: Some([3; 32]),
        peer: None,
    }
}

const LIVE: ObjectLimit = ObjectLimit {
    max_bytes: 65_536,
    max_fragments: 90,
    deadline: DeadlineClass::Live,
};

#[test]
fn local_ingress_assembles_in_order_and_verifies_the_hash() -> TestResult {
    let bytes = object(7_000);
    let fragments = fragment_object(&bytes)?;
    let key = local_key(ObjectId::compute(&bytes));
    let mut assembler = E2eeAssembler::default();
    let first = fragments.first().ok_or("fragment")?;
    let second = fragments.get(1).ok_or("fragment")?;
    let third = fragments.get(2).ok_or("fragment")?;
    assert_eq!(
        assembler.ingest(key.clone(), scopes(), LIVE, first, 10)?,
        Ingest::Incomplete
    );
    assert_eq!(assembler.quotas().reserved_bytes(), 7_000);
    assert_eq!(assembler.quotas().open_objects(), 1);
    assert_eq!(
        assembler.ingest(key.clone(), scopes(), LIVE, first, 11)?,
        Ingest::Duplicate
    );
    assert_eq!(
        assembler.ingest(key.clone(), scopes(), LIVE, second, 12)?,
        Ingest::Incomplete
    );
    assert_eq!(
        assembler.ingest(key.clone(), scopes(), LIVE, third, 13)?,
        Ingest::Complete(bytes)
    );
    assert_eq!(assembler.quotas().reserved_bytes(), 0);
    assert_eq!(assembler.open_count(), 0);
    assert!(assembler.is_recent(&key));
    assert_eq!(
        assembler.ingest(key.clone(), scopes(), LIVE, first, 14)?,
        Ingest::Recent
    );
    assembler.expire(13 + 30 * 60);
    assert!(!assembler.is_recent(&key));
    Ok(())
}

#[test]
fn a_recent_object_is_scoped_to_its_direction_and_sender() -> TestResult {
    let bytes = object(100);
    let fragments = fragment_object(&bytes)?;
    let first = fragments.first().ok_or("fragment")?;
    let local = local_key(ObjectId::compute(&bytes));
    let mut assembler = E2eeAssembler::default();
    assert_eq!(
        assembler.ingest(local.clone(), scopes(), LIVE, first, 10)?,
        Ingest::Complete(bytes.clone())
    );
    assert_eq!(
        assembler.ingest(local.clone(), scopes(), LIVE, first, 11)?,
        Ingest::Recent
    );
    // The coordinator delivering the same bytes is a different flow.
    let delivered = AssemblyKey {
        direction: Direction::Response,
        sender: Sender::Peer([9; 16]),
        ..local.clone()
    };
    assert_eq!(
        assembler.ingest(delivered.clone(), scopes(), LIVE, first, 12)?,
        Ingest::Complete(bytes.clone())
    );
    // Deliveries are keyed by position, never by content: the same bytes
    // delivered again assemble again.
    assert!(!assembler.is_recent(&delivered));
    assert_eq!(
        assembler.ingest(delivered, scopes(), LIVE, first, 13)?,
        Ingest::Complete(bytes)
    );
    assert!(assembler.is_recent(&local));
    // The same bytes under another command are a new submission.
    let other_command = AssemblyKey {
        command: CarrierCommand::Federation(ArcWireObjectKind::FederationRequest),
        ..local.clone()
    };
    assert_eq!(
        assembler.ingest(other_command, scopes(), LIVE, first, 14)?,
        Ingest::Complete(object(100))
    );
    Ok(())
}

#[test]
fn a_forgotten_recent_object_assembles_again() -> TestResult {
    let bytes = object(100);
    let fragments = fragment_object(&bytes)?;
    let first = fragments.first().ok_or("fragment")?;
    let request = remote_key(ObjectId::compute(&bytes));
    let declaration = AssemblyKey {
        command: CarrierCommand::Federation(ArcWireObjectKind::FederationOrigin),
        ..request.clone()
    };
    let mut assembler = E2eeAssembler::default();
    for key in [&request, &declaration] {
        assert_eq!(
            assembler.ingest(key.clone(), scopes(), LIVE, first, 10)?,
            Ingest::Complete(bytes.clone())
        );
    }
    // Only the selected submissions are forgotten.
    let forgotten = assembler.forget_recent(|key| key.command == request.command);
    assert_eq!(forgotten, 1);
    assert!(!assembler.is_recent(&request));
    assert!(assembler.is_recent(&declaration));
    assert_eq!(
        assembler.ingest(request.clone(), scopes(), LIVE, first, 11)?,
        Ingest::Complete(bytes)
    );
    assert_eq!(
        assembler.ingest(declaration, scopes(), LIVE, first, 11)?,
        Ingest::Recent
    );
    assert_eq!(assembler.forget_recent(|_| false), 0);
    Ok(())
}

#[test]
fn the_same_object_on_another_route_assembles_as_a_new_submission() -> TestResult {
    let bytes = object(100);
    let fragments = fragment_object(&bytes)?;
    let fragment = fragments.first().ok_or("fragment")?;
    for direction in [Direction::LocalIngress, Direction::Remote] {
        let first = AssemblyKey {
            direction,
            ..local_key(ObjectId::compute(&bytes))
        };
        let second = AssemblyKey {
            route: [99; 32],
            ..first.clone()
        };
        let mut assembler = E2eeAssembler::default();
        assert_eq!(
            assembler.ingest(first.clone(), scopes(), LIVE, fragment, 1)?,
            Ingest::Complete(bytes.clone())
        );
        assert!(!assembler.is_recent(&second));
        assert_eq!(
            assembler.ingest(second.clone(), scopes(), LIVE, fragment, 2)?,
            Ingest::Complete(bytes.clone())
        );
        assert_eq!(
            assembler.ingest(first.clone(), scopes(), LIVE, fragment, 3)?,
            Ingest::Recent
        );
        assert_eq!(
            assembler.ingest(second.clone(), scopes(), LIVE, fragment, 3)?,
            Ingest::Recent
        );
        assembler.expire(1 + 30 * 60);
        assert!(!assembler.is_recent(&first));
        assert!(assembler.is_recent(&second));
    }
    Ok(())
}

#[test]
fn completed_submissions_are_bounded_without_evicting_live_retries() -> TestResult {
    let mut assembler = E2eeAssembler::default();
    let mut first = None;
    for index in 0..MAX_RECENT_OBJECTS {
        let bytes = u64::try_from(index)?.to_be_bytes().to_vec();
        let fragment = fragment_object(&bytes)?
            .into_iter()
            .next()
            .ok_or("fragment")?;
        let key = local_key(ObjectId::compute(&bytes));
        assert_eq!(
            assembler.ingest(key.clone(), scopes(), LIVE, &fragment, 10)?,
            Ingest::Complete(bytes)
        );
        if first.is_none() {
            first = Some((key, fragment));
        }
    }
    let (first_key, first_fragment) = first.ok_or("first completed object")?;
    let extra = fragment_object(b"one more object")?
        .into_iter()
        .next()
        .ok_or("fragment")?;
    let extra_key = local_key(extra.object_id);
    assert_eq!(
        assembler.ingest(extra_key.clone(), scopes(), LIVE, &extra, 11),
        Err(AssemblyError::ReassemblyLimit)
    );
    assert_eq!(assembler.quotas().reserved_bytes(), 0);
    assert_eq!(assembler.open_count(), 0);
    assert_eq!(
        assembler.ingest(first_key.clone(), scopes(), LIVE, &first_fragment, 11)?,
        Ingest::Recent
    );
    // Responses never use the recent cache and still flow at its ceiling.
    let response = AssemblyKey {
        direction: Direction::Response,
        ..extra_key.clone()
    };
    assert_eq!(
        assembler.ingest(response, scopes(), LIVE, &extra, 12)?,
        Ingest::Complete(b"one more object".to_vec())
    );
    assembler.expire(10 + RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS);
    assert!(!assembler.is_recent(&first_key));
    assert_eq!(
        assembler.ingest(
            extra_key,
            scopes(),
            LIVE,
            &extra,
            11 + RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS
        )?,
        Ingest::Complete(b"one more object".to_vec())
    );
    Ok(())
}

#[test]
fn open_submissions_reserve_recent_slots_before_payload_allocation() -> TestResult {
    let mut assembler = E2eeAssembler::default();
    let cached = local_key(ObjectId::compute(b"cached"));
    for index in 0..MAX_RECENT_OBJECTS - 1 {
        let mut key = cached.clone();
        key.sender = Sender::Connection {
            connection: u64::try_from(index)?,
            session_generation: 1,
        };
        assembler.recent.insert(key, 1_000);
    }
    let bytes = object(7_000);
    let fragments = fragment_object(&bytes)?;
    let first = fragments.first().ok_or("fragment")?;
    let key = local_key(ObjectId::compute(&bytes));
    let second = AssemblyKey {
        sender: Sender::Connection {
            connection: 99_999,
            session_generation: 1,
        },
        ..key.clone()
    };
    assert_eq!(
        assembler.ingest(key.clone(), scopes(), LIVE, first, 1)?,
        Ingest::Incomplete
    );
    assert_eq!(
        assembler.ingest(second.clone(), QuotaScopes::default(), LIVE, first, 1),
        Err(AssemblyError::ReassemblyLimit)
    );
    assert_eq!(assembler.quotas().reserved_bytes(), bytes.len());
    assembler.discard(&key);
    assert_eq!(
        assembler.ingest(second, QuotaScopes::default(), LIVE, first, 2)?,
        Ingest::Incomplete
    );
    Ok(())
}

#[test]
fn local_ingress_refuses_out_of_order_and_inconsistent_fragments() -> TestResult {
    let bytes = object(7_000);
    let fragments = fragment_object(&bytes)?;
    let key = local_key(ObjectId::compute(&bytes));
    let first = fragments.first().ok_or("fragment")?;
    let second = fragments.get(1).ok_or("fragment")?;
    let third = fragments.get(2).ok_or("fragment")?;
    let mut assembler = E2eeAssembler::default();
    assert_eq!(
        assembler.ingest(key.clone(), scopes(), LIVE, second, 1),
        Err(AssemblyError::InvalidFragment),
        "fragment zero must come first"
    );
    assert_eq!(assembler.quotas().reserved_bytes(), 0);
    assembler.ingest(key.clone(), scopes(), LIVE, first, 1)?;
    assert_eq!(
        assembler.ingest(key.clone(), scopes(), LIVE, third, 2),
        Err(AssemblyError::InvalidFragment),
        "a gap discards the assembly"
    );
    assert_eq!(assembler.open_count(), 0);
    assert_eq!(assembler.quotas().reserved_bytes(), 0);
    assembler.ingest(key.clone(), scopes(), LIVE, first, 3)?;
    let mut altered = first.clone();
    if let Some(byte) = altered.segment.first_mut() {
        *byte = byte.wrapping_add(1);
    }
    assert_eq!(
        assembler.ingest(key.clone(), scopes(), LIVE, &altered, 4),
        Err(AssemblyError::InvalidFragment),
        "a duplicate index with different bytes"
    );
    assembler.ingest(key.clone(), scopes(), LIVE, first, 5)?;
    let mut other_total = second.clone();
    other_total.total = 7_001;
    assert_eq!(
        assembler.ingest(key.clone(), scopes(), LIVE, &other_total, 6),
        Err(AssemblyError::InvalidFragment),
        "the pinned total"
    );
    let mut other_id = first.clone();
    other_id.object_id = ObjectId::from_bytes([1; 32]);
    assert_eq!(
        assembler.ingest(key, scopes(), LIVE, &other_id, 7),
        Err(AssemblyError::InvalidFragment)
    );
    Ok(())
}

#[test]
fn a_hash_mismatch_discards_the_object_after_release() -> TestResult {
    let bytes = object(100);
    let mut fragments = fragment_object(&bytes)?;
    let key = local_key(ObjectId::compute(&bytes));
    let fragment = fragments.first_mut().ok_or("fragment")?;
    if let Some(byte) = fragment.segment.last_mut() {
        *byte ^= 0xff;
    }
    let mut assembler = E2eeAssembler::default();
    assert_eq!(
        assembler.ingest(key.clone(), scopes(), LIVE, fragment, 1),
        Err(AssemblyError::HashMismatch)
    );
    assert_eq!(assembler.quotas().reserved_bytes(), 0);
    assert!(!assembler.is_recent(&key));
    assert_eq!(
        AssemblyError::HashMismatch.reply_code(),
        E2eeReplyCode::HashMismatch
    );
    assert_eq!(
        AssemblyError::ObjectTooLarge.reply_code(),
        E2eeReplyCode::ObjectTooLarge
    );
    assert_eq!(
        AssemblyError::ReassemblyLimit.reply_code(),
        E2eeReplyCode::ReassemblyLimit
    );
    assert_eq!(
        AssemblyError::InvalidFragment.reply_code(),
        E2eeReplyCode::InvalidFragment
    );
    Ok(())
}

#[test]
fn limits_are_checked_before_any_reservation() -> TestResult {
    let bytes = object(65_537);
    let fragments = fragment_object(&bytes)?;
    let first = fragments.first().ok_or("fragment")?;
    let key = local_key(ObjectId::compute(&bytes));
    let mut assembler = E2eeAssembler::default();
    assert_eq!(
        assembler.ingest(key, scopes(), LIVE, first, 1),
        Err(AssemblyError::ObjectTooLarge)
    );
    assert_eq!(assembler.quotas().reserved_bytes(), 0);
    let small = ObjectLimit {
        max_fragments: 2,
        ..LIVE
    };
    let bytes = object(9_000);
    let fragments = fragment_object(&bytes)?;
    let first = fragments.first().ok_or("fragment")?;
    assert_eq!(
        assembler.ingest(
            local_key(ObjectId::compute(&bytes)),
            scopes(),
            small,
            first,
            1
        ),
        Err(AssemblyError::ObjectTooLarge)
    );
    Ok(())
}

#[test]
fn one_open_object_per_local_sender_and_quotas_per_scope() -> TestResult {
    let first_object = object(6_000);
    let second_object = object(6_001);
    let first = fragment_object(&first_object)?;
    let second = fragment_object(&second_object)?;
    let mut assembler = E2eeAssembler::default();
    assembler.ingest(
        local_key(ObjectId::compute(&first_object)),
        scopes(),
        LIVE,
        first.first().ok_or("fragment")?,
        1,
    )?;
    assert_eq!(
        assembler.ingest(
            local_key(ObjectId::compute(&second_object)),
            scopes(),
            LIVE,
            second.first().ok_or("fragment")?,
            1
        ),
        Err(AssemblyError::ReassemblyLimit)
    );
    let sender = Sender::Connection {
        connection: 1,
        session_generation: 1,
    };
    assert_eq!(assembler.discard_sender(&sender), 1);
    assert_eq!(assembler.quotas().reserved_bytes(), 0);
    let limits = QuotaLimits {
        account: (2, 100_000),
        route: (64, 6_500),
        ..QuotaLimits::default()
    };
    let mut assembler = E2eeAssembler::new(limits);
    let mut remote = remote_key(ObjectId::compute(&first_object));
    assembler.ingest(
        remote.clone(),
        scopes(),
        LIVE,
        first.first().ok_or("fragment")?,
        1,
    )?;
    remote.object_id = ObjectId::compute(&second_object);
    assert_eq!(
        assembler.ingest(remote, scopes(), LIVE, second.first().ok_or("fragment")?, 1),
        Err(AssemblyError::ReassemblyLimit),
        "route bytes"
    );
    let other_route = QuotaScopes {
        route: Some([9; 32]),
        ..scopes()
    };
    let third_object = object(6_002);
    let third = fragment_object(&third_object)?;
    assembler.ingest(
        remote_key(ObjectId::compute(&third_object)),
        other_route,
        LIVE,
        third.first().ok_or("fragment")?,
        1,
    )?;
    let fourth_object = object(6_003);
    let fourth = fragment_object(&fourth_object)?;
    assert_eq!(
        assembler.ingest(
            remote_key(ObjectId::compute(&fourth_object)),
            QuotaScopes {
                route: Some([10; 32]),
                ..scopes()
            },
            LIVE,
            fourth.first().ok_or("fragment")?,
            1
        ),
        Err(AssemblyError::ReassemblyLimit),
        "account open objects"
    );
    Ok(())
}

#[test]
fn remote_assembly_tolerates_any_order_and_expires_by_deadline() -> TestResult {
    let bytes = object(7_000);
    let fragments = fragment_object(&bytes)?;
    let key = remote_key(ObjectId::compute(&bytes));
    let mut assembler = E2eeAssembler::default();
    let peer = QuotaScopes {
        peer: Some([4; 16]),
        ..QuotaScopes::default()
    };
    assembler.ingest(
        key.clone(),
        peer,
        LIVE,
        fragments.get(2).ok_or("fragment")?,
        1,
    )?;
    assembler.ingest(
        key.clone(),
        peer,
        LIVE,
        fragments.first().ok_or("fragment")?,
        2,
    )?;
    assert_eq!(
        assembler.ingest(
            key.clone(),
            peer,
            LIVE,
            fragments.get(1).ok_or("fragment")?,
            3
        )?,
        Ingest::Complete(bytes.clone())
    );
    let mut assembler = E2eeAssembler::default();
    assembler.ingest(
        key.clone(),
        peer,
        LIVE,
        fragments.first().ok_or("fragment")?,
        100,
    )?;
    assert!(assembler.expire(114).is_empty());
    assert_eq!(assembler.expire(115), vec![key.clone()]);
    assert_eq!(assembler.quotas().reserved_bytes(), 0);
    assembler.ingest(
        key.clone(),
        peer,
        LIVE,
        fragments.first().ok_or("fragment")?,
        200,
    )?;
    assembler.ingest(
        key.clone(),
        peer,
        LIVE,
        fragments.get(1).ok_or("fragment")?,
        210,
    )?;
    assert_eq!(
        assembler.ingest(
            key.clone(),
            peer,
            LIVE,
            fragments.get(2).ok_or("fragment")?,
            330
        ),
        Err(AssemblyError::ReassemblyLimit),
        "absolute deadline"
    );
    assert_eq!(assembler.open_count(), 0);
    Ok(())
}

/// Completes one single-fragment object from `sender` keyed by `index`.
fn complete_from(
    assembler: &mut E2eeAssembler,
    sender: [u8; 16],
    index: usize,
    now: u64,
) -> Result<(AssemblyKey, Ingest), Box<dyn Error>> {
    let bytes = u64::try_from(index)?.to_be_bytes().to_vec();
    let fragment = fragment_object(&bytes)?
        .into_iter()
        .next()
        .ok_or("fragment")?;
    let key = AssemblyKey {
        sender: Sender::Peer(sender),
        ..remote_key(ObjectId::compute(&bytes))
    };
    let peer = QuotaScopes {
        peer: Some(sender),
        ..QuotaScopes::default()
    };
    let outcome = assembler.ingest(key.clone(), peer, LIVE, &fragment, now)?;
    Ok((key, outcome))
}

#[test]
fn a_per_sender_ceiling_assembles_past_it_without_a_recent_tuple() -> TestResult {
    let mut assembler =
        E2eeAssembler::with_ceiling(QuotaLimits::default(), RecentCeiling::PerSender);
    for index in 0..MAX_RECENT_OBJECTS {
        let (key, outcome) = complete_from(&mut assembler, [4; 16], index, 10)?;
        assert!(matches!(outcome, Ingest::Complete(_)));
        assert!(assembler.is_recent(&key));
    }
    // Past its sender's ceiling an object still completes, keeps no tuple
    // and holds no reservation.
    let (past, outcome) = complete_from(&mut assembler, [4; 16], MAX_RECENT_OBJECTS, 11)?;
    assert!(matches!(outcome, Ingest::Complete(_)));
    assert!(!assembler.is_recent(&past));
    assert_eq!(assembler.quotas().reserved_bytes(), 0);
    let (again, outcome) = complete_from(&mut assembler, [4; 16], MAX_RECENT_OBJECTS, 12)?;
    assert_eq!(again, past);
    assert!(matches!(outcome, Ingest::Complete(_)), "it assembles again");
    // Another sender keeps its own ceiling.
    let (other, outcome) = complete_from(&mut assembler, [5; 16], 0, 12)?;
    assert!(matches!(outcome, Ingest::Complete(_)));
    assert!(assembler.is_recent(&other));
    // The shared ceiling still refuses before any reservation.
    let mut shared = E2eeAssembler::default();
    for index in 0..MAX_RECENT_OBJECTS {
        let _completed = complete_from(&mut shared, [4; 16], index, 10)?;
    }
    let refused = complete_from(&mut shared, [5; 16], MAX_RECENT_OBJECTS, 11);
    assert!(refused.is_err());
    assert_eq!(shared.quotas().reserved_bytes(), 0);
    Ok(())
}

#[test]
fn an_open_submission_reserves_its_senders_slot() -> TestResult {
    let mut assembler =
        E2eeAssembler::with_ceiling(QuotaLimits::default(), RecentCeiling::PerSender);
    for index in 0..MAX_RECENT_OBJECTS - 1 {
        let _completed = complete_from(&mut assembler, [4; 16], index, 10)?;
    }
    // The last slot goes to the first of two open objects of the sender.
    let bytes = object(7_000);
    let fragments = fragment_object(&bytes)?;
    let first = fragments.first().ok_or("fragment")?;
    let open = AssemblyKey {
        sender: Sender::Peer([4; 16]),
        ..remote_key(ObjectId::compute(&bytes))
    };
    let second = AssemblyKey {
        route: [8; 32],
        ..open.clone()
    };
    assert_eq!(
        assembler.ingest(open.clone(), QuotaScopes::default(), LIVE, first, 11)?,
        Ingest::Incomplete
    );
    assert_eq!(
        assembler.ingest(second.clone(), QuotaScopes::default(), LIVE, first, 11)?,
        Ingest::Incomplete
    );
    for fragment in fragments.iter().skip(1) {
        let _open = assembler.ingest(open.clone(), QuotaScopes::default(), LIVE, fragment, 12)?;
        let _second =
            assembler.ingest(second.clone(), QuotaScopes::default(), LIVE, fragment, 12)?;
    }
    assert!(assembler.is_recent(&open));
    assert!(!assembler.is_recent(&second));
    Ok(())
}

#[test]
fn expiring_recent_objects_releases_their_slots_and_keeps_open_assemblies() -> TestResult {
    let mut assembler =
        E2eeAssembler::with_ceiling(QuotaLimits::default(), RecentCeiling::PerSender);
    let mut first = None;
    for index in 0..MAX_RECENT_OBJECTS {
        let (key, _) = complete_from(&mut assembler, [4; 16], index, 10)?;
        first.get_or_insert(key);
    }
    let first = first.ok_or("first object")?;
    let bytes = object(7_000);
    let fragments = fragment_object(&bytes)?;
    let open = AssemblyKey {
        sender: Sender::Peer([6; 16]),
        ..remote_key(ObjectId::compute(&bytes))
    };
    assert_eq!(
        assembler.ingest(
            open.clone(),
            QuotaScopes::default(),
            LIVE,
            fragments.first().ok_or("fragment")?,
            10
        )?,
        Ingest::Incomplete
    );
    let ends = 10 + RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS;
    assert_eq!(assembler.expire_recent(ends - 1), 0);
    assert!(assembler.is_recent(&first));
    assert_eq!(assembler.expire_recent(ends), MAX_RECENT_OBJECTS);
    assert!(!assembler.is_recent(&first));
    assert_eq!(assembler.open_count(), 1, "open assemblies are left alone");
    let (key, outcome) = complete_from(&mut assembler, [4; 16], MAX_RECENT_OBJECTS, ends)?;
    assert!(matches!(outcome, Ingest::Complete(_)));
    assert!(assembler.is_recent(&key), "the sender records again");
    Ok(())
}

#[test]
fn forgetting_one_object_releases_its_senders_slot() -> TestResult {
    let mut assembler =
        E2eeAssembler::with_ceiling(QuotaLimits::default(), RecentCeiling::PerSender);
    let mut first = None;
    for index in 0..MAX_RECENT_OBJECTS {
        let (key, _) = complete_from(&mut assembler, [4; 16], index, 10)?;
        first.get_or_insert(key);
    }
    let first = first.ok_or("first object")?;
    assert!(assembler.forget(&first));
    assert!(!assembler.forget(&first), "forgotten once");
    let (key, _) = complete_from(&mut assembler, [4; 16], MAX_RECENT_OBJECTS, 11)?;
    assert!(assembler.is_recent(&key));
    let (past, _) = complete_from(&mut assembler, [4; 16], MAX_RECENT_OBJECTS + 1, 11)?;
    assert!(!assembler.is_recent(&past));
    assert_eq!(
        assembler.forget_recent(|key| key.sender == Sender::Peer([4; 16])),
        MAX_RECENT_OBJECTS
    );
    let (again, _) = complete_from(&mut assembler, [4; 16], MAX_RECENT_OBJECTS + 1, 12)?;
    assert!(assembler.is_recent(&again));
    Ok(())
}
