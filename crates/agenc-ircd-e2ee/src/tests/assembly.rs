#![forbid(unsafe_code)]

//! Fragment reassembly.

use std::error::Error;

use super::*;
use crate::object::IrcWireObjectKind;
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
        command: CarrierCommand::Federation(IrcWireObjectKind::FederationRequest),
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
    assert!(assembler.is_recent(key.direction, key.sender, key.command, &key.object_id));
    assert_eq!(
        assembler.ingest(key.clone(), scopes(), LIVE, first, 14)?,
        Ingest::Recent
    );
    assembler.expire(13 + 30 * 60);
    assert!(!assembler.is_recent(key.direction, key.sender, key.command, &key.object_id));
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
    assert!(!assembler.is_recent(
        delivered.direction,
        delivered.sender,
        delivered.command,
        &delivered.object_id
    ));
    assert_eq!(
        assembler.ingest(delivered, scopes(), LIVE, first, 13)?,
        Ingest::Complete(bytes)
    );
    assert!(assembler.is_recent(
        local.direction,
        local.sender,
        local.command,
        &local.object_id
    ));
    // The same bytes under another command are a new submission.
    let other_command = AssemblyKey {
        command: CarrierCommand::Federation(IrcWireObjectKind::FederationRequest),
        ..local.clone()
    };
    assert_eq!(
        assembler.ingest(other_command, scopes(), LIVE, first, 14)?,
        Ingest::Complete(object(100))
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
    assert!(!assembler.is_recent(key.direction, key.sender, key.command, &key.object_id));
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
