#![forbid(unsafe_code)]

//! E2EE ingress admission (companion 16, ENC-16): fragment zero pays the
//! line and the verification, its continuation fragments pay decoded bytes
//! through the dedicated account-and-device bucket, and a fragment behind no
//! accepted fragment zero is a command line again that the router refuses.

use agenc_relay_client_wire::{
    CapabilityProfile, CapabilitySpec, CapabilityState, FramedLine, ParsedMessage, parse_message,
};
use agenc_relay_e2ee::limits::{
    MAX_LIVE_OBJECT, MAX_SEQUENCER_RECORD_OBJECT, MIN_ADMITTED_E2EE_INGRESS_RATE,
};
use agenc_relay_e2ee::wire::command::EkeyCommand;
use agenc_relay_e2ee::wire::fragment::{FragmentTag, fragment_object};
use agenc_relay_types::{AccountId, AccountRandomId, MonotonicTick, UserId};

use super::projection::base_edge;
use super::*;
use crate::admission::{
    BucketDemand, BucketKey, BucketKind, BucketTable, E2EE_INGRESS_BURST_BYTES, RateLimits,
};
use crate::budget::MemoryBudget;
use crate::e2ee::edge::{IngressCharge, SessionFacts};
use crate::sync::Arc;
use crate::test_support::StateCoreFixture;

const USER: UserId = UserId::from_bytes([18; 16]);
const DEVICE: [u8; 16] = [7; 16];

fn account_id() -> AccountId {
    AccountId::from_random(AccountRandomId::from_bytes([40; 16]))
}

fn capabilities() -> TestResult<CapabilityState> {
    let names = [
        "message-tags",
        "echo-message",
        "batch",
        "labeled-response",
        "standard-replies",
        "account-tag",
    ];
    let mut specs = names
        .iter()
        .map(|name| CapabilitySpec::new(name, None))
        .collect::<Result<Vec<_>, _>>()?;
    specs.push(CapabilitySpec::new(
        "agenc.ag/e2ee-mls",
        Some(agenc_relay_e2ee::limits::CAPABILITY_VALUE),
    )?);
    let profile = CapabilityProfile::new(specs)?;
    let mut state = CapabilityState::default();
    let _reply = state.request(&format!("{} agenc.ag/e2ee-mls", names.join(" ")), &profile)?;
    Ok(state)
}

fn buckets() -> BucketTable {
    BucketTable::new(RateLimits::defaults(), Arc::new(MemoryBudget::new(1 << 20)))
}

/// One fragment of an `EKEY PUBLISH IDENTITY` submission as a client line.
fn line(fragment: &FragmentTag) -> TestResult<ParsedMessage> {
    let text = format!(
        "@+agenc.ag/e2ee={} EKEY PUBLISH IDENTITY",
        fragment.render()
    );
    Ok(parse_message(FramedLine::new(&text)?)?.ok_or("message")?)
}

/// An active edge whose one connection holds a settled, attached origin.
fn active_edge(generation: ConnectionGeneration) -> TestResult<E2eeEdge> {
    let mut edge = edge();
    edge.phase = Phase::Active;
    let mut settled = origin([5; 16], 1, 0);
    settled.acked = Some(1);
    settled.account = Some(account_id().to_text().as_bytes().try_into()?);
    settled.device = Some((DEVICE, 1));
    edge.origins.insert(generation, settled);
    Ok(edge)
}

/// What one bucket of `table` still holds at tick zero.
fn left(table: &mut BucketTable, kind: BucketKind, key: BucketKey) -> u64 {
    table.available(MonotonicTick::from_ticks(0), kind, key)
}

#[tokio::test]
async fn one_object_costs_one_line_one_verification_and_its_continuation_bytes() -> TestResult {
    let generation = ConnectionGeneration::new(1);
    let mut core = StateCoreFixture::new(vec![0; 4_096])?;
    let mut base = base_edge();
    let mut edge = active_edge(generation)?;
    let capabilities = capabilities()?;
    let account = account_id().to_text().as_bytes().try_into()?;
    let facts = SessionFacts {
        user_id: USER,
        account: Some(account),
        capabilities: &capabilities,
        nickname: "Sender",
    };
    let object = vec![0xa5; 2 * 2_940 + 100];
    let fragments = fragment_object(&object)?;
    assert_eq!(fragments.len(), 3);
    let mut table = buckets();
    let now = MonotonicTick::from_ticks(0);
    for fragment in &fragments {
        let message = line(fragment)?;
        let charge = edge.ingress_charge(generation, &message);
        let expected = if fragment.part == 0 {
            IngressCharge::Command {
                carries_object: true,
            }
        } else {
            IngressCharge::Continuation {
                device: DEVICE,
                decoded_bytes: u64::try_from(fragment.segment.len())?,
            }
        };
        assert_eq!(charge, expected, "fragment {}", fragment.part);
        table
            .charge_all_or_nothing(now, &charge.demands(USER, Some(account_id()))?)
            .map_err(|_| "admission refused an object inside every burst")?;
        let outputs =
            edge.client_line(core.context_mut()?, &mut base, generation, &message, &facts);
        // Only the completed object reaches the (absent) coordinator link.
        assert_eq!(outputs.is_empty(), !fragment.is_final());
    }
    assert_eq!(
        left(
            &mut table,
            BucketKind::E2eeCommand,
            BucketKey::Session(USER)
        ),
        19,
        "one object is one command line"
    );
    assert_eq!(
        left(
            &mut table,
            BucketKind::E2eeSignature,
            BucketKey::Account(account_id())
        ),
        1_023,
        "one object is one signature verification"
    );
    assert_eq!(
        left(
            &mut table,
            BucketKind::E2eeIngress,
            BucketKey::AccountDevice(account_id(), DEVICE)
        ),
        E2EE_INGRESS_BURST_BYTES - 2_940 - 100,
        "continuation fragments pay their decoded bytes"
    );
    Ok(())
}

#[tokio::test]
async fn a_continuation_behind_no_accepted_fragment_zero_is_refused_as_a_command_line() -> TestResult
{
    let generation = ConnectionGeneration::new(1);
    let mut core = StateCoreFixture::new(vec![0; 4_096])?;
    let mut base = base_edge();
    let mut edge = active_edge(generation)?;
    let capabilities = capabilities()?;
    let facts = SessionFacts {
        user_id: USER,
        account: Some(account_id().to_text().as_bytes().try_into()?),
        capabilities: &capabilities,
        nickname: "Sender",
    };
    let object = vec![0x5a; 2 * 2_940];
    let orphan = fragment_object(&object)?.pop().ok_or("fragment one")?;
    assert_eq!(orphan.part, 1);
    let message = line(&orphan)?;
    // No fragment zero was admitted: the line rides no byte bucket.
    assert_eq!(
        edge.ingress_charge(generation, &message),
        IngressCharge::Command {
            carries_object: true
        }
    );
    let outputs = edge.client_line(core.context_mut()?, &mut base, generation, &message, &facts);
    let frame = outputs
        .first()
        .and_then(|output| output.frames.first())
        .ok_or("a refusal")?;
    assert_eq!(frame.command(), "FAIL");
    assert!(
        frame
            .middle()
            .iter()
            .any(|value| value == "E2EE_INVALID_FRAGMENT")
    );
    assert!(edge.ingress.is_empty());
    // Another connection's admitted fragment zero entitles this one to nothing.
    let other = ConnectionGeneration::new(2);
    let mut settled = origin([6; 16], 1, 0);
    settled.acked = Some(1);
    settled.account = Some(account_id().to_text().as_bytes().try_into()?);
    edge.origins.insert(other, settled);
    let zero = fragment_object(&object)?
        .into_iter()
        .next()
        .ok_or("fragment zero")?;
    assert!(
        edge.client_line(core.context_mut()?, &mut base, other, &line(&zero)?, &facts)
            .is_empty()
    );
    assert!(matches!(
        edge.ingress_charge(other, &message),
        IngressCharge::Continuation { device, .. } if device == [0; 16]
    ));
    assert_eq!(
        edge.ingress_charge(generation, &message),
        IngressCharge::Command {
            carries_object: true
        }
    );
    Ok(())
}

#[tokio::test]
async fn the_duplicate_fragments_of_a_retried_object_ride_the_byte_bucket() -> TestResult {
    let generation = ConnectionGeneration::new(1);
    let mut core = StateCoreFixture::new(vec![0; 4_096])?;
    let mut base = base_edge();
    let mut edge = active_edge(generation)?;
    let capabilities = capabilities()?;
    let facts = SessionFacts {
        user_id: USER,
        account: Some(account_id().to_text().as_bytes().try_into()?),
        capabilities: &capabilities,
        nickname: "Sender",
    };
    let object = vec![0x3c; 2 * 2_940];
    let fragments = fragment_object(&object)?;
    let [zero, one] = fragments.as_slice() else {
        return Err("two fragments".into());
    };
    // The object completed earlier on this connection and its reply stands.
    let command = Resolved::Command(ClientCommand::Ekey(EkeyCommand::PublishIdentity));
    let scope = crate::e2ee::edge::router::request_scope(&command)
        .map_err(|refusal| refusal.code.to_string())?;
    let mut answered = pending(1, 0, true);
    answered.command = command;
    answered.reply_key = Some((generation.get(), 1, *zero.object_id.as_bytes(), scope));
    reserve_reply(&mut answered)?;
    edge.replies
        .remember(
            &mut answered,
            vec![":edge.example EKEY STORED".to_owned()],
            0,
        )
        .map_err(|refusal| refusal.code.to_string())?;
    assert_eq!(
        edge.ingress_charge(generation, &line(one)?),
        IngressCharge::Command {
            carries_object: true
        },
        "before its fragment zero is answered a duplicate is an orphan"
    );
    let replayed = edge.client_line(
        core.context_mut()?,
        &mut base,
        generation,
        &line(zero)?,
        &facts,
    );
    assert_eq!(replayed.len(), 1);
    assert!(matches!(
        edge.ingress_charge(generation, &line(one)?),
        IngressCharge::Continuation {
            decoded_bytes: 2_940,
            ..
        }
    ));
    // The next fragment zero ends the retry.
    let next = fragment_object(&[0x11; 2 * 2_940])?
        .into_iter()
        .next()
        .ok_or("fragment zero")?;
    let _opened = edge.client_line(
        core.context_mut()?,
        &mut base,
        generation,
        &line(&next)?,
        &facts,
    );
    assert_eq!(
        edge.ingress_charge(generation, &line(one)?),
        IngressCharge::Command {
            carries_object: true
        }
    );
    Ok(())
}

/// Seconds a complete object of `total` bytes needs to pass the dedicated
/// bucket when every continuation is sent as soon as it is admitted.
fn seconds_to_admit(total: usize) -> TestResult<u64> {
    let mut table = buckets();
    let key = BucketKey::AccountDevice(account_id(), DEVICE);
    let mut seconds = 0_u64;
    let object = vec![0; total];
    for fragment in fragment_object(&object)?.iter().skip(1) {
        let demand = BucketDemand::new(
            BucketKind::E2eeIngress,
            key,
            u64::try_from(fragment.segment.len())?,
        )?;
        while table
            .charge_all_or_nothing(MonotonicTick::from_ticks(seconds * 1_000), &[demand])
            .is_err()
        {
            seconds += 1;
        }
    }
    // Continuations never touch the line or the verification bucket.
    assert_eq!(
        left(
            &mut table,
            BucketKind::E2eeCommand,
            BucketKey::Session(USER)
        ),
        20
    );
    Ok(seconds)
}

#[test]
fn a_maximum_size_object_completes_at_no_less_than_the_floor_rate() -> TestResult {
    assert_eq!(
        E2EE_INGRESS_BURST_BYTES,
        u64::try_from(MAX_LIVE_OBJECT)?,
        "one live object is the burst"
    );
    assert_eq!(
        BucketKind::E2eeIngress.default_rate().refill_tokens(),
        MIN_ADMITTED_E2EE_INGRESS_RATE
    );
    assert_eq!(
        BucketKind::E2eeIngress.hard_rate(),
        BucketKind::E2eeIngress.default_rate(),
        "the floor is not operator configurable"
    );
    // A live object is never paced by its own size.
    assert_eq!(seconds_to_admit(MAX_LIVE_OBJECT)?, 0);
    // The largest control object: 1,427 fragments.
    let total = MAX_SEQUENCER_RECORD_OBJECT;
    let seconds = seconds_to_admit(total)?;
    let floor = u64::try_from(total)? / MIN_ADMITTED_E2EE_INGRESS_RATE;
    assert!(
        seconds <= floor,
        "{total} bytes took {seconds}s, above the {floor}s the floor rate allows"
    );
    // The per-line model this replaces needed (1,427 - 20) / 4 seconds.
    assert!(seconds < (1_427 - 20) / 4);
    Ok(())
}

#[tokio::test]
async fn a_command_that_needs_a_device_is_refused_before_attachment() -> TestResult {
    let generation = ConnectionGeneration::new(1);
    let mut core = StateCoreFixture::new(vec![0; 4_096])?;
    let mut base = base_edge();
    let mut edge = active_edge(generation)?;
    if let Some(origin) = edge.origins.get_mut(&generation) {
        origin.device = None;
    }
    let capabilities = capabilities()?;
    let facts = SessionFacts {
        user_id: USER,
        account: Some(account_id().to_text().as_bytes().try_into()?),
        capabilities: &capabilities,
        nickname: "Sender",
    };
    let message = parse_message(FramedLine::new("EKEY CLAIM STATUS AAAAAAAAAAAAAAAAAAAAAA")?)?
        .ok_or("message")?;
    let outputs = edge.client_line(core.context_mut()?, &mut base, generation, &message, &facts);
    let frame = outputs
        .first()
        .and_then(|output| output.frames.first())
        .ok_or("a refusal")?;
    assert_eq!(frame.command(), "FAIL");
    assert!(
        frame
            .middle()
            .iter()
            .any(|value| value == "E2EE_DEVICE_REQUIRED"),
        "{:?}",
        frame.middle()
    );
    assert!(edge.pending.is_empty());
    Ok(())
}

/// The facts of one session authenticated as the test account.
fn facts<'a>(capabilities: &'a CapabilityState) -> TestResult<SessionFacts<'a>> {
    Ok(SessionFacts {
        user_id: USER,
        account: Some(account_id().to_text().as_bytes().try_into()?),
        capabilities,
        nickname: "Sender",
    })
}

/// The carrier of an `EKEY PUBLISH IDENTITY` object.
fn identity_carrier() -> TestResult<agenc_relay_e2ee::wire::carrier::CarrierCommand> {
    Ok(super::super::router::Resolved::Command(
        agenc_relay_e2ee::wire::command::ClientCommand::Ekey(EkeyCommand::PublishIdentity),
    )
    .carrier()
    .ok_or("carrier")?)
}

/// The assembly tuple of an `EKEY PUBLISH IDENTITY` object of `generation`
/// under the test attachment.
fn identity_tuple(
    generation: ConnectionGeneration,
    fragment: &FragmentTag,
) -> TestResult<agenc_relay_e2ee::wire::assembly::AssemblyKey> {
    let command = super::super::router::Resolved::Command(
        agenc_relay_e2ee::wire::command::ClientCommand::Ekey(EkeyCommand::PublishIdentity),
    );
    let carrier = identity_carrier()?;
    let scope = super::super::router::request_scope(&command).map_err(|e| e.code.to_string())?;
    Ok(super::super::router::submission_key(
        (generation.get(), 1, *fragment.object_id.as_bytes(), scope),
        carrier,
    ))
}

/// An `EKEY PUBLISH IDENTITY` payload of `total` encoded bytes: a wire
/// object of the kind the command carries, filled with `fill`.
fn identity_object(total: usize, fill: u8) -> TestResult<Vec<u8>> {
    use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
    use agenc_relay_e2ee::tls::TlsEncode;
    Ok(ArcWireObject::new(ArcWireObjectKind::RootIdentity, vec![fill; total - 6])?.encode()?)
}

fn refused_with(outputs: &[super::super::ClientOutput], code: &str) -> bool {
    outputs.iter().any(|output| {
        output
            .frames
            .iter()
            .any(|frame| frame.middle().iter().any(|parameter| parameter == code))
    })
}

/// Each connection holds its own share of the recent-object cache (companion
/// 16: storage at the ceiling is refused fairly): a connection past its
/// share is refused before any reservation, and another connection's
/// submission is still admitted.
#[tokio::test]
async fn a_connection_past_its_recent_share_leaves_the_others_admitted() -> TestResult {
    use agenc_relay_e2ee::wire::assembly::{Ingest, MAX_RECENT_OBJECTS, QuotaScopes};
    let (first, second) = (ConnectionGeneration::new(1), ConnectionGeneration::new(2));
    let mut core = StateCoreFixture::new(vec![0; 4_096])?;
    let mut base = base_edge();
    let mut edge = active_edge(first)?;
    let settled = edge.origins.get(&first).cloned().ok_or("origin")?;
    edge.origins.insert(second, settled);
    let capabilities = capabilities()?;
    let facts = facts(&capabilities)?;
    for index in 0..MAX_RECENT_OBJECTS {
        let bytes = u64::try_from(index)?.to_be_bytes().to_vec();
        let fragment = fragment_object(&bytes)?
            .into_iter()
            .next()
            .ok_or("fragment")?;
        let tuple = identity_tuple(first, &fragment)?;
        let completed = edge.assembler.ingest(
            tuple,
            QuotaScopes::default(),
            identity_carrier()?.limit(),
            &fragment,
            0,
        )?;
        assert!(matches!(completed, Ingest::Complete(_)));
    }
    let object = vec![0xa5; 100];
    let fragment = fragment_object(&object)?
        .into_iter()
        .next()
        .ok_or("fragment")?;
    let message = line(&fragment)?;
    let refused = edge.client_line(core.context_mut()?, &mut base, first, &message, &facts);
    assert!(
        refused_with(&refused, "E2EE_REASSEMBLY_LIMIT"),
        "{refused:?}"
    );
    assert!(!edge.assembler.is_recent(&identity_tuple(first, &fragment)?));
    let admitted = edge.client_line(core.context_mut()?, &mut base, second, &message, &facts);
    assert!(
        !refused_with(&admitted, "E2EE_REASSEMBLY_LIMIT"),
        "{admitted:?}"
    );
    assert!(
        edge.assembler
            .is_recent(&identity_tuple(second, &fragment)?)
    );
    assert_eq!(edge.assembler.quotas().reserved_bytes(), 0);
    Ok(())
}

/// A completed submission refused before it went out keeps no recent-object
/// tuple, so its retry is admitted again rather than refused as a duplicate.
#[tokio::test]
async fn a_submission_refused_before_it_is_sent_releases_its_recent_tuple() -> TestResult {
    let generation = ConnectionGeneration::new(1);
    let mut core = StateCoreFixture::new(vec![0; 4_096])?;
    let mut base = base_edge();
    let mut edge = active_edge(generation)?;
    let capabilities = capabilities()?;
    let facts = facts(&capabilities)?;
    let object = vec![0xa5; 2 * 2_940 + 100];
    let fragments = fragment_object(&object)?;
    let first = fragments.first().ok_or("fragment")?;
    let opened = edge.client_line(
        core.context_mut()?,
        &mut base,
        generation,
        &line(first)?,
        &facts,
    );
    assert!(opened.is_empty(), "{opened:?}");
    // While the object assembles, the connection's reply quota fills with
    // kept replies.
    let mut request = pending(1, 0, true);
    for index in 0..u32::try_from(super::super::retry::CONNECTION_REPLIES)? {
        let mut object_id = [0; 32];
        object_id
            .get_mut(..4)
            .ok_or("object")?
            .copy_from_slice(&index.to_be_bytes());
        request.reply_key = Some((1, 7, object_id, [7; 32]));
        reserve_reply(&mut request)?;
        edge.replies
            .remember(
                &mut request,
                vec![":edge.example EKEY STORED IDENTITY x".to_owned()],
                0,
            )
            .map_err(|e| e.code.to_string())?;
    }
    let mut refused = Vec::new();
    for fragment in fragments.iter().skip(1) {
        refused = edge.client_line(
            core.context_mut()?,
            &mut base,
            generation,
            &line(fragment)?,
            &facts,
        );
    }
    assert!(refused_with(&refused, "E2EE_RATE_LIMITED"), "{refused:?}");
    assert!(edge.pending.is_empty());
    assert!(
        !edge
            .assembler
            .is_recent(&identity_tuple(generation, first)?),
        "the refused submission keeps no tuple"
    );
    Ok(())
}

/// A closed connection's recent submissions and its open one leave the
/// cache with it.
#[tokio::test]
async fn a_closed_connection_forgets_its_recent_submissions() -> TestResult {
    use agenc_relay_e2ee::wire::assembly::{Ingest, QuotaScopes};
    let generation = ConnectionGeneration::new(1);
    let mut core = StateCoreFixture::new(vec![0; 4_096])?;
    let mut base = base_edge();
    let mut edge = active_edge(generation)?;
    let capabilities = capabilities()?;
    let facts = facts(&capabilities)?;
    let fragment = fragment_object(&[0xa5; 100])?
        .into_iter()
        .next()
        .ok_or("fragment")?;
    let tuple = identity_tuple(generation, &fragment)?;
    let other = identity_tuple(ConnectionGeneration::new(2), &fragment)?;
    for key in [&tuple, &other] {
        let completed = edge.assembler.ingest(
            key.clone(),
            QuotaScopes::default(),
            identity_carrier()?.limit(),
            &fragment,
            0,
        )?;
        assert!(matches!(completed, Ingest::Complete(_)));
    }
    let large = fragment_object(&vec![0x5a; 2 * 2_940 + 100])?;
    let opening = line(large.first().ok_or("fragment")?)?;
    let opened = edge.client_line(core.context_mut()?, &mut base, generation, &opening, &facts);
    assert!(opened.is_empty(), "{opened:?}");
    assert_eq!(edge.assembler.open_count(), 1);
    edge.connection_closed(generation);
    assert!(!edge.assembler.is_recent(&tuple));
    assert_eq!(edge.assembler.open_count(), 0);
    assert!(
        edge.assembler.is_recent(&other),
        "another connection's stays"
    );
    Ok(())
}

/// Outstanding requests are bounded per connection, per account and for
/// the edge (companion 16): a connection past its own bound, or an account
/// past its own over its connections, is refused, while another account's
/// connection is still admitted until the edge's bound.
#[tokio::test]
async fn outstanding_requests_are_bounded_per_connection_account_and_edge() -> TestResult {
    let generations: Vec<ConnectionGeneration> = (1..=4).map(ConnectionGeneration::new).collect();
    let mut core = StateCoreFixture::new(vec![0; 4_096])?;
    let mut base = base_edge();
    let first = *generations.first().ok_or("first")?;
    let mut edge = active_edge(first)?;
    let settled = edge.origins.get(&first).cloned().ok_or("origin")?;
    for generation in &generations {
        edge.origins.insert(*generation, settled.clone());
    }
    let capabilities = capabilities()?;
    let facts = facts(&capabilities)?;
    let account = facts.account.ok_or("account")?;
    let outstanding = |edge: &mut E2eeEdge, connection: u64, account: [u8; 24], count: u8| {
        for sequence in 0..count {
            let mut request = pending(connection, u64::from(sequence), false);
            request.account = account;
            let mut id = [u8::try_from(connection).unwrap_or(u8::MAX); 16];
            if let Some(last) = id.last_mut() {
                *last = sequence;
            }
            edge.pending.insert(id, request);
        }
    };
    let whoami = parse_message(FramedLine::new("EKEY WHOAMI")?)?.ok_or("message")?;
    outstanding(&mut edge, 1, account, 4);
    let refused = edge.client_line(core.context_mut()?, &mut base, first, &whoami, &facts);
    assert!(refused_with(&refused, "E2EE_RATE_LIMITED"), "{refused:?}");
    // The account's second connection is admitted until the account holds eight.
    let second = *generations.get(1).ok_or("second")?;
    outstanding(&mut edge, 2, account, 3);
    let admitted = edge.client_line(core.context_mut()?, &mut base, second, &whoami, &facts);
    assert!(
        !refused_with(&admitted, "E2EE_RATE_LIMITED"),
        "{admitted:?}"
    );
    assert_eq!(edge.pending.len(), 8);
    let third = *generations.get(2).ok_or("third")?;
    let refused = edge.client_line(core.context_mut()?, &mut base, third, &whoami, &facts);
    assert!(
        refused_with(&refused, "E2EE_RATE_LIMITED"),
        "the account's bound: {refused:?}"
    );
    // Another account's connection is admitted until the edge holds 32.
    let other_facts = SessionFacts {
        account: Some(account_of(40)),
        ..super::ingress::facts(&capabilities)?
    };
    let admitted = edge.client_line(core.context_mut()?, &mut base, third, &whoami, &other_facts);
    assert!(
        !refused_with(&admitted, "E2EE_RATE_LIMITED"),
        "{admitted:?}"
    );
    // The test's entropy names every sent request alike, so fill the rest
    // of the edge's bound by count.
    let mut connection = 10_u64;
    while edge.pending.len() < 32 {
        let room = 32 - edge.pending.len();
        outstanding(
            &mut edge,
            connection,
            account_of(connection),
            u8::try_from(room.min(4))?,
        );
        connection += 1;
    }
    let fourth = *generations.get(3).ok_or("fourth")?;
    let fresh_facts = SessionFacts {
        account: Some(account_of(41)),
        ..super::ingress::facts(&capabilities)?
    };
    let refused = edge.client_line(
        core.context_mut()?,
        &mut base,
        fourth,
        &whoami,
        &fresh_facts,
    );
    assert!(
        refused_with(&refused, "E2EE_RATE_LIMITED"),
        "the edge's bound: {refused:?}"
    );
    Ok(())
}

/// A closed connection's unanswered requests keep their places in its
/// account's and the edge's outstanding bounds (companion 16): eight of an
/// account's refuse it on another connection, and another account's
/// connection is admitted until the edge holds 32 with them.
#[tokio::test]
async fn a_closed_connections_requests_count_against_the_outstanding_bounds() -> TestResult {
    let generation = ConnectionGeneration::new(1);
    let mut core = StateCoreFixture::new(vec![0; 4_096])?;
    let mut base = base_edge();
    let mut edge = active_edge(generation)?;
    let capabilities = capabilities()?;
    let facts = facts(&capabilities)?;
    let account = facts.account.ok_or("account")?;
    for index in 0..8_u8 {
        edge.closed_requests.insert([index; 16], ([9; 16], account));
    }
    let whoami = parse_message(FramedLine::new("EKEY WHOAMI")?)?.ok_or("message")?;
    let refused = edge.client_line(core.context_mut()?, &mut base, generation, &whoami, &facts);
    assert!(
        refused_with(&refused, "E2EE_RATE_LIMITED"),
        "the account's bound: {refused:?}"
    );
    for index in 8..31_u8 {
        edge.closed_requests
            .insert([index; 16], ([9; 16], account_of(u64::from(index))));
    }
    let other_facts = SessionFacts {
        account: Some(account_of(40)),
        ..super::ingress::facts(&capabilities)?
    };
    let admitted = edge.client_line(
        core.context_mut()?,
        &mut base,
        generation,
        &whoami,
        &other_facts,
    );
    assert!(
        !refused_with(&admitted, "E2EE_RATE_LIMITED"),
        "{admitted:?}"
    );
    assert_eq!(edge.pending.len(), 1);
    let refused = edge.client_line(
        core.context_mut()?,
        &mut base,
        generation,
        &whoami,
        &other_facts,
    );
    assert!(
        refused_with(&refused, "E2EE_RATE_LIMITED"),
        "the edge's bound: {refused:?}"
    );
    Ok(())
}

/// The reservations of a connection's and an account's outstanding
/// submissions count against their reply quotas at fragment zero
/// (companion 16): a connection keeping 511 replies is refused while one
/// submission of its is outstanding, and admitted once none is; a third
/// connection of an account keeping 1,023 replies over two connections is
/// refused while one submission of the account is outstanding, and admitted
/// once none is.
#[tokio::test]
async fn outstanding_reservations_count_against_the_reply_quotas_at_fragment_zero() -> TestResult {
    use super::super::retry::{ACCOUNT_REPLIES, CONNECTION_REPLIES};
    let generations: Vec<ConnectionGeneration> = (1..=3).map(ConnectionGeneration::new).collect();
    let capabilities = capabilities()?;
    let facts = facts(&capabilities)?;
    let account = facts.account.ok_or("account")?;
    let quota = u32::try_from(CONNECTION_REPLIES)?;
    let submission = line(
        fragment_object(&identity_object(64, 0x5a)?)?
            .first()
            .ok_or("fragment")?,
    )?;
    let outstanding = |edge: &mut E2eeEdge, connection: u64| -> TestResult {
        let mut request = pending(connection, 0, false);
        request.account = account;
        request.reply_key = Some((connection, 1, [0xee; 32], [7; 32]));
        reserve_reply(&mut request)?;
        edge.pending.insert([0xee; 16], request);
        Ok(())
    };
    for (kept, submitter) in [((quota - 1, 0), 0_usize), ((quota, quota - 1), 2)] {
        let mut core = StateCoreFixture::new(vec![0; 4_096])?;
        let mut base = base_edge();
        let first = *generations.first().ok_or("first")?;
        let mut edge = active_edge(first)?;
        let settled = edge.origins.get(&first).cloned().ok_or("origin")?;
        for generation in &generations {
            edge.origins.insert(*generation, settled.clone());
        }
        keep(&mut edge.replies, 1, account, kept.0)?;
        keep(&mut edge.replies, 2, account, kept.1)?;
        assert!(
            usize::try_from(kept.0 + kept.1)? < ACCOUNT_REPLIES,
            "the kept replies alone fit"
        );
        // The connection's own submission, or the account's on its second
        // connection, is outstanding.
        outstanding(&mut edge, if submitter == 0 { 1 } else { 2 })?;
        let connection = *generations.get(submitter).ok_or("submitter")?;
        let refused = edge.client_line(
            core.context_mut()?,
            &mut base,
            connection,
            &submission,
            &facts,
        );
        assert!(refused_with(&refused, "E2EE_RATE_LIMITED"), "{refused:?}");
        assert_eq!(edge.pending.len(), 1, "nothing more went out");
        edge.pending.clear();
        let _sent = edge.client_line(
            core.context_mut()?,
            &mut base,
            connection,
            &submission,
            &facts,
        );
        assert_eq!(edge.pending.len(), 1, "with none outstanding it went out");
    }
    Ok(())
}

/// A connection at its reply quota is still answered for a request whose
/// reply is not kept, which reserves nothing (companion 16).
#[tokio::test]
async fn a_connection_at_its_reply_quota_is_served_a_request_it_keeps_no_reply_for() -> TestResult {
    let generation = ConnectionGeneration::new(1);
    let mut core = StateCoreFixture::new(vec![0; 4_096])?;
    let mut base = base_edge();
    let mut edge = active_edge(generation)?;
    let capabilities = capabilities()?;
    let facts = facts(&capabilities)?;
    let mut request = pending(1, 0, true);
    request.account = facts.account.ok_or("account")?;
    for index in 0..u32::try_from(super::super::retry::CONNECTION_REPLIES)? {
        let mut object_id = [0; 32];
        object_id
            .get_mut(..4)
            .ok_or("object")?
            .copy_from_slice(&index.to_be_bytes());
        request.reply_key = Some((1, 1, object_id, [7; 32]));
        reserve_reply(&mut request)?;
        edge.replies
            .remember(
                &mut request,
                vec![":edge.example EKEY STORED IDENTITY x".to_owned()],
                0,
            )
            .map_err(|e| e.code.to_string())?;
    }
    let fragment = fragment_object(&identity_object(64, 0x5a)?)?
        .into_iter()
        .next()
        .ok_or("fragment")?;
    let refused = edge.client_line(
        core.context_mut()?,
        &mut base,
        generation,
        &line(&fragment)?,
        &facts,
    );
    assert!(refused_with(&refused, "E2EE_RATE_LIMITED"), "{refused:?}");
    let whoami = parse_message(FramedLine::new("EKEY WHOAMI")?)?.ok_or("message")?;
    let served = edge.client_line(core.context_mut()?, &mut base, generation, &whoami, &facts);
    assert!(!refused_with(&served, "E2EE_RATE_LIMITED"), "{served:?}");
    assert_eq!(edge.pending.len(), 1, "the request went out");
    Ok(())
}

/// A submission whose largest reply the memory budget cannot reserve is
/// refused `E2EE_RATE_LIMITED` before it goes out (architecture 19.2).
#[tokio::test]
async fn a_submission_the_memory_budget_cannot_reserve_for_is_refused() -> TestResult {
    let generation = ConnectionGeneration::new(1);
    let mut core = StateCoreFixture::new(vec![0; 4_096])?;
    let mut base = base_edge();
    let mut edge = active_edge(generation)?;
    let capabilities = capabilities()?;
    let facts = facts(&capabilities)?;
    let mut held = Vec::new();
    for chunk in [1_u64 << 20, 4_096] {
        while let Ok(permit) = core.context_mut()?.reserve_kept_output(chunk) {
            held.push(permit);
        }
    }
    let fragment = fragment_object(&identity_object(64, 0x5a)?)?
        .into_iter()
        .next()
        .ok_or("fragment")?;
    let refused = edge.client_line(
        core.context_mut()?,
        &mut base,
        generation,
        &line(&fragment)?,
        &facts,
    );
    assert!(refused_with(&refused, "E2EE_RATE_LIMITED"), "{refused:?}");
    assert!(edge.pending.is_empty());
    drop(held);
    let _sent = edge.client_line(
        core.context_mut()?,
        &mut base,
        generation,
        &line(&fragment)?,
        &facts,
    );
    assert_eq!(edge.pending.len(), 1, "with the memory back it goes out");
    Ok(())
}
