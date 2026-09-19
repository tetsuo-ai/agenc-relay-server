#![forbid(unsafe_code)]

//! E2EE ingress admission (companion 16, ENC-16): fragment zero pays the
//! line and the verification, its continuation fragments pay decoded bytes
//! through the dedicated account-and-device bucket, and a fragment behind no
//! accepted fragment zero is a command line again that the router refuses.

use agenc_ircd_client_wire::{
    CapabilityProfile, CapabilitySpec, CapabilityState, FramedLine, ParsedMessage, parse_message,
};
use agenc_ircd_e2ee::limits::{
    MAX_LIVE_OBJECT, MAX_SEQUENCER_RECORD_OBJECT, MIN_ADMITTED_E2EE_INGRESS_RATE,
};
use agenc_ircd_e2ee::wire::command::EkeyCommand;
use agenc_ircd_e2ee::wire::fragment::{FragmentTag, fragment_object};
use agenc_ircd_types::{AccountId, AccountRandomId, MonotonicTick, UserId};

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
        Some(agenc_ircd_e2ee::limits::CAPABILITY_VALUE),
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
    edge.replies
        .remember(&answered, vec![":edge.example EKEY STORED".to_owned()], 0)
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
