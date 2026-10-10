#![forbid(unsafe_code)]

//! The companion listings page over immutable, requester-bound cuts
//! (companion 11.6, 11.7 and 16): `EKEY FETCH ROOT-CHAIN`, `BINDING-LOCKS`
//! and `CAPABILITIES` and `EGROUP FETCH AUTHORIZATIONS`, `ACKS` and
//! `RECEIPTS` each hold more than one batch, repeat one snapshot token on
//! every page, continue with no gap or repeat, exclude what changes after
//! their cut, pack every page against all three batch limits, and refuse
//! every cursor but the one live cursor of their cut.

use agenc_relay_e2ee::limits::WIRE_OBJECT_ENVELOPE_BYTES;
use agenc_relay_types::{ChannelInstanceId, EntropySource, ServerId, UserId};

use super::super::{Counter, ORIGIN, account_param, origin_key};
use super::*;
use crate::e2ee::coordinator::CompanionOrigin;
use crate::e2ee::coordinator::ops::{self, Exec, Fail};
use crate::e2ee::coordinator::request::{self, Outcome};

mod bounds;
mod cursors;
pub(in crate::e2ee::coordinator::tests) mod directory;
mod packing;
mod proofs;
mod refusals;

/// Entries of a listing longer than one batch.
const ENTRIES: usize = 40;

/// The encoded cursor parameter: empty for `*`.
fn cursor_param(cursor: Option<[u8; 32]>) -> Vec<u8> {
    match cursor {
        None => vec![0],
        Some(cursor) => [vec![32], cursor.to_vec()].concat(),
    }
}

/// One answered page of a listing.
struct Page {
    objects: Vec<Vec<u8>>,
    snapshot: [u8; 32],
    next: Option<[u8; 32]>,
}

/// The page `cursor` names of the listing whose parameters before the cursor
/// are `prefix`; its receipt is applied.
fn page(
    harness: &mut Harness,
    op: Op,
    prefix: &[u8],
    cursor: Option<[u8; 32]>,
) -> TestResult<Page> {
    let outcome = ok(harness.run(op, &[prefix, &cursor_param(cursor)].concat(), None)?)?;
    assert_eq!(outcome.result, ResultBody::ObjectPage);
    Ok(Page {
        objects: outcome
            .responses
            .into_iter()
            .map(|response| response.bytes)
            .collect(),
        snapshot: outcome.snapshot_token.ok_or("a snapshot token")?,
        next: outcome.next_cursor,
    })
}

/// Pages a listing from `*` to its end, requiring every page to repeat the
/// first page's snapshot token.
fn pages(harness: &mut Harness, op: Op, prefix: &[u8]) -> TestResult<Vec<Page>> {
    let mut pages: Vec<Page> = Vec::new();
    let mut cursor = None;
    loop {
        let next = page(harness, op, prefix, cursor)?;
        if let Some(first) = pages.first() {
            assert_eq!(next.snapshot, first.snapshot, "a page left its cut");
        }
        cursor = next.next;
        pages.push(next);
        if cursor.is_none() {
            return Ok(pages);
        }
        if pages.len() > 64 {
            return Err("a listing that never ends".into());
        }
    }
}

/// Every object of `pages`, in order.
fn objects(pages: &[Page]) -> Vec<Vec<u8>> {
    pages
        .iter()
        .flat_map(|page| page.objects.iter().cloned())
        .collect()
}

/// The object count of each page.
fn counts(pages: &[Page]) -> Vec<usize> {
    pages.iter().map(|page| page.objects.len()).collect()
}

/// A synthetic retained object of `kind`, exactly `size` bytes long and
/// unique to `tag`.
fn object_of(kind: ArcWireObjectKind, size: usize, tag: u64) -> TestResult<Vec<u8>> {
    let length = size
        .checked_sub(WIRE_OBJECT_ENVELOPE_BYTES)
        .ok_or("an object holds its envelope")?;
    let mut body = vec![0x5a; length];
    body.get_mut(..8)
        .ok_or("an object body of eight bytes")?
        .copy_from_slice(&tag.to_be_bytes());
    wire_raw(kind, body)
}

/// Retains `bytes` as a coordinator object and returns its identifier.
fn retain(harness: &mut Harness, bytes: Vec<u8>) -> [u8; 32] {
    let id = object_id(&bytes);
    harness.coordinator.state.objects.insert(id, bytes);
    id
}

/// Retains a sequencer record of `size` bytes at `sequence` of
/// `conversation` and returns its bytes.
fn seed_record(
    harness: &mut Harness,
    conversation: [u8; 32],
    sequence: u64,
    size: usize,
) -> TestResult<Vec<u8>> {
    let bytes = object_of(ArcWireObjectKind::SequencerRecord, size, sequence)?;
    let id = retain(harness, bytes.clone());
    harness
        .coordinator
        .state
        .conversations
        .get_mut(&conversation)
        .ok_or("a bound conversation")?
        .records
        .insert(sequence, id);
    Ok(bytes)
}

/// The parameters of `EGROUP FETCH RECEIPTS` from `first`.
fn receipts_from(conversation: [u8; 32], first: u64) -> Vec<u8> {
    [conversation.to_vec(), first.to_be_bytes().to_vec()].concat()
}

/// The requester an evaluated request runs as.
pub(in crate::e2ee::coordinator::tests) struct Requester {
    pub(in crate::e2ee::coordinator::tests) user: [u8; 16],
    pub(in crate::e2ee::coordinator::tests) origin: CompanionOrigin,
    pub(in crate::e2ee::coordinator::tests) monotonic_millis: u64,
    /// Whether the requester holds a base session, whose query snapshots a
    /// cut is charged to.
    pub(in crate::e2ee::coordinator::tests) session: bool,
}

impl Requester {
    /// The harness's own origin and session, at the harness's time.
    pub(in crate::e2ee::coordinator::tests) fn of(harness: &Harness) -> TestResult<Self> {
        Ok(Self {
            user: ORIGIN,
            origin: harness
                .coordinator
                .state
                .origins
                .get(&origin_key())
                .cloned()
                .ok_or("the harness origin")?,
            monotonic_millis: harness.monotonic_millis,
            session: true,
        })
    }
}

/// Evaluates one request as `requester` against the committed state without
/// committing it; returns its outcome and whether it drew any entropy.
pub(in crate::e2ee::coordinator::tests) fn evaluate(
    harness: &Harness,
    requester: &Requester,
    op: Op,
    params: &[u8],
) -> TestResult<(Result<Outcome, Fail>, bool)> {
    let mut entropy = Counter(harness.entropy.0);
    let outcome = evaluate_with(harness, requester, op, params, &mut entropy)?;
    Ok((outcome, entropy.0 != harness.entropy.0))
}

/// [`evaluate`] drawing from `entropy`.
fn evaluate_with(
    harness: &Harness,
    requester: &Requester,
    op: Op,
    params: &[u8],
    entropy: &mut dyn EntropySource,
) -> TestResult<Result<Outcome, Fail>> {
    let complete = harness.request(op, params, None)?;
    let decoded = request::decode(&harness.coordinator, &complete)
        .map_err(|code| format!("decode failed with {code:?}"))?;
    let home = ServerId::from_bytes(requester.origin.home_server_id);
    let peers = [home];
    let holds = |_: ServerId, _: ChannelInstanceId| true;
    let hosting = |_: ChannelInstanceId| vec![home];
    let attached = |_: &[u8; 32]| vec![home];
    let member = |_: ChannelInstanceId| true;
    let plan_binding = |_: ChannelInstanceId, _: &[[u8; 24]]| Ok(None);
    let mut exec = Exec {
        object_source: crate::e2ee::coordinator::object_read::Source::CompleteMemory,
        queries: requester.session.then(|| {
            harness.query_sessions.query_reservations(
                UserId::from_bytes(requester.user),
                harness.query_limits,
                harness.backing.clone(),
            )
        }),
        backing: harness.backing.clone(),
        monotonic_millis: requester.monotonic_millis,
        coordinator: &harness.coordinator,
        home,
        origin: &requester.origin,
        decoded: &decoded,
        now: harness.now,
        entropy,
        peers: &peers,
        holds_channel: &holds,
        hosting: &hosting,
        attached_edges: &attached,
        channel_member: &member,
        plan_binding: &plan_binding,
        state_generation: super::super::STATE_GENERATION,
        source_view: Vec::new(),
    };
    Ok(ops::execute(&mut exec).and_then(ops::Prepared::complete))
}

/// Requires `params` refused with `E2EE_OBJECT_NOT_FOUND` for `requester`
/// before any entropy is drawn, leaving the cuts as they stand.
fn refused_as(harness: &Harness, requester: &Requester, op: Op, params: &[u8]) -> TestResult {
    let cursors = harness.coordinator.state.listing_snapshots.cursors();
    let (outcome, drew) = evaluate(harness, requester, op, params)?;
    assert_eq!(
        outcome
            .map(|outcome| outcome.result)
            .map_err(|fail| fail.code),
        Err(E2eeReplyCode::ObjectNotFound)
    );
    assert!(!drew, "a refused cursor drew entropy");
    assert_eq!(
        harness.coordinator.state.listing_snapshots.cursors(),
        cursors
    );
    Ok(())
}

/// [`refused_as`] for the harness's own requester.
fn refused(harness: &Harness, op: Op, params: &[u8]) -> TestResult {
    refused_as(harness, &Requester::of(harness)?, op, params)
}
