#![forbid(unsafe_code)]

//! A restored `pending` route adopts a `roster_recovery` finalization that
//! renews its principal's expired roster (companion 8.4 and 13.7.4): the
//! historical chain checks the principal's vote and ACK against both the
//! expired predecessor and the unexpired successor the record installs,
//! and refuses the same record when the successor does not cover the
//! Commit's validation time or when the references at its position carry a
//! second roster of the principal (companion 9.3).

use super::*;
use crate::e2ee::coordinator::recovery_lineage::references_at;
use crate::e2ee::coordinator::tests::support::{commit_authorization, roster, roster_id};
use agenc_relay_e2ee::objects::conversation::{ArcCommitAuthorizationRule, action_bits};
use agenc_relay_e2ee::objects::identity::ArcDeviceRoster;
use agenc_relay_e2ee::objects::sequencing::ArcFinalizationRequest;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};

/// A validation time after the principal's generation-zero roster, which
/// ends at `100 + 6 * 24 * 3600`, and inside the sequencer credential.
const LAPSED: u64 = 600_000;

/// The principal's next roster under the same root, keeping its devices'
/// certificates, over `interval`.
fn renewed(harness: &Harness, interval: (u64, u64)) -> TestResult<ArcDeviceRoster> {
    renewed_after(harness, &harness.principal.roster, interval)
}

/// The principal's roster after `previous` under the same root, keeping its
/// devices' certificates, over `interval`.
fn renewed_after(
    harness: &Harness,
    previous: &ArcDeviceRoster,
    interval: (u64, u64),
) -> TestResult<ArcDeviceRoster> {
    let certificates = harness
        .principal
        .roster
        .tbs
        .active_devices
        .as_slice()
        .iter()
        .map(|entry| entry.certificate.clone())
        .collect();
    Ok(roster(
        &harness.principal.root_secret,
        &harness.principal.root,
        previous.tbs.roster_generation + 1,
        roster_id(previous)?,
        interval,
        certificates,
        Vec::new(),
    )?)
}

/// Finalizes a `roster_recovery` candidate of `epoch` at `validation_time`
/// on the live coordinator, which checks no roster time: no controller
/// approves it and every device votes.
fn recover_at(
    source: &mut Harness,
    conversation: [u8; 32],
    epoch: u64,
    validation_time: u64,
) -> TestResult {
    let policy = source
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?
        .current_policy_id;
    let (receipt, object, candidate) =
        submit_candidate(source, conversation, epoch, validation_time)?;
    let ack_bytes = ack(conversation, epoch, candidate, object)?;
    ok(source.run(Op::SubmitCommitAck, &conversation, Some(&ack_bytes))?)?;
    let bytes = finalization_request_under(
        source,
        conversation,
        &receipt,
        object,
        candidate,
        &ack_bytes,
        &[DEVICE],
        (policy, policy),
    )?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
    let object = agenc_relay_e2ee::object::ArcWireObject::decode_kind(
        &bytes,
        Some(ArcWireObjectKind::FinalizationRequest),
        &mut budget,
    )?;
    let mut request = ArcFinalizationRequest::decode_exact(object.body(), &mut budget)?;
    let core = &request.proof.core;
    let mut authorization = request.proof.authorization.tbs.clone();
    authorization.prior_epoch = core.prior_epoch;
    authorization.prior_state_id = core.prior_state_id;
    authorization.candidate_id = core.candidate_id;
    authorization.commit_object_id = core.commit_object_id;
    authorization.canonical_validation_time = validation_time;
    authorization.resulting_group_context_digest = core.resulting_group_context_digest;
    authorization.resulting_ratchet_tree_digest = core.resulting_ratchet_tree_digest;
    authorization.authorization_rule = ArcCommitAuthorizationRule::RosterRecovery;
    authorization.action_bits = action_bits::ROSTER;
    request.proof.authorization = commit_authorization(authorization, &[])?;
    request.proof.core.commit_authorization_id = semantic_id_of(
        SemanticHashDomain::CommitAuthorizationId,
        &request.proof.authorization.tbs,
    )?;
    let terminal = semantic_id_of(SemanticHashDomain::FinalizationId, &request.proof.core)?;
    let votes = source
        .devices
        .clone()
        .into_iter()
        .map(|device| {
            vote(
                source,
                device,
                &receipt,
                candidate,
                Terminal::finalize(terminal),
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    request.votes = TlsVec::new(votes)?;
    let bytes = wire(ArcWireObjectKind::FinalizationRequest, &request)?;
    let outcome = ok(source.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(_, _, id, _) if id == terminal));
    Ok(())
}

/// A source whose bootstrap activates at 150 and whose next finalization
/// recovers the principal's roster at `LAPSED`, with the writes captured at
/// the genesis.
fn recovering_source() -> TestResult<Source> {
    let mut harness = Harness::with_devices(&[DEVICE])?;
    let conversation = harness.bind_channel()?;
    let snapshot = clone_writes(&harness.writes)?;
    finish_at(&mut harness, conversation, 0, None, 150)?;
    let after_activation = clone_writes(&harness.writes)?;
    recover_at(&mut harness, conversation, 1, LAPSED)?;
    let closing = clone_writes(&harness.writes)?;
    let records = records_of(&harness, &conversation)?;
    let policy = wire(ArcWireObjectKind::Policy, &harness.operational_policy)?;
    Ok(Source {
        harness,
        conversation,
        snapshot,
        after_activation,
        closing,
        records,
        close: Vec::new(),
        close_id: [0; 32],
        policy,
    })
}

/// Adopts the source's bootstrap and its recovery candidate, offers
/// `successors` as the recovery's roster references, and returns the reply
/// to the recovery's finalization record.
fn adopt_recovery(
    pending: &mut Harness,
    source: &Source,
    successors: &[&ArcDeviceRoster],
) -> TestResult<Result<Outcome, Fail>> {
    let conversation = source.conversation;
    let (finalization, earlier) = source.records.split_last().ok_or("records")?;
    for (sequence, bytes) in earlier {
        if *sequence == 1 {
            deliver(
                pending,
                conversation,
                ArcRecoveryElementKind::ReferenceElement,
                ArcWireObjectKind::Policy,
                &source.policy,
            )?;
        }
        deliver(
            pending,
            conversation,
            ArcRecoveryElementKind::RecordElement,
            ArcWireObjectKind::SequencerRecord,
            bytes,
        )?;
    }
    for successor in successors {
        let roster_bytes = wire(ArcWireObjectKind::DeviceRoster, *successor)?;
        deliver(
            pending,
            conversation,
            ArcRecoveryElementKind::ReferenceElement,
            ArcWireObjectKind::DeviceRoster,
            &roster_bytes,
        )?;
    }
    let submission = accept(
        pending,
        conversation,
        ArcRecoveryElementKind::RecordElement,
        ArcWireObjectKind::SequencerRecord,
        &finalization.1,
    )?;
    element(pending, conversation, submission, &finalization.1)
}

#[test]
fn a_pending_route_adopts_a_roster_recovery_from_an_expired_predecessor() -> TestResult {
    let source = recovering_source()?;
    let conversation = source.conversation;
    assert_eq!(source.records.len(), 4);
    let successor = renewed(&source.harness, (550_000, 1_000_000))?;
    let mut pending = pending_from(&source)?;
    let reply = ok(adopt_recovery(&mut pending, &source, &[&successor])?)?;
    let ResultBody::RecoveryExtended(replied, sequence, _) = reply.result else {
        return Err(format!("the recovery was not adopted: {:?}", reply.result).into());
    };
    assert_eq!((replied, sequence), (conversation, 3));
    assert_pending_unchanged(&pending, &conversation);
    // The lineage replays the adopted recovery after a restart.
    let mut reopened = pending.reloaded()?;
    attach(&mut reopened, &source);
    assert_eq!(head_position(&reopened, &conversation)?.0, 3);
    Ok(())
}

#[test]
fn a_pending_route_refuses_a_roster_recovery_whose_successor_has_expired() -> TestResult {
    let source = recovering_source()?;
    let conversation = source.conversation;
    // Signed and continuous, but over before the Commit's validation time.
    let successor = renewed(&source.harness, (100, LAPSED - 1))?;
    let mut pending = pending_from(&source)?;
    assert_eq!(
        code(adopt_recovery(&mut pending, &source, &[&successor])?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    assert_eq!(head_position(&pending, &conversation)?.0, 2);
    assert_pending_unchanged(&pending, &conversation);
    Ok(())
}

#[test]
fn a_pending_route_refuses_a_recovery_whose_references_carry_two_rosters_of_its_principal()
-> TestResult {
    let source = recovering_source()?;
    let conversation = source.conversation;
    // Each roster continues the one before it and covers the record's time,
    // but the record installs one roster per account (companion 9.3).
    let successor = renewed(&source.harness, (550_000, 1_000_000))?;
    let next = renewed_after(&source.harness, &successor, (550_000, 1_000_000))?;
    let mut pending = pending_from(&source)?;
    let reply = adopt_recovery(&mut pending, &source, &[&successor, &next])?;
    // The chain takes the retained references in that order, so without the
    // rule it would install both and move the head past the successor.
    let references = references_at(&pending.coordinator.state, &conversation, 3);
    let (_, rosters) = references.heads();
    let ordered = [
        wire(ArcWireObjectKind::DeviceRoster, &successor)?,
        wire(ArcWireObjectKind::DeviceRoster, &next)?,
    ];
    assert_eq!(
        rosters,
        ordered.iter().map(Vec::as_slice).collect::<Vec<_>>()
    );
    assert_eq!(code(reply), Some(E2eeReplyCode::BindingAuthInvalid));
    assert_eq!(head_position(&pending, &conversation)?.0, 2);
    assert_pending_unchanged(&pending, &conversation);
    Ok(())
}
