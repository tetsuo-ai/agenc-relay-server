//! Public ACK bindings. Old-tree signature identity and coverage require endpoint state.
#![forbid(unsafe_code)]
use super::{Exec, Fail};
use agenc_ircd_domain::e2ee::sequencer_log::{AttemptSlot, CandidateSlot};
use agenc_ircd_e2ee::limits::{MAX_REINIT_OBJECT, MAX_SEQUENCER_RECORD_OBJECT};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::reinit::{IrcReInitAckKind, IrcReInitAckTbs, IrcReInitAttempt};
use agenc_ircd_e2ee::objects::sequencing::{
    IrcCommitAckTbs, IrcFinalizationCoreTbs, IrcSequencerRecord,
};
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;

pub(super) fn commit_submission(
    exec: &Exec<'_>,
    conversation: &[u8; 32],
    ack: &IrcCommitAckTbs,
    slot: &CandidateSlot,
) -> Result<(), Fail> {
    if ack.profile_version != 1 {
        return Err(Fail::with(E2eeReplyCode::InvalidFragment, conversation));
    }
    if ack.network_id != exec.coordinator.network_id {
        return Err(Fail::with(E2eeReplyCode::RouteInvalid, conversation));
    }
    if ack.conversation_id != *conversation
        || ack.prior_epoch != slot.position.prior_epoch
        || Some(ack.resulting_epoch) != slot.position.prior_epoch.checked_add(1)
    {
        return Err(Fail::with(E2eeReplyCode::EpochStale, conversation));
    }
    Ok(())
}

pub(super) fn commit_finalization(ack: &IrcCommitAckTbs, core: &IrcFinalizationCoreTbs) -> bool {
    let named = (
        ack.profile_version,
        ack.network_id,
        ack.conversation_id,
        ack.prior_epoch,
        ack.candidate_id,
        ack.commit_object_id,
        ack.resulting_epoch,
    );
    let expected = (
        core.profile_version,
        core.network_id,
        core.conversation_id,
        core.prior_epoch,
        core.candidate_id,
        core.commit_object_id,
        core.resulting_epoch,
    );
    let result = (
        ack.resulting_group_context_digest,
        ack.resulting_ratchet_tree_digest,
        ack.finalization_authenticator,
    );
    let certified = (
        core.resulting_group_context_digest,
        core.resulting_ratchet_tree_digest,
        core.finalization_authenticator,
    );
    named == expected && result == certified
}

pub(super) fn reinit_submission(
    exec: &Exec<'_>,
    conversation: &[u8; 32],
    ack: &IrcReInitAckTbs,
    slot: &AttemptSlot,
) -> Result<(), Fail> {
    if ack.profile_version != 1 {
        return Err(Fail::with(E2eeReplyCode::InvalidFragment, conversation));
    }
    if ack.network_id != exec.coordinator.network_id || ack.old_conversation_id != *conversation {
        return Err(Fail::with(E2eeReplyCode::RouteInvalid, conversation));
    }
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation);
    let log = exec
        .coordinator
        .state
        .logs
        .get(conversation)
        .ok_or_else(invalid)?;
    if ack.old_reinit_state_id != *log.accepted_state_id() {
        return Err(Fail::with(E2eeReplyCode::EpochStale, conversation));
    }
    let record_id = exec
        .coordinator
        .state
        .conversations
        .get(conversation)
        .and_then(|state| state.records.get(&slot.route_sequence))
        .ok_or_else(invalid)?;
    with_retained(
        exec,
        record_id,
        IrcWireObjectKind::SequencerRecord,
        MAX_SEQUENCER_RECORD_OBJECT,
        |record: IrcSequencerRecord| {
            let IrcSequencerRecord::ReinitAttempt(receipt) = record else {
                return Err(invalid());
            };
            let tbs = &receipt.tbs;
            let named = (
                tbs.profile_version,
                tbs.network_id,
                tbs.old_conversation_id,
                tbs.old_reinit_state_id,
                tbs.route_sequence,
                tbs.attempt_sequence,
                tbs.predecessor_record_id,
                tbs.reinit_attempt_id,
            );
            let expected = (
                1,
                exec.coordinator.network_id,
                *conversation,
                *log.accepted_state_id(),
                slot.route_sequence,
                slot.attempt_sequence,
                slot.predecessor_record_id,
                slot.attempt_id,
            );
            if named != expected {
                return Err(invalid());
            }
            with_retained(
                exec,
                &tbs.attempt_object_id,
                IrcWireObjectKind::ReinitAttempt,
                MAX_REINIT_OBJECT,
                |attempt: IrcReInitAttempt| {
                    if attempt.tbs.attempt_sequence != slot.attempt_sequence
                        || !reinit_attempt(ack, &attempt, &slot.attempt_id)
                    {
                        return Err(invalid());
                    }
                    Ok(())
                },
            )
        },
    )
}

/// Both decoded wire and typed body remain inside the reservation's lifetime.
fn with_retained<T: TlsDecode>(
    exec: &Exec<'_>,
    id: &[u8; 32],
    kind: IrcWireObjectKind,
    limit: usize,
    verify: impl FnOnce(T) -> Result<(), Fail>,
) -> Result<(), Fail> {
    let invalid = || Fail::from(E2eeReplyCode::BindingAuthInvalid);
    let bytes = exec.coordinator.state.objects.get(id).ok_or_else(invalid)?;
    if bytes.len() > limit {
        return Err(invalid());
    }
    let capacity = bytes
        .len()
        .checked_mul(4)
        .and_then(|n| n.checked_add(8192))
        .ok_or_else(invalid)?;
    let _memory = exec
        .backing
        .reserve(capacity)
        .map_err(|_| Fail::from(E2eeReplyCode::RateLimited))?;
    if agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes() != id {
        return Err(invalid());
    }
    let mut budget = DecodeBudget::new(capacity, 1 << 16);
    let object =
        IrcWireObject::decode_kind(bytes, Some(kind), &mut budget).map_err(|_| invalid())?;
    let value = T::decode_exact(object.body(), &mut budget).map_err(|_| invalid())?;
    verify(value)
}

pub(super) fn reinit_attempt(
    ack: &IrcReInitAckTbs,
    attempt: &IrcReInitAttempt,
    id: &[u8; 32],
) -> bool {
    let tbs = &attempt.tbs;
    let named = (
        ack.network_id,
        ack.old_conversation_id,
        ack.new_conversation_id,
        ack.old_reinit_state_id,
        ack.reinit_attempt_id,
    );
    let expected = (
        tbs.network_id,
        tbs.old_conversation_id,
        tbs.new_conversation_id,
        tbs.old_reinit_state_id,
        *id,
    );
    let result = (
        ack.new_group_info_digest,
        ack.new_group_context_digest,
        ack.new_ratchet_tree_digest,
        ack.new_exporter_authenticator,
    );
    let expected_result = (
        tbs.new_group_info_digest,
        tbs.new_group_context_digest,
        tbs.new_ratchet_tree_digest,
        tbs.new_exporter_authenticator,
    );
    ack.profile_version == 1
        && tbs.profile_version == 1
        && named == expected
        && result == expected_result
        && reinit_role(ack, attempt)
}

fn reinit_role(ack: &IrcReInitAckTbs, attempt: &IrcReInitAttempt) -> bool {
    let creator = &attempt.tbs;
    match ack.ack_kind {
        IrcReInitAckKind::CreatorState => {
            ack.key_package_ref.as_slice().is_empty()
                && ack.old_leaf_index == creator.creator_old_leaf_index
                && ack.old_credential_hash == creator.creator_old_credential_hash
        }
        IrcReInitAckKind::WelcomeJoin => {
            !ack.key_package_ref.as_slice().is_empty()
                && ack.old_leaf_index != creator.creator_old_leaf_index
                && attempt
                    .key_package_plan
                    .entries
                    .as_slice()
                    .iter()
                    .any(|entry| entry.creator == 0 && entry.key_package_ref == ack.key_package_ref)
        }
    }
}
