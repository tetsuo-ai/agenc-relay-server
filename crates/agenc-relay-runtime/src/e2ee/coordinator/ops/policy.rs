//! Policy publication (companion Section 9.3): the server retains each
//! conversation's policy chain so the sequencer can verify finality quorums
//! before it certifies a terminal (Section 12.4).

use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_domain::e2ee::projection::StoreKind;
use agenc_relay_e2ee::limits::{MAX_POLICY_CHAIN_BYTES, MAX_POLICY_OBJECT};
use agenc_relay_e2ee::object::ArcWireObjectKind;
use agenc_relay_e2ee::objects::conversation::ArcPolicy;
use agenc_relay_e2ee::policy::verify_policy;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::TableId;
use agenc_relay_storage::e2ee_records::{SEQUENCER_ROW_KIND, SequencerRow};

use super::super::request::{Outcome, ResultBody, state_row};
use super::super::{CompanionCoordinator, ConversationState, RetainedPolicy};
use super::route::rosters_of;
use super::{Exec, Fail};

/// `submit_policy`: verifies a published policy against the binding's
/// chain and the retained rosters, then retains it by content identifier.
/// An identical resubmission answers with the retained object.
pub fn submit_policy(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    exec.attached_device()?;
    let (object, bytes) = exec.payload()?;
    if object.kind() != ArcWireObjectKind::Policy {
        return Err(Fail::with(E2eeReplyCode::InvalidFragment, &conversation_id));
    }
    let state = conversation(exec, &conversation_id)?;
    // A route blocked on a retired credential accepts no policy change.
    state
        .blocked_credential_id
        .map_or(Ok(()), |_| Err(Fail::from(E2eeReplyCode::Syncing)))?;
    let mut budget = DecodeBudget::new(MAX_POLICY_OBJECT, 1 << 16);
    let policy = ArcPolicy::decode_exact(object.body(), &mut budget)
        .map_err(|_| Fail::with(E2eeReplyCode::InvalidFragment, &conversation_id))?;
    let policy_id = CompanionCoordinator::id_of(SemanticHashDomain::PolicyId, &policy.tbs)?;
    if let Some(existing) = state.policies.get(&policy_id) {
        return Ok(Outcome::scalar(ResultBody::Stored(
            StoreKind::Policy,
            existing.object_id,
        )));
    }
    let verified = verify_chained(exec, state, &conversation_id, &policy, policy_id)?;
    if state.policy_bytes().saturating_add(bytes.len()) > MAX_POLICY_CHAIN_BYTES {
        return Err(Fail::with(E2eeReplyCode::PolicyInvalid, &conversation_id));
    }
    let object_id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
    let mut outcome = Outcome::scalar(ResultBody::Stored(StoreKind::Policy, object_id));
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome.writes.push(
        state_row(
            TableId::E2eeState,
            SEQUENCER_ROW_KIND,
            SequencerRow::policy_key(&conversation_id, &policy_id)
                .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
            SequencerRow::Policy {
                object_id,
                generation: verified.generation,
                previous_policy_id: verified.previous_policy_id,
            }
            .encode()
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        )
        .map_err(Fail::from)?,
    );
    let retained = RetainedPolicy {
        object_id,
        object_bytes: bytes.len(),
        policy: verified,
    };
    outcome.effects.push(Box::new(move |companion| {
        if let Some(state) = companion.conversations.get_mut(&conversation_id) {
            state.policies.insert(policy_id, retained);
        }
    }));
    Ok(outcome)
}

fn conversation<'a>(
    exec: &Exec<'a>,
    conversation_id: &[u8; 32],
) -> Result<&'a ConversationState, Fail> {
    exec.coordinator
        .state
        .conversations
        .get(conversation_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, conversation_id))
}

/// Verifies `policy` under the binding's chain rule: generation zero must
/// be the binding's initial policy, every later generation names a
/// retained predecessor, and approvals resolve through the retained
/// rosters of the binding's principals.
fn verify_chained(
    exec: &Exec<'_>,
    state: &ConversationState,
    conversation_id: &[u8; 32],
    policy: &ArcPolicy,
    policy_id: [u8; 32],
) -> Result<agenc_relay_e2ee::policy::VerifiedPolicy, Fail> {
    let invalid = || Fail::with(E2eeReplyCode::PolicyInvalid, conversation_id);
    let predecessor = if policy.tbs.policy_generation == 0 {
        if policy_id != state.initial_policy_id {
            return Err(invalid());
        }
        None
    } else {
        Some(
            &state
                .policies
                .get(&policy.tbs.previous_policy_id)
                .ok_or_else(invalid)?
                .policy,
        )
    };
    let rosters = rosters_of(exec, &state.principal_accounts)?;
    verify_policy(
        &exec.coordinator.network_id,
        conversation_id,
        policy,
        &rosters,
        predecessor,
    )
    .map_err(|_| invalid())
}
