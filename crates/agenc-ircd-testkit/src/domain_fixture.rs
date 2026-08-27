//! Deterministic builders for pure-domain integration and model tests.

use agenc_ircd_domain::{
    AccountState, AdmissionSnapshot, ApplyReceipt, CanonicalCommand, CommandEnvelope, DomainError,
    DomainState, ExternalInputs, MutationPlan, PlanDecision, RateBucket, SessionSeed,
};
use agenc_ircd_types::{
    AccountId, AccountRandomId, ChannelInstanceId, Generation, PublicCloak, Revision, ServerId,
    SessionId, UserId, UtcSecond,
};

/// Deterministic identities and fences belonging to one test session.
#[derive(Clone, Copy)]
pub struct DomainTestIdentity {
    /// Physical-session identity.
    pub session_id: SessionId,
    /// Per-connection logical user identity.
    pub user_id: UserId,
    /// Session-generation fence.
    pub generation: Generation,
    /// Optional immutable account authority.
    pub account_id: Option<AccountId>,
}

/// Expands one fixture byte into a 16-byte identifier value.
#[must_use]
pub const fn bytes(seed: u8) -> [u8; 16] {
    [seed; 16]
}

/// Builds one domain-separated deterministic account identity.
#[must_use]
pub const fn account_id(seed: u8) -> AccountId {
    AccountId::from_random(AccountRandomId::from_bytes(bytes(seed)))
}

/// Builds one deterministic channel-creation identity.
#[must_use]
pub const fn channel_id(seed: u8) -> ChannelInstanceId {
    ChannelInstanceId::from_bytes(bytes(seed))
}

/// Builds one checked revision and maps validation into domain errors.
pub fn revision(value: u64) -> Result<Revision, DomainError> {
    Revision::new(value).map_err(Into::into)
}

/// Builds one checked generation and maps validation into domain errors.
pub fn generation(value: u64) -> Result<Generation, DomainError> {
    Generation::new(value).map_err(Into::into)
}

/// Prepares, applies, and validates one deterministic mutation plan.
pub fn apply_plan(
    state: &mut DomainState,
    plan: MutationPlan,
) -> Result<ApplyReceipt, DomainError> {
    let prepared = state.prepare_mutation(plan)?;
    let receipt = state.apply_prepared(prepared)?;
    state.validate()?;
    Ok(receipt)
}

/// Creates and applies one deterministic account bootstrap plan.
pub fn create_account(
    state: &mut DomainState,
    seed: u8,
    account_generation: u64,
) -> Result<(AccountId, Generation), DomainError> {
    let account_id = account_id(seed);
    let account_generation = generation(account_generation)?;
    let plan = state.plan_account_created(AccountState::new(
        account_id,
        account_generation,
        state.revision(),
    ))?;
    apply_plan(state, plan)?;
    Ok((account_id, account_generation))
}

/// Creates and applies one deterministic guest or account session.
pub fn open_session(
    state: &mut DomainState,
    seed: u8,
    nickname: &str,
    account: Option<(AccountId, Generation)>,
) -> Result<DomainTestIdentity, DomainError> {
    let session_generation = generation(1)?;
    let (account_id, account_session_generation) = match account {
        Some((account_id, account_generation)) => (Some(account_id), account_generation),
        None => (None, generation(0)?),
    };
    let cloak = deterministic_cloak(seed)?;
    let identity = DomainTestIdentity {
        session_id: SessionId::from_bytes(bytes(seed)),
        user_id: UserId::from_bytes(bytes(seed.wrapping_add(64))),
        generation: session_generation,
        account_id,
    };
    let plan = state.plan_session_opened(SessionSeed {
        session_id: identity.session_id,
        user_id: identity.user_id,
        home_server_id: ServerId::from_bytes(bytes(240)),
        account_id,
        account_session_generation,
        generation: session_generation,
        nickname: agenc_ircd_domain::NicknameValue::parse(nickname)?,
        display_name: agenc_ircd_domain::DisplayNameValue::prepare(nickname)?,
        public_cloak: cloak,
        connection_nonce: [seed; 32],
        negotiated_capability_hash: [seed.wrapping_add(1); 32],
        created_at_utc: UtcSecond::from_unix_seconds(1_700_000_000 + u64::from(seed)),
        revision: state.revision(),
    })?;
    apply_plan(state, plan)?;
    Ok(identity)
}

/// Builds admission credit for one ordinary registered command.
pub fn registered_admission(user_id: UserId) -> Result<AdmissionSnapshot, DomainError> {
    AdmissionSnapshot::new(vec![(RateBucket::RegisteredCommand(user_id), 100)])
}

/// Builds all hierarchical message buckets for explicit channel targets.
pub fn message_admission(
    identity: DomainTestIdentity,
    channel_ids: &[ChannelInstanceId],
) -> Result<AdmissionSnapshot, DomainError> {
    let mut entries = vec![(RateBucket::RegisteredCommand(identity.user_id), 100)];
    match identity.account_id {
        Some(account_id) => entries.push((RateBucket::AccountMessage(account_id), 100)),
        None => entries.push((RateBucket::GuestMessage(identity.user_id), 100)),
    }
    for channel_id in channel_ids {
        entries.push((RateBucket::ChannelMessage(*channel_id), 100));
    }
    AdmissionSnapshot::new(entries)
}

/// Authorizes one command against the state's current revision.
pub fn authorize(
    state: &DomainState,
    identity: DomainTestIdentity,
    command: CanonicalCommand,
    admission: &AdmissionSnapshot,
) -> Result<agenc_ircd_domain::AuthorizedCommand, DomainError> {
    state
        .authorize(
            CommandEnvelope::new(
                identity.session_id,
                identity.user_id,
                identity.generation,
                state.revision(),
                command,
            ),
            admission,
        )
        .map_err(|failure| failure.error())
}

/// Produces one query, external-input request, or mutation decision.
pub fn plan(
    state: &DomainState,
    identity: DomainTestIdentity,
    command: CanonicalCommand,
    admission: &AdmissionSnapshot,
    external: Option<ExternalInputs>,
) -> Result<PlanDecision, DomainError> {
    let authorized = authorize(state, identity, command, admission)?;
    state.plan_authorized(authorized, external)
}

/// Authorizes, plans, applies, and validates one mutation command.
pub fn apply_command(
    state: &mut DomainState,
    identity: DomainTestIdentity,
    command: CanonicalCommand,
    admission: &AdmissionSnapshot,
    external: Option<ExternalInputs>,
) -> Result<ApplyReceipt, DomainError> {
    let decision = plan(state, identity, command, admission, external)?;
    let PlanDecision::Mutation(plan) = decision else {
        return Err(DomainError::BadState);
    };
    apply_plan(state, plan)
}

fn deterministic_cloak(seed: u8) -> Result<PublicCloak, DomainError> {
    let cloak = match seed % 4 {
        0 => PublicCloak::parse("aaaaaaaaaa", "aaaaaaaaaaaaaaaa")?,
        1 => PublicCloak::parse("bbbbbbbbbb", "bbbbbbbbbbbbbbbb")?,
        2 => PublicCloak::parse("cccccccccc", "cccccccccccccccc")?,
        _ => PublicCloak::parse("dddddddddd", "dddddddddddddddd")?,
    };
    Ok(cloak)
}
