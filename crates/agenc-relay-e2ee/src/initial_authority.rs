//! Public authority at an independently pinned ordinary genesis binding.
//!
//! The expected binding ID comes from trusted source state, never from the
//! evidence being imported. Its exact TBS pins the roots, rosters, initial
//! policy, context core and sequencer credential. Those pins permit checking
//! the named objects without their earlier directory history. This does not
//! establish directory continuity, global root-lock ancestry, later context
//! adoption, MLS leaf membership, finality or recovery completion.
//!
//! An ordinary group at semantic incarnation zero is the genesis of its
//! semantic route. An ordinary group at a later incarnation is the genesis
//! of a recreated route: it also needs the terminal of the incarnation
//! before it, the close its semantic route names, which only a validated
//! closed chain yields ([`PriorTerminal`], companion 9.4 and 11.5).

#![forbid(unsafe_code)]

mod anchors;
mod prior;

pub use prior::PriorTerminal;

use crate::context::verify_context_core;
use crate::error::E2eeError;
use crate::identity::ValidationTime;
use crate::ids::semantic_id_of;
use crate::limits::MAX_BINDING_PRINCIPALS;
use crate::object::{ArcWireObject, ArcWireObjectKind};
use crate::objects::conversation::{ArcContextCoreTbs, ArcConversationBindingPackage, ArcPolicy};
use crate::policy::{VerifiedPolicy, verify_policy};
use crate::route::{PrincipalRosters, VerifiedBinding, verify_binding_package};
use crate::sequencer::VerifiedSequencerCredential;
use crate::tls::{DecodeBudget, TlsDecode};
use agenc_relay_crypto::SemanticHashDomain;

/// Initial source identity established independently of the evidence upload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedInitialAuthority {
    /// Trusted network identity.
    pub network_id: [u8; 32],
    /// Trusted conversation identity.
    pub conversation_id: [u8; 32],
    /// Trusted semantic binding ID, not a transport object hash.
    pub binding_id: [u8; 32],
}

/// Exact public objects for one binding principal, in binding account order.
#[derive(Clone, Copy, Debug)]
pub struct InitialPrincipalEvidence<'a> {
    /// Complete `root_identity` wire object.
    pub root_object: &'a [u8],
    /// Complete `device_roster` wire object.
    pub roster_object: &'a [u8],
}

/// Borrowed public evidence. This is an API input, not a new wire format.
#[derive(Clone, Copy, Debug)]
pub struct InitialAuthorityEvidence<'a> {
    /// Complete `conversation_binding` wire object.
    pub binding_object: &'a [u8],
    /// Exact TLS `ArcContextCoreTBS`, which has no wire object arm or topic.
    pub context_core: &'a [u8],
    /// Complete generation-zero `policy` wire object.
    pub initial_policy_object: &'a [u8],
    /// Exact TLS `ArcSequencerCredential`, which has no wire object arm.
    pub sequencer_credential: &'a [u8],
    /// Exactly one root and roster pair per binding principal.
    pub principals: &'a [InitialPrincipalEvidence<'a>],
}

/// Initial public authority revalidated under the independent binding pin.
/// This value cannot clear a recovery gate or authorize a later context.
#[derive(Debug)]
pub struct InitialAuthority {
    binding: VerifiedBinding,
    principals: PrincipalRosters,
    policy: VerifiedPolicy,
    sequencer: VerifiedSequencerCredential,
    validation_time: ValidationTime,
    required_operational_policy_id: [u8; 32],
    prior_terminal: Option<PriorTerminal>,
}

impl InitialAuthority {
    /// Original binding, including its verified approvals and root locks.
    #[must_use]
    pub const fn binding(&self) -> &VerifiedBinding {
        &self.binding
    }

    /// Exact initial roots and rosters, independent of the current directory.
    #[must_use]
    pub const fn principals(&self) -> &PrincipalRosters {
        &self.principals
    }

    /// Initial policy only; publication does not prove later adoption.
    #[must_use]
    pub const fn policy(&self) -> &VerifiedPolicy {
        &self.policy
    }

    /// Credential selected directly by the trusted initial binding.
    #[must_use]
    pub const fn sequencer(&self) -> &VerifiedSequencerCredential {
        &self.sequencer
    }

    /// Canonical initial time committed by the context core.
    #[must_use]
    pub const fn validation_time(&self) -> ValidationTime {
        self.validation_time
    }

    /// Required future bootstrap policy ID; its body and adoption are unverified.
    #[must_use]
    pub const fn required_operational_policy_id(&self) -> &[u8; 32] {
        &self.required_operational_policy_id
    }

    /// The closed incarnation a recreated route follows; `None` at
    /// semantic incarnation zero.
    #[must_use]
    pub const fn prior_terminal(&self) -> Option<&PriorTerminal> {
        self.prior_terminal.as_ref()
    }
}

/// Revalidates public initial authority without mutating any caller state.
///
/// Only binding generation zero and semantic incarnation zero are supported
/// here: a recreated route, at a later incarnation, needs the terminal of the
/// incarnation before it ([`authenticate_recreated_authority`]), and
/// ReInit successors and replacements need their preceding terminal
/// evidence. An exact trusted pin replaces earlier directory chain traversal;
/// it does not prove the omitted continuity signatures. In particular, a new
/// current directory roster cannot replace a roster named by the binding.
///
/// One shared budget charges every decode. The caller must reserve work memory
/// for the bounded evidence and retain a charge for the returned public values.
/// No clock, directory, storage owner, MLS engine or recovery override is used.
pub fn authenticate_initial_authority(
    expected: &ExpectedInitialAuthority,
    evidence: &InitialAuthorityEvidence<'_>,
    budget: &mut DecodeBudget,
) -> Result<InitialAuthority, E2eeError> {
    authenticate(expected, None, evidence, budget)
}

/// Revalidates the public initial authority of a recreated ordinary route:
/// a generation-zero binding at semantic incarnation one or later whose
/// semantic route names, at the incarnation after it, exactly the close
/// `prior` ended (companion 9.4). The new binding is checked as every
/// genesis binding is, with its unanimous approvals, root locks and
/// bootstrap; `prior` comes from the validated chain whose lineage that
/// close ended ([`crate::history::HistoricalChain::prior_terminal`]), which
/// adopted the close only under its last finalized policy (companion 11.5).
/// A binding at incarnation zero, of another route key, a skipped
/// incarnation, another close, or the closed conversation itself is refused.
pub fn authenticate_recreated_authority(
    expected: &ExpectedInitialAuthority,
    prior: &PriorTerminal,
    evidence: &InitialAuthorityEvidence<'_>,
    budget: &mut DecodeBudget,
) -> Result<InitialAuthority, E2eeError> {
    authenticate(expected, Some(prior), evidence, budget)
}

fn authenticate(
    expected: &ExpectedInitialAuthority,
    prior: Option<&PriorTerminal>,
    evidence: &InitialAuthorityEvidence<'_>,
    budget: &mut DecodeBudget,
) -> Result<InitialAuthority, E2eeError> {
    if evidence.principals.is_empty() || evidence.principals.len() > MAX_BINDING_PRINCIPALS {
        return Err(E2eeError::LimitExceeded);
    }
    let package: ArcConversationBindingPackage = decode_object(
        evidence.binding_object,
        ArcWireObjectKind::ConversationBinding,
        budget,
    )?;
    anchors::binding(expected, prior, &package)?;
    let core = ArcContextCoreTbs::decode_exact(evidence.context_core, budget)?;
    let time = ValidationTime(core.initial_validation_time);
    let principals = anchors::principals(expected, &package, evidence.principals, time, budget)?;
    let binding = verify_binding_package(&expected.network_id, &package, &principals)?;
    verify_context_core(&expected.network_id, &core, &binding)?;
    anchors::core(&package.binding.tbs, &core)?;
    let policy: ArcPolicy = decode_object(
        evidence.initial_policy_object,
        ArcWireObjectKind::Policy,
        budget,
    )?;
    if semantic_id_of(SemanticHashDomain::PolicyId, &policy.tbs)? != core.initial_policy_id {
        return Err(E2eeError::InvalidValue);
    }
    let policy = verify_policy(
        &expected.network_id,
        &expected.conversation_id,
        &policy,
        &principals,
        None,
    )?;
    anchors::bootstrap(&package, &policy, &principals)?;
    let sequencer = anchors::sequencer(expected, evidence.sequencer_credential, &core, budget)?;
    Ok(InitialAuthority {
        binding,
        principals,
        policy,
        sequencer,
        validation_time: time,
        required_operational_policy_id: core.required_operational_policy_id,
        prior_terminal: prior.cloned(),
    })
}

fn decode_object<T: TlsDecode>(
    bytes: &[u8],
    kind: ArcWireObjectKind,
    budget: &mut DecodeBudget,
) -> Result<T, E2eeError> {
    let object = ArcWireObject::decode_kind(bytes, Some(kind), budget)?;
    T::decode_exact(object.body(), budget)
}
