//! The exact policy subject a device can review before its own approval exists.
use super::{
    ExpectedInitialAuthority, InitialPlanEvidence, InitialProposalScope, PolicyInput,
    check_proposal,
};
use crate::identity::VerifiedCertificate;
use crate::objects::conversation::ArcPolicyTbs;
use crate::{DecodeBudget, E2eeError};

/// The two distinct policy decisions made before a generation-zero binding can be signed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialPolicyStage {
    /// Review the unsigned generation-zero subject. Both policy IDs are already fixed.
    Bootstrap,
    /// Review generation one under the fully approved generation-zero predecessor.
    Operational,
}

/// Exact existing ARC wire values accepted for each policy review stage.
pub enum InitialPolicyInputs<'a> {
    /// Both canonical TLS-encoded policy TBS values, before any policy signature exists.
    Bootstrap {
        /// `ArcPolicyTbs` of the bootstrap generation.
        bootstrap_tbs: &'a [u8],
        /// `ArcPolicyTbs` of the planned operational generation.
        operational_tbs: &'a [u8],
    },
    /// The signed and quorum-verified predecessor and the canonical operational TBS.
    Operational {
        /// Complete registered policy envelope of generation zero.
        approved_bootstrap: &'a [u8],
        /// `ArcPolicyTbs` of generation one.
        operational_tbs: &'a [u8],
    },
}

/// Validated local review material for a device policy approval. Neither this value nor its
/// public context can become a verified policy, a verified binding, or signing authority.
pub struct InitialPolicyProposal {
    scope: InitialProposalScope,
    stage: InitialPolicyStage,
    bootstrap: ArcPolicyTbs,
    operational: ArcPolicyTbs,
    controller: [u8; 32],
}

impl InitialPolicyProposal {
    /// Exact independently pinned binding, plan, principal rosters, context and sequencer.
    pub fn scope(&self) -> &InitialProposalScope {
        &self.scope
    }
    /// The policy approval this review can request.
    pub fn stage(&self) -> InitialPolicyStage {
        self.stage
    }
    /// The two policy subjects whose semantic IDs the binding and context commit.
    pub fn policies(&self) -> (&ArcPolicyTbs, &ArcPolicyTbs) {
        (&self.bootstrap, &self.operational)
    }
    /// Canonical input to the existing policy-approval signature for this stage.
    pub fn subject(&self) -> &ArcPolicyTbs {
        match self.stage {
            InitialPolicyStage::Bootstrap => &self.bootstrap,
            InitialPolicyStage::Operational => &self.operational,
        }
    }

    /// Resolve a planned, policy-authorized device under the governing creator root.
    /// The endpoint still checks its independently held certificate, current time and grant.
    ///
    /// # Errors
    /// Refuses a different controller, unplanned device, unknown certificate or missing
    /// policy-approval flag.
    pub fn eligible_signer(
        &self,
        root: &[u8; 32],
        device: &[u8; 16],
    ) -> Result<&VerifiedCertificate, E2eeError> {
        if root != &self.controller
            || !self
                .scope
                .plan()
                .entries
                .as_slice()
                .iter()
                .any(|member| &member.root_fingerprint == root && &member.device_id == device)
        {
            return Err(E2eeError::InvalidValue);
        }
        let cert = crate::policy::active_device(self.scope.principals(), root, device)?;
        if !cert.may_approve_policy() {
            return Err(E2eeError::InvalidValue);
        }
        Ok(cert)
    }
}

/// Verify a prospective policy against the complete original binding/plan, both committed
/// policy subjects, directory heads and sequencer. A pending subject uses its canonical
/// `ArcPolicyTbs` encoding. Generation one also requires the complete approved bootstrap
/// policy in its registered ARC envelope.
///
/// # Errors
/// Refuses a partial or wrong-stage policy, insufficient predecessor authority, different
/// independently supplied pins, inconsistent route/plan/council, or exhausted decode budget.
pub fn review_initial_policy_proposal(
    expected: &ExpectedInitialAuthority,
    evidence: &InitialPlanEvidence<'_>,
    policies: InitialPolicyInputs<'_>,
    budget: &mut DecodeBudget,
) -> Result<InitialPolicyProposal, E2eeError> {
    let (stage, bootstrap, operational) = match policies {
        InitialPolicyInputs::Bootstrap {
            bootstrap_tbs,
            operational_tbs,
        } => (
            InitialPolicyStage::Bootstrap,
            PolicyInput::Subject(bootstrap_tbs),
            operational_tbs,
        ),
        InitialPolicyInputs::Operational {
            approved_bootstrap,
            operational_tbs,
        } => (
            InitialPolicyStage::Operational,
            PolicyInput::Approved(approved_bootstrap),
            operational_tbs,
        ),
    };
    let checked = check_proposal(
        expected,
        evidence,
        bootstrap,
        PolicyInput::Subject(operational),
        budget,
    )?;
    Ok(InitialPolicyProposal {
        scope: checked.scope,
        stage,
        bootstrap: checked.initial.subject,
        operational: checked.operational.subject,
        controller: checked.creator,
    })
}
