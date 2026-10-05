#![forbid(unsafe_code)]

//! A member that joins the successor after activation holds neither the
//! Proposal nor the epoch-1 GroupContext, so it checks its join bundle's
//! ReInit binding-chain and policy-chain entries against the target the
//! activation certificate's attempt carries (companion 9.5 and 13.8), and a
//! staged recipient checks its wrapper against the old finalization. Each
//! negative case edits one fact and relinks every hash that names it, so that
//! only the rule under test separates it from the accepted control.

use super::support::*;

use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_e2ee::ids::semantic_id_of;
use agenc_relay_e2ee::mls_outer::WelcomeHeader;
use agenc_relay_e2ee::objects::conversation::{
    ArcBindingApproval, ArcBindingChainEntry, ArcBindingProofKind, ArcConversationKind,
    ArcPolicyChainEntry, ArcPolicyProofKind, ArcRootBindingLock, ArcRootBindingLockTbs,
};
use agenc_relay_e2ee::objects::reinit::{ArcReInitActivationCertificate, ArcReInitTargetTbs};
use agenc_relay_e2ee::objects::sequencing::ArcSequencerRecord;
use agenc_relay_e2ee::reinit_target::AuthorizedReinit;
use agenc_relay_e2ee::welcome::VerifiedStagedReInit;
use agenc_relay_e2ee::{E2eeError, Opaque, TlsDecode, TlsVec};

/// What a later joiner holds for one successor: the two referenced
/// certificates and the join bundle's entries.
#[derive(Clone)]
struct Join {
    authorized: AuthorizedReinit,
    activation: ArcReInitActivationCertificate,
    previous: ArcBindingChainEntry,
    entry: ArcBindingChainEntry,
    policy: ArcPolicyChainEntry,
}

fn activation(file: &str) -> TestResult<ArcReInitActivationCertificate> {
    match record(file)? {
        ArcSequencerRecord::ReinitActivation(certificate) => Ok(certificate),
        _ => Err(format!("{file} is not an activation record").into()),
    }
}

fn join_of(suite: u16) -> TestResult<Join> {
    let prefix = format!("suite-{suite:04x}");
    Ok(Join {
        authorized: AuthorizedReinit::from_proof(&finalization_proof(&format!(
            "{prefix}-record-03-reinit-finalization.bin"
        ))?)?,
        activation: activation(&format!("{prefix}-record-05-activation.bin"))?,
        previous: ArcBindingChainEntry::decode_exact(
            &read("join-genesis-binding-entry.bin")?,
            &mut budget(),
        )?,
        entry: ArcBindingChainEntry::decode_exact(
            &read(&format!("{prefix}-join-binding-entry.bin"))?,
            &mut budget(),
        )?,
        policy: ArcPolicyChainEntry::decode_exact(
            &read(&format!("{prefix}-join-policy-entry.bin"))?,
            &mut budget(),
        )?,
    })
}

impl Join {
    fn check(&self) -> Result<(), E2eeError> {
        self.authorized.check_join_entries(
            &self.activation,
            &self.previous,
            &self.entry,
            &self.policy,
            &mut budget(),
        )
    }

    /// Recomputes the attempt ID the activation core names and the
    /// activation ID the certificate carries, after an edit of the attempt.
    fn relink(&mut self) -> TestResult {
        let request = &mut self.activation.tbs.request;
        request.core.reinit_attempt_id =
            semantic_id_of(SemanticHashDomain::ReinitAttemptId, &request.attempt.tbs)?;
        self.activation.tbs.reinit_activation_id =
            semantic_id_of(SemanticHashDomain::ReinitActivationId, &request.core)?;
        Ok(())
    }
}

/// One edit of a carried target.
type TargetEdit = (&'static str, fn(&mut ArcReInitTargetTbs));

/// One edit of the joiner's inputs, and whether the activation is relinked
/// after it.
type JoinEdit = (&'static str, bool, fn(&mut Join) -> TestResult);

fn refused(cases: &[JoinEdit]) -> TestResult {
    let control = join_of(1)?;
    for (name, relink, edit) in cases {
        let mut join = control.clone();
        edit(&mut join)?;
        if *relink {
            join.relink()?;
        }
        assert!(join.check().is_err(), "{name}");
    }
    Ok(())
}

#[test]
fn a_later_joiner_accepts_the_entries_of_the_carried_target() -> TestResult {
    for suite in [1_u16, 3] {
        let join = join_of(suite)?;
        join.check()?;
        let mut relinked = join.clone();
        relinked.relink()?;
        relinked.check()?;
        assert_eq!(
            relinked.activation.tbs.reinit_activation_id, join.activation.tbs.reinit_activation_id,
            "relinking the unedited activation changes nothing"
        );
        let carried = &join.activation.tbs.request.attempt.target;
        assert_eq!(
            semantic_id_of(SemanticHashDomain::ReinitTarget, carried)?,
            id(
                &format!("suite-{suite:04x}-target.bin"),
                "target_context_digest"
            )?
        );
    }

    // The advanced log authorized the suite-0x0001 target at another prior
    // state and activated it with its second attempt: the same entries.
    let mut advanced = join_of(1)?;
    advanced.authorized = AuthorizedReinit::from_proof(&finalization_proof(
        "advanced-record-07-reinit-finalization.bin",
    )?)?;
    advanced.activation = activation("advanced-record-11-activation.bin")?;
    advanced.check()?;

    // Another suite's entries, or another suite's activation, are refused.
    let one = join_of(1)?;
    let three = join_of(3)?;
    for (name, join) in [
        (
            "the other suite's entries",
            Join {
                authorized: one.authorized,
                activation: one.activation.clone(),
                ..three.clone()
            },
        ),
        (
            "the other suite's activation",
            Join {
                activation: three.activation.clone(),
                ..one.clone()
            },
        ),
        (
            "the other suite's binding entry",
            Join {
                entry: three.entry.clone(),
                ..one.clone()
            },
        ),
        (
            "the other suite's policy",
            Join {
                policy: three.policy.clone(),
                ..one.clone()
            },
        ),
    ] {
        assert_eq!(join.check(), Err(E2eeError::InvalidValue), "{name}");
    }
    Ok(())
}

#[test]
fn the_activation_attempt_must_carry_the_authorized_target() -> TestResult {
    let cases: [JoinEdit; 13] = [
        ("attempt names another finalization", true, |join| {
            join.activation.tbs.request.attempt.tbs.old_reinit_state_id = [9; 32];
            Ok(())
        }),
        ("attempt names another digest", true, |join| {
            join.activation
                .tbs
                .request
                .attempt
                .tbs
                .target_context_digest = [9; 32];
            Ok(())
        }),
        ("attempt carries another target", true, |join| {
            join.activation.tbs.request.attempt.target =
                ArcReInitTargetTbs::decode_exact(&read("suite-0003-target.bin")?, &mut budget())?;
            Ok(())
        }),
        ("attempt names another binding", true, |join| {
            join.activation.tbs.request.attempt.tbs.target_binding_id = [9; 32];
            Ok(())
        }),
        ("attempt names another plan", true, |join| {
            join.activation
                .tbs
                .request
                .attempt
                .tbs
                .initial_member_plan_id = [9; 32];
            Ok(())
        }),
        ("attempt names another suite", true, |join| {
            join.activation.tbs.request.attempt.tbs.target_suite = 3;
            Ok(())
        }),
        ("core names another finalization", true, |join| {
            join.activation.tbs.request.core.old_reinit_state_id = [9; 32];
            Ok(())
        }),
        ("core names another profile", true, |join| {
            join.activation.tbs.request.core.profile_version = 2;
            Ok(())
        }),
        ("core names another network", true, |join| {
            join.activation.tbs.request.core.network_id = [9; 32];
            Ok(())
        }),
        ("core names another old conversation", true, |join| {
            join.activation.tbs.request.core.old_conversation_id = [9; 32];
            Ok(())
        }),
        ("core names another successor", true, |join| {
            join.activation.tbs.request.core.new_conversation_id = [9; 32];
            Ok(())
        }),
        ("core names another attempt", false, |join| {
            join.activation.tbs.request.core.reinit_attempt_id = [9; 32];
            let core = &join.activation.tbs.request.core;
            join.activation.tbs.reinit_activation_id =
                semantic_id_of(SemanticHashDomain::ReinitActivationId, core)?;
            Ok(())
        }),
        ("another activation ID", false, |join| {
            join.activation.tbs.reinit_activation_id = [9; 32];
            Ok(())
        }),
    ];
    refused(&cases)
}

#[test]
fn the_carried_target_must_be_the_successor_of_the_preceding_binding() -> TestResult {
    // The preceding binding-chain entry stands in for the old conversation's
    // current binding: the carried target's binding must replace it.
    let cases: [JoinEdit; 6] = [
        ("a preceding entry of another conversation", false, |join| {
            join.previous.package.binding.tbs.conversation_id = [9; 32];
            Ok(())
        }),
        ("a preceding entry at another generation", false, |join| {
            join.previous.package.binding.tbs.binding_generation = 1;
            Ok(())
        }),
        ("a preceding entry at the last generation", false, |join| {
            join.previous.package.binding.tbs.binding_generation = u64::MAX;
            Ok(())
        }),
        ("a preceding entry with another route lock", false, |join| {
            join.previous.package.binding.tbs.semantic_route_lock_id = [9; 32];
            Ok(())
        }),
        ("a preceding entry with another route", false, |join| {
            join.previous.package.binding.tbs.route_binding = [9; 32];
            Ok(())
        }),
        (
            "a preceding entry with another channel instance",
            false,
            |join| {
                join.previous.package.binding.tbs.channel_instance_id = Opaque::new(vec![9; 16])?;
                Ok(())
            },
        ),
    ];
    refused(&cases)?;

    // A carried target whose derived fields are not the ones its list
    // yields, authorized and carried consistently: only the joiner's
    // rebuild of the list refuses it.
    let control = join_of(1)?;
    let edits: [TargetEdit; 4] = [
        ("context core", |target| {
            target.target_context_core_id = [9; 32]
        }),
        ("binding", |target| target.target_binding_id = [9; 32]),
        ("plan", |target| target.initial_member_plan_id = [9; 32]),
        ("extensions", |target| {
            if let Ok(extensions) = read("reject-extensions-duplicate-context.bin")
                && let Ok(extensions) = Opaque::new(extensions)
            {
                target.encoded_target_extensions = extensions;
            }
        }),
    ];
    for (name, edit) in edits {
        let mut join = control.clone();
        let attempt = &mut join.activation.tbs.request.attempt;
        edit(&mut attempt.target);
        let digest = semantic_id_of(SemanticHashDomain::ReinitTarget, &attempt.target)?;
        attempt.tbs.target_context_digest = digest;
        attempt.tbs.target_binding_id = attempt.target.target_binding_id;
        attempt.tbs.initial_member_plan_id = attempt.target.initial_member_plan_id;
        let mut proof = finalization_proof("suite-0001-record-03-reinit-finalization.bin")?;
        proof.authorization.tbs.transition_target_digest = digest;
        proof.core.commit_authorization_id = semantic_id_of(
            SemanticHashDomain::CommitAuthorizationId,
            &proof.authorization.tbs,
        )?;
        join.authorized = AuthorizedReinit::from_proof(&proof)?;
        attempt.tbs.old_reinit_state_id = *join.authorized.finalization_id();
        let core = &mut join.activation.tbs.request.core;
        core.old_reinit_state_id = *join.authorized.finalization_id();
        join.relink()?;
        assert!(join.check().is_err(), "{name}");
    }
    Ok(())
}

#[test]
fn the_reinit_binding_entry_must_be_the_carried_target_binding() -> TestResult {
    let cases: [JoinEdit; 15] = [
        ("another proof kind", false, |join| {
            join.entry.proof_kind = ArcBindingProofKind::CommitFinalizedTransition;
            Ok(())
        }),
        ("another context core", false, |join| {
            join.entry.package.binding.tbs.context_core_id = [9; 32];
            Ok(())
        }),
        ("another network", false, |join| {
            join.entry.package.binding.tbs.network_id = [9; 32];
            Ok(())
        }),
        ("another group", false, |join| {
            join.entry.package.binding.tbs.group_id = Opaque::new(vec![9; 32])?;
            Ok(())
        }),
        ("another version", false, |join| {
            join.entry.package.binding.tbs.mls_version = 2;
            Ok(())
        }),
        ("another suite", false, |join| {
            join.entry.package.binding.tbs.cipher_suite = 3;
            Ok(())
        }),
        ("another conversation", false, |join| {
            join.entry.package.binding.tbs.conversation_id = [9; 32];
            Ok(())
        }),
        ("another plan ID", false, |join| {
            join.entry.package.binding.tbs.initial_member_plan_id = [9; 32];
            Ok(())
        }),
        ("a plan that is not the named one", false, |join| {
            let mut entries = join
                .entry
                .package
                .initial_member_plan
                .entries
                .as_slice()
                .to_vec();
            entries.pop();
            join.entry.package.initial_member_plan.entries = TlsVec::new(entries)?;
            Ok(())
        }),
        ("the next generation but one", false, |join| {
            join.entry.package.binding.tbs.binding_generation = 2;
            Ok(())
        }),
        ("another previous binding", false, |join| {
            join.entry.package.binding.tbs.previous_binding_id = [9; 32];
            Ok(())
        }),
        ("another initial policy", false, |join| {
            join.entry.package.binding.tbs.initial_policy_id = [9; 32];
            Ok(())
        }),
        ("another operational policy", false, |join| {
            join.entry
                .package
                .binding
                .tbs
                .required_operational_policy_id = [9; 32];
            Ok(())
        }),
        ("an approved replacement", false, |join| {
            join.entry.package.binding.approvals = TlsVec::new(vec![ArcBindingApproval {
                signer_root_fingerprint: [9; 32],
                signer_device_id: [9; 16],
                signer_device_certificate_id: [9; 32],
                device_signature: [9; 64],
            }])?;
            Ok(())
        }),
        ("a replacement with a root lock", false, |join| {
            let tbs = ArcRootBindingLockTbs {
                profile_version: 1,
                network_id: [1; 32],
                account_id: Opaque::new(vec![b'c'; 24])?,
                root_fingerprint: [9; 32],
                root_binding_sequence: 1,
                previous_root_binding_lock_id: [9; 32],
                semantic_route_lock_id: [9; 32],
                binding_id: [9; 32],
                roster_generation: 0,
                roster_id: [9; 32],
            };
            join.entry.package.root_binding_locks = TlsVec::new(vec![ArcRootBindingLock {
                tbs,
                root_signature: [9; 64],
            }])?;
            Ok(())
        }),
    ];
    refused(&cases)
}

#[test]
fn the_reinit_policy_entry_must_be_the_carried_target_policy() -> TestResult {
    let cases: [JoinEdit; 10] = [
        ("another proof kind", false, |join| {
            join.policy.proof_kind = ArcPolicyProofKind::PolicyCommitFinalizedTransition;
            Ok(())
        }),
        ("another profile", false, |join| {
            join.policy.policy.tbs.profile_version = 2;
            Ok(())
        }),
        ("another network", false, |join| {
            join.policy.policy.tbs.network_id = [9; 32];
            Ok(())
        }),
        ("another conversation", false, |join| {
            join.policy.policy.tbs.conversation_id = [9; 32];
            Ok(())
        }),
        ("another kind", false, |join| {
            join.policy.policy.tbs.kind = ArcConversationKind::Direct;
            Ok(())
        }),
        ("another suite", false, |join| {
            join.policy.policy.tbs.selected_suite = 3;
            Ok(())
        }),
        ("a later generation", false, |join| {
            join.policy.policy.tbs.policy_generation = 1;
            Ok(())
        }),
        ("a predecessor", false, |join| {
            join.policy.policy.tbs.previous_policy_id = [9; 32];
            Ok(())
        }),
        ("another leaf bound", false, |join| {
            join.policy.policy.tbs.max_group_leaves += 1;
            Ok(())
        }),
        ("other approvals", false, |join| {
            let mut approvals = join.policy.policy.approvals.as_slice().to_vec();
            if let Some(first) = approvals.first_mut() {
                first.device_signature = [9; 64];
            }
            join.policy.policy.approvals = TlsVec::new(approvals)?;
            Ok(())
        }),
    ];
    refused(&cases)
}

/// A staged wrapper's verified facts, as `verify_staged_reinit` returns them.
fn staged(old_conversation_id: [u8; 32], old_reinit_state_id: [u8; 32]) -> VerifiedStagedReInit {
    VerifiedStagedReInit {
        old_conversation_id,
        new_conversation_id: [5; 32],
        old_reinit_state_id,
        reinit_attempt_id: [6; 32],
        welcome: WelcomeHeader {
            cipher_suite: 1,
            new_member_refs: Vec::new(),
            encrypted_group_info_len: 0,
        },
        references: Vec::new(),
    }
}

#[test]
fn a_staged_wrapper_must_name_this_finalization() -> TestResult {
    let authorized = join_of(1)?.authorized;
    let old = old_conversation()?;
    let finalization = *authorized.finalization_id();
    authorized.check_staged(&staged(old, finalization))?;
    for (name, wrapper) in [
        ("another finalization", staged(old, [9; 32])),
        ("the prior state", staged(old, *authorized.prior_state_id())),
        ("another old conversation", staged([9; 32], finalization)),
    ] {
        assert_eq!(
            authorized.check_staged(&wrapper),
            Err(E2eeError::InvalidValue),
            "{name}"
        );
    }
    Ok(())
}
