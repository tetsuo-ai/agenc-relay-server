#![forbid(unsafe_code)]
//! Canonical record shapes with synthetic endpoint proofs. Tests replace the
//! outer sequencer signatures with real signatures. These fixtures exercise
//! record authentication only, not MLS processing or a finalized lifecycle.
use agenc_relay_e2ee::objects::AccountIdField;
use agenc_relay_e2ee::objects::conversation::*;
use agenc_relay_e2ee::objects::reinit::*;
use agenc_relay_e2ee::objects::sequencing::*;
use agenc_relay_e2ee::{E2eeError, Opaque, TlsVec};

fn account() -> Result<AccountIdField, E2eeError> {
    Opaque::from_slice(&[b'a'; 24])
}

pub(super) fn receipt() -> ArcCandidateReceipt {
    ArcCandidateReceipt {
        tbs: ArcCandidateReceiptTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: [20; 32],
            route_sequence: 0,
            prior_epoch: 0,
            resulting_epoch: 1,
            candidate_sequence: 0,
            commit_object_id: [49; 32],
            prior_state_id: [50; 32],
            predecessor_record_id: [50; 32],
            sequenced_at: 7,
            sequencer_key_id: [31; 32],
        },
        sequencer_signature: [51; 64],
    }
}

fn authorization() -> Result<ArcCommitAuthorization, E2eeError> {
    Ok(ArcCommitAuthorization {
        tbs: ArcCommitAuthorizationTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: [20; 32],
            prior_epoch: 0,
            prior_state_id: [50; 32],
            candidate_id: [52; 32],
            commit_object_id: [49; 32],
            canonical_validation_time: 7,
            old_policy_id: [27; 32],
            authorization_rule: ArcCommitAuthorizationRule::RoutineSelfUpdate,
            action_bits: 0,
            resulting_policy_id: [27; 32],
            resulting_group_context_digest: [53; 32],
            resulting_ratchet_tree_digest: [54; 32],
            transition_target_digest: [0; 32],
        },
        approvals: TlsVec::new(Vec::new())?,
    })
}

fn ack() -> Result<ArcCommitAck, E2eeError> {
    Ok(ArcCommitAck {
        tbs: ArcCommitAckTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: [20; 32],
            prior_epoch: 0,
            candidate_id: [52; 32],
            commit_object_id: [49; 32],
            old_leaf_index: 0,
            old_credential_hash: [55; 32],
            resulting_epoch: 1,
            resulting_group_context_digest: [53; 32],
            resulting_ratchet_tree_digest: [54; 32],
            finalization_authenticator: [56; 32],
        },
        old_leaf_signature: Opaque::new(vec![57; 64])?,
    })
}

pub(super) fn finalization() -> Result<ArcCommitFinalizationCertificate, E2eeError> {
    Ok(ArcCommitFinalizationCertificate {
        tbs: ArcCommitFinalizationTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: [20; 32],
            route_sequence: 1,
            predecessor_record_id: [52; 32],
            finalization_id: [58; 32],
            sequencer_key_id: [31; 32],
            request: ArcFinalizationRequest {
                proof: ArcFinalizationProof {
                    core: ArcFinalizationCoreTbs {
                        profile_version: 1,
                        network_id: [1; 32],
                        conversation_id: [20; 32],
                        prior_epoch: 0,
                        prior_state_id: [50; 32],
                        candidate_id: [52; 32],
                        commit_object_id: [49; 32],
                        resulting_epoch: 1,
                        old_policy_id: [27; 32],
                        commit_authorization_id: [59; 32],
                        acknowledgement_set_digest: [60; 32],
                        resulting_group_context_digest: [53; 32],
                        resulting_ratchet_tree_digest: [54; 32],
                        finalization_authenticator: [56; 32],
                    },
                    receipt: receipt(),
                    authorization: authorization()?,
                    acknowledgements: TlsVec::new(vec![ack()?])?,
                },
                votes: TlsVec::new(vec![ArcFinalityVote {
                    signer_root_fingerprint: [5; 32],
                    signer_device_id: [7; 16],
                    signer_device_certificate_id: [21; 32],
                    device_signature: [61; 64],
                }])?,
            },
        },
        sequencer_signature: [62; 64],
    })
}

fn reinit_target() -> Result<ArcReInitTargetTbs, E2eeError> {
    Ok(ArcReInitTargetTbs {
        profile_version: 1,
        network_id: [1; 32],
        old_conversation_id: [20; 32],
        new_conversation_id: [70; 32],
        target_group_id: Opaque::new(vec![71; 32])?,
        target_version: 1,
        target_suite: 3,
        target_context_core_id: [86; 32],
        target_binding_id: [73; 32],
        initial_member_plan_id: [29; 32],
        encoded_target_extensions: Opaque::new(vec![87; 40])?,
    })
}

pub(super) fn reinit_attempt() -> Result<ArcReInitAttempt, E2eeError> {
    Ok(ArcReInitAttempt {
        tbs: ArcReInitAttemptTbs {
            profile_version: 1,
            network_id: [1; 32],
            old_conversation_id: [20; 32],
            new_conversation_id: [70; 32],
            old_reinit_state_id: [58; 32],
            attempt_sequence: 0,
            creator_old_leaf_index: 0,
            creator_old_credential_hash: [55; 32],
            target_group_id: Opaque::new(vec![71; 32])?,
            target_version: 1,
            target_suite: 3,
            target_context_digest: [72; 32],
            target_binding_id: [73; 32],
            initial_member_plan_id: [29; 32],
            key_package_plan_id: [74; 32],
            initial_commit_digest: [75; 32],
            attempt_authorization_id: [76; 32],
            new_group_info_digest: [77; 32],
            new_group_context_digest: [78; 32],
            new_ratchet_tree_digest: [79; 32],
            new_exporter_authenticator: [80; 32],
        },
        target: reinit_target()?,
        key_package_plan: ArcKeyPackagePlan {
            entries: TlsVec::new(vec![ArcKeyPackagePlanEntry {
                account_id: account()?,
                root_fingerprint: [5; 32],
                device_id: [7; 16],
                capability_id: [33; 32],
                key_package_ref: Opaque::new(Vec::new())?,
                leaf_signature_scheme: 0x0807,
                leaf_signature_key_digest: [81; 32],
                creator: 1,
            }])?,
        },
        initial_commit_bytes: Opaque::new(vec![82; 100])?,
        authorization: ArcReInitAttemptAuthorization {
            tbs: ArcReInitAttemptAuthorizationTbs {
                profile_version: 1,
                network_id: [1; 32],
                old_conversation_id: [20; 32],
                old_reinit_state_id: [58; 32],
                attempt_sequence: 0,
                creator_old_leaf_index: 0,
                creator_old_credential_hash: [55; 32],
                new_conversation_id: [70; 32],
                target_context_digest: [72; 32],
                target_binding_id: [73; 32],
                initial_member_plan_id: [29; 32],
                key_package_plan_id: [74; 32],
                initial_commit_digest: [75; 32],
                new_group_info_digest: [77; 32],
                new_group_context_digest: [78; 32],
                new_ratchet_tree_digest: [79; 32],
                new_exporter_authenticator: [80; 32],
            },
            approvals: TlsVec::new(vec![ArcCommitApproval {
                signer_root_fingerprint: [5; 32],
                signer_device_id: [7; 16],
                signer_device_certificate_id: [21; 32],
                device_signature: [83; 64],
            }])?,
        },
        creator_old_leaf_signature: Opaque::new(vec![84; 64])?,
    })
}

pub(super) fn attempt_receipt() -> ArcReInitAttemptReceipt {
    ArcReInitAttemptReceipt {
        tbs: ArcReInitAttemptReceiptTbs {
            profile_version: 1,
            network_id: [1; 32],
            old_conversation_id: [20; 32],
            old_reinit_state_id: [58; 32],
            route_sequence: 2,
            attempt_sequence: 0,
            predecessor_record_id: [58; 32],
            reinit_attempt_id: [85; 32],
            attempt_object_id: [86; 32],
            sequenced_at: 8,
            sequencer_key_id: [31; 32],
        },
        sequencer_signature: [87; 64],
    }
}

pub(super) fn abort() -> Result<ArcCommitAbortCertificate, E2eeError> {
    Ok(ArcCommitAbortCertificate {
        tbs: ArcCommitAbortTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: [20; 32],
            route_sequence: 1,
            predecessor_record_id: [52; 32],
            abort_id: [64; 32],
            sequencer_key_id: [31; 32],
            request: ArcAbortRequest {
                core: ArcAbortCoreTbs {
                    profile_version: 1,
                    network_id: [1; 32],
                    conversation_id: [20; 32],
                    prior_state_id: [50; 32],
                    candidate_id: [52; 32],
                    prior_epoch: 0,
                    reason: ArcCommitAbortReason::StagingTimeout,
                    evidence_digest: [65; 32],
                },
                receipt: receipt(),
                votes: TlsVec::new(Vec::new())?,
            },
        },
        sequencer_signature: [66; 64],
    })
}

pub(super) fn activation() -> Result<ArcReInitActivationCertificate, E2eeError> {
    let reinit_ack = ArcReInitAck {
        tbs: ArcReInitAckTbs {
            profile_version: 1,
            network_id: [1; 32],
            old_conversation_id: [20; 32],
            new_conversation_id: [70; 32],
            old_reinit_state_id: [58; 32],
            reinit_attempt_id: [85; 32],
            ack_kind: ArcReInitAckKind::CreatorState,
            new_group_info_digest: [77; 32],
            new_group_context_digest: [78; 32],
            new_ratchet_tree_digest: [79; 32],
            new_exporter_authenticator: [80; 32],
            old_leaf_index: 0,
            old_credential_hash: [55; 32],
            new_leaf_index: 0,
            key_package_ref: Opaque::new(Vec::new())?,
        },
        old_leaf_signature: Opaque::new(vec![89; 64])?,
    };
    Ok(ArcReInitActivationCertificate {
        tbs: ArcReInitActivationTbs {
            profile_version: 1,
            network_id: [1; 32],
            old_conversation_id: [20; 32],
            route_sequence: 3,
            predecessor_record_id: [85; 32],
            reinit_activation_id: [90; 32],
            sequencer_key_id: [31; 32],
            request: ArcReInitActivationRequest {
                core: ArcReInitActivationCoreTbs {
                    profile_version: 1,
                    network_id: [1; 32],
                    old_conversation_id: [20; 32],
                    new_conversation_id: [70; 32],
                    old_reinit_state_id: [58; 32],
                    attempt_sequence: 0,
                    reinit_attempt_id: [85; 32],
                    new_group_info_digest: [77; 32],
                    new_group_context_digest: [78; 32],
                    new_ratchet_tree_digest: [79; 32],
                    new_exporter_authenticator: [80; 32],
                    acknowledgement_set_digest: [91; 32],
                },
                receipt: attempt_receipt(),
                attempt: reinit_attempt()?,
                acknowledgements: TlsVec::new(vec![reinit_ack])?,
                votes: TlsVec::new(Vec::new())?,
            },
        },
        sequencer_signature: [92; 64],
    })
}

pub(super) fn reinit_abort() -> Result<ArcReInitAbortCertificate, E2eeError> {
    Ok(ArcReInitAbortCertificate {
        tbs: ArcReInitAbortTbs {
            profile_version: 1,
            network_id: [1; 32],
            old_conversation_id: [20; 32],
            route_sequence: 3,
            predecessor_record_id: [85; 32],
            reinit_abort_id: [93; 32],
            sequencer_key_id: [31; 32],
            request: ArcReInitAbortRequest {
                core: ArcReInitAbortCoreTbs {
                    profile_version: 1,
                    network_id: [1; 32],
                    old_conversation_id: [20; 32],
                    old_reinit_state_id: [58; 32],
                    attempt_sequence: 0,
                    slot_predecessor_record_id: [58; 32],
                    reinit_attempt_id: [85; 32],
                    reason_code: 5,
                    evidence_digest: [94; 32],
                },
                receipt: attempt_receipt(),
                attempt: reinit_attempt()?,
                votes: TlsVec::new(Vec::new())?,
            },
        },
        sequencer_signature: [95; 64],
    })
}
