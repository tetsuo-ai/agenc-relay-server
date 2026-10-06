#![forbid(unsafe_code)]

//! Object declaration tests: representative structures of every family
//! round-trip byte for byte, and the record union is closed.

use std::error::Error;

use super::attach::*;
use super::conversation::*;
use super::federation::*;
use super::identity::*;
use super::recovery::*;
use super::reinit::*;
use super::sequencing::*;
use super::*;
use crate::object::ArcWireObjectKind;
use crate::tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode, TlsVec};

type TestResult = Result<(), Box<dyn Error>>;

fn budget() -> DecodeBudget {
    DecodeBudget::new(1 << 22, 1 << 16)
}

fn account() -> Result<AccountIdField, E2eeError> {
    Opaque::from_slice(&[b'a'; 24])
}

fn round_trip<T: TlsEncode + TlsDecode + PartialEq + core::fmt::Debug>(value: &T) -> TestResult {
    let encoded = value.encode()?;
    let decoded = T::decode_exact(&encoded, &mut budget())?;
    assert_eq!(&decoded, value);
    assert_eq!(decoded.encode()?, encoded);
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        T::decode_exact(&trailing, &mut budget()),
        Err(E2eeError::TrailingBytes)
    );
    let truncated = encoded.get(..encoded.len() - 1).unwrap_or_default();
    assert!(T::decode_exact(truncated, &mut budget()).is_err());
    Ok(())
}

fn root_identity(generation: u64) -> Result<ArcRootIdentity, E2eeError> {
    Ok(ArcRootIdentity {
        tbs: ArcRootIdentityTbs {
            profile_version: 1,
            network_id: [1; 32],
            account_id: account()?,
            root_generation: generation,
            root_public_key: [2; 32],
            not_before: 10,
            not_after: 20,
            previous_root_fingerprint: [0; 32],
        },
        self_signature: [3; 64],
        continuity_signature: Opaque::new(if generation == 0 {
            Vec::new()
        } else {
            vec![4; 64]
        })?,
    })
}

fn enrollment() -> Result<ArcDeviceEnrollment, E2eeError> {
    Ok(ArcDeviceEnrollment {
        tbs: ArcDeviceEnrollmentTbs {
            profile_version: 1,
            network_id: [1; 32],
            account_id: account()?,
            root_generation: 0,
            root_fingerprint: [5; 32],
            target_roster_generation: 0,
            enrollment_challenge: [6; 32],
            device_id: [7; 16],
            device_authorization_key: [8; 32],
            issued_at: 1,
            expires_at: 2,
        },
        new_device_signature: [9; 64],
        root_signature: [10; 64],
    })
}

fn certificate(device: u8) -> Result<ArcDeviceCertificate, E2eeError> {
    Ok(ArcDeviceCertificate {
        tbs: ArcDeviceCertificateTbs {
            profile_version: 1,
            network_id: [1; 32],
            account_id: account()?,
            root_generation: 0,
            root_fingerprint: [5; 32],
            device_id: [device; 16],
            device_authorization_key: [device; 32],
            target_roster_generation: 0,
            enrollment_challenge: [6; 32],
            enrollment_id: [11; 32],
            certificate_serial: 1,
            authorization_flags: 3,
            not_before: 0,
            not_after: 100,
        },
        enrollment_proof: enrollment()?,
        root_signature: [12; 64],
    })
}

fn roster() -> Result<ArcDeviceRoster, E2eeError> {
    Ok(ArcDeviceRoster {
        tbs: ArcDeviceRosterTbs {
            profile_version: 1,
            network_id: [1; 32],
            account_id: account()?,
            root_generation: 0,
            root_fingerprint: [5; 32],
            roster_generation: 0,
            not_before: 0,
            not_after: 100,
            previous_roster_id: [0; 32],
            active_devices: TlsVec::new(vec![
                ArcActiveDevice {
                    device_id: [7; 16],
                    certificate: certificate(7)?,
                },
                ArcActiveDevice {
                    device_id: [8; 16],
                    certificate: certificate(8)?,
                },
            ])?,
            revocations: TlsVec::new(vec![ArcDeviceRevocation {
                device_id: [9; 16],
                certificate_serial: 4,
                revoked_in_generation: 0,
                reason_code: 1,
            }])?,
        },
        root_signature: [13; 64],
    })
}

#[test]
fn identity_objects_round_trip() -> TestResult {
    round_trip(&root_identity(0)?)?;
    round_trip(&root_identity(1)?)?;
    round_trip(&certificate(7)?)?;
    round_trip(&roster()?)?;
    round_trip(&ArcDeviceCapabilities {
        tbs: ArcDeviceCapabilitiesTbs {
            profile_version: 1,
            network_id: [1; 32],
            account_id: account()?,
            root_fingerprint: [5; 32],
            roster_generation: 0,
            roster_id: [14; 32],
            device_id: [7; 16],
            capability_generation: 0,
            previous_capability_id: [0; 32],
            not_before: 0,
            not_after: 50,
            versions: TlsVec::new(vec![1])?,
            cipher_suites: TlsVec::new(vec![1, 3])?,
            extensions: TlsVec::new(vec![0xF1C1, 0xF1C3])?,
            proposals: TlsVec::new(vec![0xF1C2])?,
            credentials: TlsVec::new(vec![1])?,
        },
        device_signature: [15; 64],
    })?;
    round_trip(&ArcCredentialBundle {
        root: root_identity(0)?,
        device_certificate: certificate(7)?,
        leaf_authorization: ArcLeafAuthorization {
            tbs: ArcLeafAuthorizationTbs {
                profile_version: 1,
                network_id: [1; 32],
                account_id: account()?,
                root_generation: 0,
                root_fingerprint: [5; 32],
                roster_generation: 0,
                roster_id: [14; 32],
                device_id: [7; 16],
                credential_generation: 0,
                mls_version: 1,
                cipher_suite: 1,
                leaf_signature_scheme: 0x0807,
                leaf_signature_key: Opaque::new(vec![16; 32])?,
                leaf_capabilities_hash: [17; 32],
                package_nonce: [18; 32],
                last_resort: 0,
                not_before: 0,
                not_after: 40,
            },
            device_signature: [19; 64],
        },
    })?;
    round_trip(&ArcAccountRootChain {
        account_id: account()?,
        roots: TlsVec::new(vec![root_identity(0)?, root_identity(1)?])?,
    })?;
    Ok(())
}

fn policy() -> Result<ArcPolicy, E2eeError> {
    Ok(ArcPolicy {
        tbs: ArcPolicyTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: [20; 32],
            policy_generation: 0,
            previous_policy_id: [0; 32],
            kind: ArcConversationKind::Channel,
            membership_policy: ArcMembershipPolicy::Moderated,
            mls_version: 1,
            selected_suite: 1,
            allowed_suites: TlsVec::new(vec![1, 3])?,
            controller_root_fingerprints: Opaque::new(vec![5; 32])?,
            controller_threshold: 1,
            finality_principals: TlsVec::new(vec![ArcFinalityPrincipal {
                root_fingerprint: [5; 32],
                device_id: [7; 16],
                device_certificate_id: [21; 32],
            }])?,
            finality_fault_bound: 0,
            require_oob_verified_roots: 0,
            max_devices_per_account: 64,
            max_group_leaves: 512,
        },
        approvals: TlsVec::new(vec![ArcPolicyApproval {
            signer_root_fingerprint: [5; 32],
            signer_device_id: [7; 16],
            signer_device_certificate_id: [21; 32],
            device_signature: [22; 64],
        }])?,
    })
}

fn semantic_route() -> Result<ArcSemanticRouteTbs, E2eeError> {
    Ok(ArcSemanticRouteTbs {
        profile_version: 1,
        network_id: [1; 32],
        kind: ArcConversationKind::Channel,
        direct_account_a: Opaque::new(Vec::new())?,
        direct_account_b: Opaque::new(Vec::new())?,
        canonical_channel_name: Opaque::from_slice(b"#room")?,
        channel_authority_root_fingerprint: [5; 32],
        semantic_incarnation: 0,
        predecessor_close_id: [0; 32],
    })
}

fn binding_package() -> Result<ArcConversationBindingPackage, E2eeError> {
    Ok(ArcConversationBindingPackage {
        binding: ArcConversationBinding {
            tbs: ArcConversationBindingTbs {
                profile_version: 1,
                network_id: [1; 32],
                kind: ArcConversationKind::Channel,
                binding_generation: 0,
                previous_binding_id: [0; 32],
                semantic_route: semantic_route()?,
                semantic_route_lock_id: [23; 32],
                channel_instance_id: Opaque::new(vec![24; 16])?,
                conversation_nonce: Opaque::new(Vec::new())?,
                group_id: Opaque::new(vec![25; 32])?,
                conversation_id: [20; 32],
                route_binding: [26; 32],
                mls_version: 1,
                cipher_suite: 1,
                initial_policy_id: [27; 32],
                required_operational_policy_id: [28; 32],
                initial_member_plan_id: [29; 32],
                context_core_id: [30; 32],
                sequencer_credential_id: [31; 32],
                principals: TlsVec::new(vec![ArcBindingPrincipal {
                    account_id: account()?,
                    root_fingerprint: [5; 32],
                    roster_generation: 0,
                    roster_id: [14; 32],
                }])?,
            },
            approvals: TlsVec::new(vec![ArcBindingApproval {
                signer_root_fingerprint: [5; 32],
                signer_device_id: [7; 16],
                signer_device_certificate_id: [21; 32],
                device_signature: [32; 64],
            }])?,
        },
        initial_member_plan: ArcInitialMemberPlan {
            entries: TlsVec::new(vec![ArcInitialMemberPlanEntry {
                account_id: account()?,
                root_fingerprint: [5; 32],
                device_id: [7; 16],
                capability_id: [33; 32],
            }])?,
        },
        root_binding_locks: TlsVec::new(vec![ArcRootBindingLock {
            tbs: ArcRootBindingLockTbs {
                profile_version: 1,
                network_id: [1; 32],
                account_id: account()?,
                root_fingerprint: [5; 32],
                root_binding_sequence: 0,
                previous_root_binding_lock_id: [0; 32],
                semantic_route_lock_id: [23; 32],
                binding_id: [34; 32],
                roster_generation: 0,
                roster_id: [14; 32],
            },
            root_signature: [35; 64],
        }])?,
    })
}

fn sequencer_credential() -> Result<ArcSequencerCredential, E2eeError> {
    Ok(ArcSequencerCredential {
        tbs: ArcSequencerCredentialTbs {
            profile_version: 1,
            network_id: [1; 32],
            key_generation: 0,
            sequencer_public_key: [36; 32],
            not_before: 0,
            not_after: 1_000,
            previous_key_id: [0; 32],
        },
        continuity_signature: Opaque::new(Vec::new())?,
    })
}

#[test]
fn conversation_objects_round_trip() -> TestResult {
    round_trip(&policy()?)?;
    round_trip(&binding_package()?)?;
    round_trip(&ArcMlsContext {
        profile_version: 1,
        network_id: [1; 32],
        conversation_id: [20; 32],
        kind: ArcConversationKind::Channel,
        route_binding: [26; 32],
        initial_validation_time: 5,
        policy: policy()?,
        sequencer: sequencer_credential()?,
        current_binding: binding_package()?.binding,
        lifecycle: ArcConversationLifecycle {
            kind: ArcConversationLifecycleKind::ActiveConversation,
            close_intent_id: [0; 32],
        },
        private_topic: Opaque::from_slice(b"topic")?,
        bootstrap_pending: 1,
        roster_heads: TlsVec::new(vec![ArcRosterHead {
            account_id_digest: [37; 32],
            root_generation: 0,
            root_fingerprint: [5; 32],
            roster_generation: 0,
            roster_id: [14; 32],
        }])?,
        pending_joins: TlsVec::new(vec![ArcPendingJoin {
            leaf_index: 1,
            key_package_ref: Opaque::new(vec![38; 32])?,
        }])?,
    })?;
    round_trip(&ArcJoinAuthBundle {
        root_chains: TlsVec::new(vec![ArcAccountRootChain {
            account_id: account()?,
            roots: TlsVec::new(vec![root_identity(0)?])?,
        }])?,
        binding_chain: TlsVec::new(vec![ArcBindingChainEntry {
            package: binding_package()?,
            proof_kind: ArcBindingProofKind::RootLockedGenesis,
        }])?,
        policy_chain: TlsVec::new(vec![ArcPolicyChainEntry {
            policy: policy()?,
            proof_kind: ArcPolicyProofKind::PolicyRootLockedGenesis,
        }])?,
        roster_chain: TlsVec::new(vec![roster()?])?,
    })?;
    round_trip(&ArcReservation {
        tbs: ArcReservationTbs {
            profile_version: 1,
            network_id: [1; 32],
            reservation_id: [39; 16],
            kind: ArcConversationKind::Direct,
            route_binding: [40; 32],
            channel_instance_id: Opaque::new(Vec::new())?,
            conversation_nonce: Opaque::new(vec![41; 32])?,
            sequencer: sequencer_credential()?,
            application_object_limit: 65_536,
            live_object_limit: 262_144,
            key_package_object_limit: 65_536,
            identity_object_limit: 65_536,
            root_chain_object_limit: 1_048_576,
            roster_object_limit: 65_536,
            capability_object_limit: 65_536,
            binding_object_limit: 262_144,
            commit_approval_object_limit: 65_536,
            commit_ack_object_limit: 65_536,
            finalization_object_limit: 4_190_000,
            abort_object_limit: 1_048_576,
            reinit_object_limit: 4_190_000,
            close_object_limit: 32_768,
            welcome_object_limit: 4_194_304,
            live_part_limit: 90,
            mailbox_part_limit: 1_427,
            expires_at: 60,
        },
        sequencer_signature: [42; 64],
    })?;
    round_trip(&ArcCloseAuthorization {
        tbs: ArcCloseAuthorizationTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: [20; 32],
            binding_id: [34; 32],
            authorizing_terminal_id: [43; 32],
            close_intent: ArcCloseIntent {
                reason_code: 1,
                validation_time: 9,
            },
            close_intent_id: [44; 32],
        },
        approvals: TlsVec::new(vec![ArcCommitApproval {
            signer_root_fingerprint: [5; 32],
            signer_device_id: [7; 16],
            signer_device_certificate_id: [21; 32],
            device_signature: [45; 64],
        }])?,
    })?;
    round_trip(&ArcJoinTransitionProofBundle {
        references: TlsVec::new(vec![ArcJoinTransitionProofReference {
            subject_kind: ArcJoinTransitionSubject::PolicySubject,
            subject_id: [46; 32],
            proof_role: ArcJoinTransitionProofRole::FinalizedGroupTransition,
            record_conversation_id: [20; 32],
            authorizing_record_id: [47; 32],
            authorizing_object_id: [48; 32],
        }])?,
    })?;
    Ok(())
}

fn receipt() -> ArcCandidateReceipt {
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

fn finalization() -> Result<ArcCommitFinalizationCertificate, E2eeError> {
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

#[test]
fn sequencing_objects_and_the_record_union_round_trip() -> TestResult {
    round_trip(&receipt())?;
    round_trip(&ArcCommitApprovalEnvelope {
        tbs: authorization()?.tbs,
        approval: ArcCommitApproval {
            signer_root_fingerprint: [5; 32],
            signer_device_id: [7; 16],
            signer_device_certificate_id: [21; 32],
            device_signature: [63; 64],
        },
    })?;
    round_trip(&ack()?)?;
    round_trip(&finalization()?)?;
    let abort = ArcCommitAbortCertificate {
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
    };
    round_trip(&abort)?;
    round_trip(&ArcDeliveredWelcome {
        profile_version: 1,
        network_id: [1; 32],
        conversation_id: [20; 32],
        target_account_id_digest: [37; 32],
        target_device_id: [8; 16],
        authorization: ArcNormalJoinAuthorizationProof {
            finalization_id: [58; 32],
            finalization_object_id: [67; 32],
            added_key_package_ref: Opaque::new(vec![38; 32])?,
            resulting_leaf_index: 1,
            resulting_leaf_credential_hash: [68; 32],
        },
        transition_proofs: ArcJoinTransitionProofBundle {
            references: TlsVec::new(Vec::new())?,
        },
        welcome_bytes: Opaque::new(vec![69; 200])?,
    })?;
    for record in [
        ArcSequencerRecord::Candidate(receipt()),
        ArcSequencerRecord::Finalization(finalization()?),
        ArcSequencerRecord::Abort(abort),
    ] {
        round_trip(&record)?;
        let encoded = record.encode()?;
        assert_eq!(encoded.first().copied(), Some(record.kind().value()));
    }
    assert_eq!(
        ArcSequencerRecord::decode_exact(&[9, 0], &mut budget()),
        Err(E2eeError::UnknownDiscriminant)
    );
    Ok(())
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

fn reinit_attempt() -> Result<ArcReInitAttempt, E2eeError> {
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

fn attempt_receipt() -> ArcReInitAttemptReceipt {
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

#[test]
fn reinit_objects_round_trip() -> TestResult {
    round_trip(&reinit_target()?)?;
    round_trip(&reinit_attempt()?)?;
    round_trip(&attempt_receipt())?;
    round_trip(&ArcStagedReInit {
        old_reinit_state_id: [58; 32],
        old_reinit_finalization_object_id: [67; 32],
        receipt: attempt_receipt(),
        new_conversation_id: [70; 32],
        target_account_id_digest: [37; 32],
        target_device_id: [8; 16],
        transition_proofs: ArcJoinTransitionProofBundle {
            references: TlsVec::new(Vec::new())?,
        },
        welcome_bytes: Opaque::new(vec![88; 300])?,
    })?;
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
    round_trip(&reinit_ack)?;
    let activation = ArcReInitActivationCertificate {
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
    };
    round_trip(&activation)?;
    let abort = ArcReInitAbortCertificate {
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
    };
    round_trip(&abort)?;
    for record in [
        ArcSequencerRecord::ReinitAttempt(attempt_receipt()),
        ArcSequencerRecord::ReinitActivation(activation),
        ArcSequencerRecord::ReinitAbort(abort),
    ] {
        round_trip(&record)?;
    }
    round_trip(&ArcReInitDispositionVoteTbs {
        profile_version: 1,
        network_id: [1; 32],
        old_conversation_id: [20; 32],
        old_reinit_state_id: [58; 32],
        attempt_sequence: 0,
        slot_predecessor_record_id: [58; 32],
        reinit_attempt_id: [85; 32],
        disposition: ArcReInitDisposition::ActivateReinit,
        terminal_id: [90; 32],
        reason_code: 0,
    })?;
    Ok(())
}

#[test]
fn attach_aad_and_recovery_objects_round_trip() -> TestResult {
    let challenge = ArcDeviceAttachChallenge {
        tbs: ArcDeviceAttachTbs {
            profile_version: 1,
            network_id: [1; 32],
            account_id: account()?,
            device_id: [7; 16],
            connection_nonce: [96; 32],
            server_challenge: [97; 32],
            session_generation: 1,
            issued_at: 1,
            expires_at: 61,
        },
        sequencer_signature: [98; 64],
    };
    round_trip(&challenge)?;
    round_trip(&ArcDeviceAttach {
        challenge,
        device_signature: [99; 64],
    })?;
    round_trip(&super::aad::ArcApplicationAad {
        profile_version: 1,
        network_id: [1; 32],
        conversation_id: [20; 32],
        route_binding: [26; 32],
        latest_state_id: [58; 32],
    })?;
    round_trip(&super::aad::ArcCommitAad {
        profile_version: 1,
        network_id: [1; 32],
        conversation_id: [20; 32],
        route_binding: [26; 32],
        validation_time: 7,
        prior_state_id: [50; 32],
    })?;
    round_trip(&E2eeServerRecoveryGate {
        recovery_gate_version: 1,
        conversation_id: [20; 32],
        state: E2eeServerRecoveryKind::Pending,
        recovery_epoch: [100; 16],
        restored_binding_id: [34; 32],
        restored_accepted_state_id: [58; 32],
        restored_sequencer_head_id: [52; 32],
        source_rollback_guard_hash: [101; 32],
    })?;
    Ok(())
}

#[test]
fn federation_objects_round_trip() -> TestResult {
    round_trip(&ArcFederationRequest {
        profile_version: 1,
        network_id: [1; 32],
        home_server_id: [102; 16],
        server_incarnation: [103; 16],
        origin_id: [104; 16],
        origin_generation: 0,
        operation_sequence: 0,
        request_id: [105; 16],
        opcode: ArcFederationOpcode::SubmitCandidate,
        encoded_parameters: Opaque::new(vec![20; 32])?,
        payload_object_id: Opaque::new(vec![49; 32])?,
    })?;
    round_trip(&ArcFederationResult {
        profile_version: 1,
        network_id: [1; 32],
        home_server_id: [102; 16],
        server_incarnation: [103; 16],
        origin_id: [104; 16],
        origin_generation: 0,
        operation_sequence: 0,
        request_id: [105; 16],
        request_object_id: [106; 32],
        coordinator_state_generation: 4,
        completion_event_id: Opaque::new(vec![107; 16])?,
        result_kind: ArcFederationResultKind::MailboxPage,
        encoded_result: Opaque::new(Vec::new())?,
        snapshot_token: Opaque::new(vec![108; 32])?,
        next_cursor: Opaque::new(Vec::new())?,
        responses: TlsVec::new(vec![ArcFederationResponseDescriptor {
            response_index: 0,
            wire_kind: ArcWireObjectKind::WelcomeMls,
            object_id: [109; 32],
            total_size: 500,
            delivery_token: Opaque::new(vec![110; 32])?,
            target_device_id: Opaque::new(vec![8; 16])?,
        }])?,
    })?;
    round_trip(&ArcFederationEvent {
        profile_version: 1,
        network_id: [1; 32],
        target_server_id: [111; 16],
        delivery_generation: 0,
        coordinator_state_generation: 4,
        delivery_sequence: 0,
        event_id: [112; 16],
        event_kind: ArcFederationEventKind::CandidateEvent,
        cross_profile_mutation_id: Opaque::new(Vec::new())?,
        cross_profile_part_index: 0,
        cross_profile_part_count: 0,
        conversation_id: Opaque::new(vec![20; 32])?,
        route_sequence: 0,
        origin_id: Opaque::new(vec![104; 16])?,
        origin_generation: 0,
        source_view: Opaque::new(
            ArcFederationSourceView {
                user_id: [113; 16],
                nickname: Opaque::from_slice(b"kate")?,
                public_user_component: [b'u'; 10],
                public_host_component: [b'h'; 16],
                account_label: Opaque::new(Vec::new())?,
            }
            .encode()?,
        )?,
        request_home_server_id: Opaque::new(vec![102; 16])?,
        request_server_incarnation: Opaque::new(vec![103; 16])?,
        request_origin_id: Opaque::new(vec![104; 16])?,
        request_origin_generation: 0,
        request_operation_sequence: 0,
        request_id: Opaque::new(vec![105; 16])?,
        payload_object_id: Opaque::new(vec![49; 32])?,
        encoded_event_result: Opaque::new(receipt().encode()?)?,
    })?;
    round_trip(&ArcFederationOrigin {
        profile_version: 1,
        network_id: [1; 32],
        home_server_id: [102; 16],
        server_incarnation: [103; 16],
        origin_id: [104; 16],
        origin_generation: 0,
        previous_origin_state_id: [0; 32],
        connection_id: [114; 16],
        session_id: Opaque::new(vec![115; 16])?,
        user_id: Opaque::new(vec![113; 16])?,
        account_id: Opaque::new(vec![b'a'; 24])?,
        account_session_generation: 1,
        connection_nonce: [96; 32],
        attached_device_id: Opaque::new(vec![7; 16])?,
        device_session_generation: 1,
    })?;
    round_trip(&ArcFederationRouteState {
        profile_version: 1,
        network_id: [1; 32],
        state_generation: 4,
        conversation_id: [20; 32],
        conversation_kind: ArcConversationKind::Channel,
        route_binding: [26; 32],
        semantic_route_lock_id: [23; 32],
        channel_instance_id: Opaque::new(vec![24; 16])?,
        canonical_channel_name_hash: [116; 32],
        direct_account_a: Opaque::new(Vec::new())?,
        direct_account_b: Opaque::new(Vec::new())?,
        binding_id: [34; 32],
        finalized_epoch: 1,
        accepted_state_id: [58; 32],
        sequencer_record_head_sequence: 1,
        sequencer_record_head_id: [58; 32],
        state: ArcRouteStateKind::ActiveRoute,
    })?;
    round_trip(
        &crate::objects::federation::ArcFederationWitnessResolution {
            profile_version: 1,
            network_id: [1; 32],
            coordinator_server_id: [102; 16],
            target_server_id: [111; 16],
            conversation_id: [20; 32],
            resolution_token: [117; 16],
            expected_sequence: 5,
            expected_head_id: [58; 32],
            record_count: 2,
            new_head_sequence: 6,
            new_head_id: [59; 32],
            record_object_ids: Opaque::new([[60_u8; 32], [61; 32]].concat())?,
        },
    )?;
    // The vector holds exactly `MAX_WITNESS_RESOLUTION_RECORDS` identifiers.
    assert_eq!(
        usize::try_from(crate::limits::MAX_WITNESS_RESOLUTION_RECORDS)? * 32,
        32_768
    );
    assert_eq!(ArcFederationOpcode::ALL.len(), 44);
    assert_eq!(ArcFederationOpcode::SubmitRecovery.value(), 42);
    assert_eq!(ArcFederationOpcode::SubmitRecoveryElement.value(), 43);
    assert_eq!(ArcFederationOpcode::SubmitMembership.value(), 44);
    assert_eq!(
        crate::objects::federation::ArcFederationStoreKind::StoreMembership.value(),
        11
    );
    assert_eq!(ArcFederationResultKind::ALL.len(), 27);
    assert_eq!(ArcFederationResultKind::RecoveryConflict.value(), 27);
    assert_eq!(ArcFederationEventKind::ALL.len(), 14);
    assert_eq!(ArcFederationEmptyKind::ALL.len(), 14);
    Ok(())
}

#[test]
fn shape_helpers_enforce_semantic_lengths() -> TestResult {
    assert_eq!(account_id_bytes(&account()?)?, [b'a'; 24]);
    assert_eq!(
        account_id_bytes(&Opaque::from_slice(b"short")?),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(group_id_bytes(&Opaque::new(vec![1; 32])?)?, [1; 32]);
    assert_eq!(
        group_id_bytes(&Opaque::new(vec![1; 31])?),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(boolean(0), Ok(false));
    assert_eq!(boolean(1), Ok(true));
    assert_eq!(boolean(2), Err(E2eeError::InvalidValue));
    Ok(())
}
