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
use crate::object::IrcWireObjectKind;
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

fn root_identity(generation: u64) -> Result<IrcRootIdentity, E2eeError> {
    Ok(IrcRootIdentity {
        tbs: IrcRootIdentityTbs {
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

fn enrollment() -> Result<IrcDeviceEnrollment, E2eeError> {
    Ok(IrcDeviceEnrollment {
        tbs: IrcDeviceEnrollmentTbs {
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

fn certificate(device: u8) -> Result<IrcDeviceCertificate, E2eeError> {
    Ok(IrcDeviceCertificate {
        tbs: IrcDeviceCertificateTbs {
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

fn roster() -> Result<IrcDeviceRoster, E2eeError> {
    Ok(IrcDeviceRoster {
        tbs: IrcDeviceRosterTbs {
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
                IrcActiveDevice {
                    device_id: [7; 16],
                    certificate: certificate(7)?,
                },
                IrcActiveDevice {
                    device_id: [8; 16],
                    certificate: certificate(8)?,
                },
            ])?,
            revocations: TlsVec::new(vec![IrcDeviceRevocation {
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
    round_trip(&IrcDeviceCapabilities {
        tbs: IrcDeviceCapabilitiesTbs {
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
    round_trip(&IrcCredentialBundle {
        root: root_identity(0)?,
        device_certificate: certificate(7)?,
        leaf_authorization: IrcLeafAuthorization {
            tbs: IrcLeafAuthorizationTbs {
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
    round_trip(&IrcAccountRootChain {
        account_id: account()?,
        roots: TlsVec::new(vec![root_identity(0)?, root_identity(1)?])?,
    })?;
    Ok(())
}

fn policy() -> Result<IrcPolicy, E2eeError> {
    Ok(IrcPolicy {
        tbs: IrcPolicyTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: [20; 32],
            policy_generation: 0,
            previous_policy_id: [0; 32],
            kind: IrcConversationKind::Channel,
            membership_policy: IrcMembershipPolicy::Moderated,
            mls_version: 1,
            selected_suite: 1,
            allowed_suites: TlsVec::new(vec![1, 3])?,
            controller_root_fingerprints: Opaque::new(vec![5; 32])?,
            controller_threshold: 1,
            finality_principals: TlsVec::new(vec![IrcFinalityPrincipal {
                root_fingerprint: [5; 32],
                device_id: [7; 16],
                device_certificate_id: [21; 32],
            }])?,
            finality_fault_bound: 0,
            require_oob_verified_roots: 0,
            max_devices_per_account: 64,
            max_group_leaves: 512,
        },
        approvals: TlsVec::new(vec![IrcPolicyApproval {
            signer_root_fingerprint: [5; 32],
            signer_device_id: [7; 16],
            signer_device_certificate_id: [21; 32],
            device_signature: [22; 64],
        }])?,
    })
}

fn semantic_route() -> Result<IrcSemanticRouteTbs, E2eeError> {
    Ok(IrcSemanticRouteTbs {
        profile_version: 1,
        network_id: [1; 32],
        kind: IrcConversationKind::Channel,
        direct_account_a: Opaque::new(Vec::new())?,
        direct_account_b: Opaque::new(Vec::new())?,
        canonical_channel_name: Opaque::from_slice(b"#room")?,
        channel_authority_root_fingerprint: [5; 32],
        semantic_incarnation: 0,
        predecessor_close_id: [0; 32],
    })
}

fn binding_package() -> Result<IrcConversationBindingPackage, E2eeError> {
    Ok(IrcConversationBindingPackage {
        binding: IrcConversationBinding {
            tbs: IrcConversationBindingTbs {
                profile_version: 1,
                network_id: [1; 32],
                kind: IrcConversationKind::Channel,
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
                principals: TlsVec::new(vec![IrcBindingPrincipal {
                    account_id: account()?,
                    root_fingerprint: [5; 32],
                    roster_generation: 0,
                    roster_id: [14; 32],
                }])?,
            },
            approvals: TlsVec::new(vec![IrcBindingApproval {
                signer_root_fingerprint: [5; 32],
                signer_device_id: [7; 16],
                signer_device_certificate_id: [21; 32],
                device_signature: [32; 64],
            }])?,
        },
        initial_member_plan: IrcInitialMemberPlan {
            entries: TlsVec::new(vec![IrcInitialMemberPlanEntry {
                account_id: account()?,
                root_fingerprint: [5; 32],
                device_id: [7; 16],
                capability_id: [33; 32],
            }])?,
        },
        root_binding_locks: TlsVec::new(vec![IrcRootBindingLock {
            tbs: IrcRootBindingLockTbs {
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

fn sequencer_credential() -> Result<IrcSequencerCredential, E2eeError> {
    Ok(IrcSequencerCredential {
        tbs: IrcSequencerCredentialTbs {
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
    round_trip(&IrcMlsContext {
        profile_version: 1,
        network_id: [1; 32],
        conversation_id: [20; 32],
        kind: IrcConversationKind::Channel,
        route_binding: [26; 32],
        initial_validation_time: 5,
        policy: policy()?,
        sequencer: sequencer_credential()?,
        current_binding: binding_package()?.binding,
        lifecycle: IrcConversationLifecycle {
            kind: IrcConversationLifecycleKind::ActiveConversation,
            close_intent_id: [0; 32],
        },
        private_topic: Opaque::from_slice(b"topic")?,
        bootstrap_pending: 1,
        roster_heads: TlsVec::new(vec![IrcRosterHead {
            account_id_digest: [37; 32],
            root_generation: 0,
            root_fingerprint: [5; 32],
            roster_generation: 0,
            roster_id: [14; 32],
        }])?,
        pending_joins: TlsVec::new(vec![IrcPendingJoin {
            leaf_index: 1,
            key_package_ref: Opaque::new(vec![38; 32])?,
        }])?,
    })?;
    round_trip(&IrcJoinAuthBundle {
        root_chains: TlsVec::new(vec![IrcAccountRootChain {
            account_id: account()?,
            roots: TlsVec::new(vec![root_identity(0)?])?,
        }])?,
        binding_chain: TlsVec::new(vec![IrcBindingChainEntry {
            package: binding_package()?,
            proof_kind: IrcBindingProofKind::RootLockedGenesis,
        }])?,
        policy_chain: TlsVec::new(vec![IrcPolicyChainEntry {
            policy: policy()?,
            proof_kind: IrcPolicyProofKind::PolicyRootLockedGenesis,
        }])?,
        roster_chain: TlsVec::new(vec![roster()?])?,
    })?;
    round_trip(&IrcReservation {
        tbs: IrcReservationTbs {
            profile_version: 1,
            network_id: [1; 32],
            reservation_id: [39; 16],
            kind: IrcConversationKind::Direct,
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
    round_trip(&IrcCloseAuthorization {
        tbs: IrcCloseAuthorizationTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: [20; 32],
            binding_id: [34; 32],
            authorizing_terminal_id: [43; 32],
            close_intent: IrcCloseIntent {
                reason_code: 1,
                validation_time: 9,
            },
            close_intent_id: [44; 32],
        },
        approvals: TlsVec::new(vec![IrcCommitApproval {
            signer_root_fingerprint: [5; 32],
            signer_device_id: [7; 16],
            signer_device_certificate_id: [21; 32],
            device_signature: [45; 64],
        }])?,
    })?;
    round_trip(&IrcJoinTransitionProofBundle {
        references: TlsVec::new(vec![IrcJoinTransitionProofReference {
            subject_kind: IrcJoinTransitionSubject::PolicySubject,
            subject_id: [46; 32],
            proof_role: IrcJoinTransitionProofRole::FinalizedGroupTransition,
            record_conversation_id: [20; 32],
            authorizing_record_id: [47; 32],
            authorizing_object_id: [48; 32],
        }])?,
    })?;
    Ok(())
}

fn receipt() -> IrcCandidateReceipt {
    IrcCandidateReceipt {
        tbs: IrcCandidateReceiptTbs {
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

fn authorization() -> Result<IrcCommitAuthorization, E2eeError> {
    Ok(IrcCommitAuthorization {
        tbs: IrcCommitAuthorizationTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: [20; 32],
            prior_epoch: 0,
            prior_state_id: [50; 32],
            candidate_id: [52; 32],
            commit_object_id: [49; 32],
            canonical_validation_time: 7,
            old_policy_id: [27; 32],
            authorization_rule: IrcCommitAuthorizationRule::RoutineSelfUpdate,
            action_bits: 0,
            resulting_policy_id: [27; 32],
            resulting_group_context_digest: [53; 32],
            resulting_ratchet_tree_digest: [54; 32],
            transition_target_digest: [0; 32],
        },
        approvals: TlsVec::new(Vec::new())?,
    })
}

fn ack() -> Result<IrcCommitAck, E2eeError> {
    Ok(IrcCommitAck {
        tbs: IrcCommitAckTbs {
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

fn finalization() -> Result<IrcCommitFinalizationCertificate, E2eeError> {
    Ok(IrcCommitFinalizationCertificate {
        tbs: IrcCommitFinalizationTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: [20; 32],
            route_sequence: 1,
            predecessor_record_id: [52; 32],
            finalization_id: [58; 32],
            sequencer_key_id: [31; 32],
            request: IrcFinalizationRequest {
                proof: IrcFinalizationProof {
                    core: IrcFinalizationCoreTbs {
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
                votes: TlsVec::new(vec![IrcFinalityVote {
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
    round_trip(&IrcCommitApprovalEnvelope {
        tbs: authorization()?.tbs,
        approval: IrcCommitApproval {
            signer_root_fingerprint: [5; 32],
            signer_device_id: [7; 16],
            signer_device_certificate_id: [21; 32],
            device_signature: [63; 64],
        },
    })?;
    round_trip(&ack()?)?;
    round_trip(&finalization()?)?;
    let abort = IrcCommitAbortCertificate {
        tbs: IrcCommitAbortTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: [20; 32],
            route_sequence: 1,
            predecessor_record_id: [52; 32],
            abort_id: [64; 32],
            sequencer_key_id: [31; 32],
            request: IrcAbortRequest {
                core: IrcAbortCoreTbs {
                    profile_version: 1,
                    network_id: [1; 32],
                    conversation_id: [20; 32],
                    prior_state_id: [50; 32],
                    candidate_id: [52; 32],
                    prior_epoch: 0,
                    reason: IrcCommitAbortReason::StagingTimeout,
                    evidence_digest: [65; 32],
                },
                receipt: receipt(),
                votes: TlsVec::new(Vec::new())?,
            },
        },
        sequencer_signature: [66; 64],
    };
    round_trip(&abort)?;
    round_trip(&IrcDeliveredWelcome {
        profile_version: 1,
        network_id: [1; 32],
        conversation_id: [20; 32],
        target_account_id_digest: [37; 32],
        target_device_id: [8; 16],
        authorization: IrcNormalJoinAuthorizationProof {
            finalization_id: [58; 32],
            finalization_object_id: [67; 32],
            added_key_package_ref: Opaque::new(vec![38; 32])?,
            resulting_leaf_index: 1,
            resulting_leaf_credential_hash: [68; 32],
        },
        transition_proofs: IrcJoinTransitionProofBundle {
            references: TlsVec::new(Vec::new())?,
        },
        welcome_bytes: Opaque::new(vec![69; 200])?,
    })?;
    for record in [
        IrcSequencerRecord::Candidate(receipt()),
        IrcSequencerRecord::Finalization(finalization()?),
        IrcSequencerRecord::Abort(abort),
    ] {
        round_trip(&record)?;
        let encoded = record.encode()?;
        assert_eq!(encoded.first().copied(), Some(record.kind().value()));
    }
    assert_eq!(
        IrcSequencerRecord::decode_exact(&[9, 0], &mut budget()),
        Err(E2eeError::UnknownDiscriminant)
    );
    Ok(())
}

fn reinit_attempt() -> Result<IrcReInitAttempt, E2eeError> {
    Ok(IrcReInitAttempt {
        tbs: IrcReInitAttemptTbs {
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
        key_package_plan: IrcKeyPackagePlan {
            entries: TlsVec::new(vec![IrcKeyPackagePlanEntry {
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
        authorization: IrcReInitAttemptAuthorization {
            tbs: IrcReInitAttemptAuthorizationTbs {
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
            approvals: TlsVec::new(vec![IrcCommitApproval {
                signer_root_fingerprint: [5; 32],
                signer_device_id: [7; 16],
                signer_device_certificate_id: [21; 32],
                device_signature: [83; 64],
            }])?,
        },
        creator_old_leaf_signature: Opaque::new(vec![84; 64])?,
    })
}

fn attempt_receipt() -> IrcReInitAttemptReceipt {
    IrcReInitAttemptReceipt {
        tbs: IrcReInitAttemptReceiptTbs {
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
    round_trip(&reinit_attempt()?)?;
    round_trip(&attempt_receipt())?;
    round_trip(&IrcStagedReInit {
        old_reinit_state_id: [58; 32],
        old_reinit_finalization_object_id: [67; 32],
        receipt: attempt_receipt(),
        new_conversation_id: [70; 32],
        target_account_id_digest: [37; 32],
        target_device_id: [8; 16],
        transition_proofs: IrcJoinTransitionProofBundle {
            references: TlsVec::new(Vec::new())?,
        },
        welcome_bytes: Opaque::new(vec![88; 300])?,
    })?;
    let reinit_ack = IrcReInitAck {
        tbs: IrcReInitAckTbs {
            profile_version: 1,
            network_id: [1; 32],
            old_conversation_id: [20; 32],
            new_conversation_id: [70; 32],
            old_reinit_state_id: [58; 32],
            reinit_attempt_id: [85; 32],
            ack_kind: IrcReInitAckKind::CreatorState,
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
    let activation = IrcReInitActivationCertificate {
        tbs: IrcReInitActivationTbs {
            profile_version: 1,
            network_id: [1; 32],
            old_conversation_id: [20; 32],
            route_sequence: 3,
            predecessor_record_id: [85; 32],
            reinit_activation_id: [90; 32],
            sequencer_key_id: [31; 32],
            request: IrcReInitActivationRequest {
                core: IrcReInitActivationCoreTbs {
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
    let abort = IrcReInitAbortCertificate {
        tbs: IrcReInitAbortTbs {
            profile_version: 1,
            network_id: [1; 32],
            old_conversation_id: [20; 32],
            route_sequence: 3,
            predecessor_record_id: [85; 32],
            reinit_abort_id: [93; 32],
            sequencer_key_id: [31; 32],
            request: IrcReInitAbortRequest {
                core: IrcReInitAbortCoreTbs {
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
        IrcSequencerRecord::ReinitAttempt(attempt_receipt()),
        IrcSequencerRecord::ReinitActivation(activation),
        IrcSequencerRecord::ReinitAbort(abort),
    ] {
        round_trip(&record)?;
    }
    round_trip(&IrcReInitDispositionVoteTbs {
        profile_version: 1,
        network_id: [1; 32],
        old_conversation_id: [20; 32],
        old_reinit_state_id: [58; 32],
        attempt_sequence: 0,
        slot_predecessor_record_id: [58; 32],
        reinit_attempt_id: [85; 32],
        disposition: IrcReInitDisposition::ActivateReinit,
        terminal_id: [90; 32],
        reason_code: 0,
    })?;
    Ok(())
}

#[test]
fn attach_aad_and_recovery_objects_round_trip() -> TestResult {
    let challenge = IrcDeviceAttachChallenge {
        tbs: IrcDeviceAttachTbs {
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
    round_trip(&IrcDeviceAttach {
        challenge,
        device_signature: [99; 64],
    })?;
    round_trip(&super::aad::IrcApplicationAad {
        profile_version: 1,
        network_id: [1; 32],
        conversation_id: [20; 32],
        route_binding: [26; 32],
        latest_state_id: [58; 32],
    })?;
    round_trip(&super::aad::IrcCommitAad {
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
    round_trip(&IrcFederationRequest {
        profile_version: 1,
        network_id: [1; 32],
        home_server_id: [102; 16],
        server_incarnation: [103; 16],
        origin_id: [104; 16],
        origin_generation: 0,
        operation_sequence: 0,
        request_id: [105; 16],
        opcode: IrcFederationOpcode::SubmitCandidate,
        encoded_parameters: Opaque::new(vec![20; 32])?,
        payload_object_id: Opaque::new(vec![49; 32])?,
    })?;
    round_trip(&IrcFederationResult {
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
        result_kind: IrcFederationResultKind::MailboxPage,
        encoded_result: Opaque::new(Vec::new())?,
        snapshot_token: Opaque::new(vec![108; 32])?,
        next_cursor: Opaque::new(Vec::new())?,
        responses: TlsVec::new(vec![IrcFederationResponseDescriptor {
            response_index: 0,
            wire_kind: IrcWireObjectKind::WelcomeMls,
            object_id: [109; 32],
            total_size: 500,
            delivery_token: Opaque::new(vec![110; 32])?,
            target_device_id: Opaque::new(vec![8; 16])?,
        }])?,
    })?;
    round_trip(&IrcFederationEvent {
        profile_version: 1,
        network_id: [1; 32],
        target_server_id: [111; 16],
        delivery_generation: 0,
        coordinator_state_generation: 4,
        delivery_sequence: 0,
        event_id: [112; 16],
        event_kind: IrcFederationEventKind::CandidateEvent,
        cross_profile_mutation_id: Opaque::new(Vec::new())?,
        cross_profile_part_index: 0,
        cross_profile_part_count: 0,
        conversation_id: Opaque::new(vec![20; 32])?,
        route_sequence: 0,
        origin_id: Opaque::new(vec![104; 16])?,
        origin_generation: 0,
        source_view: Opaque::new(
            IrcFederationSourceView {
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
    round_trip(&IrcFederationOrigin {
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
    round_trip(&IrcFederationRouteState {
        profile_version: 1,
        network_id: [1; 32],
        state_generation: 4,
        conversation_id: [20; 32],
        conversation_kind: IrcConversationKind::Channel,
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
        state: IrcRouteStateKind::ActiveRoute,
    })?;
    assert_eq!(IrcFederationOpcode::ALL.len(), 44);
    assert_eq!(IrcFederationOpcode::SubmitRecovery.value(), 42);
    assert_eq!(IrcFederationOpcode::SubmitRecoveryElement.value(), 43);
    assert_eq!(IrcFederationOpcode::SubmitMembership.value(), 44);
    assert_eq!(
        crate::objects::federation::IrcFederationStoreKind::StoreMembership.value(),
        11
    );
    assert_eq!(IrcFederationResultKind::ALL.len(), 27);
    assert_eq!(IrcFederationResultKind::RecoveryConflict.value(), 27);
    assert_eq!(IrcFederationEventKind::ALL.len(), 14);
    assert_eq!(IrcFederationEmptyKind::ALL.len(), 14);
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
