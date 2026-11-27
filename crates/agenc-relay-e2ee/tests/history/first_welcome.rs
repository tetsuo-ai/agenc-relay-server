#![forbid(unsafe_code)]

//! Companion 9.4, 9.5 and 12.4. The recipient learns its authentic initial
//! context after independently replaying the root-locked first public Add.
use super::*;
use agenc_relay_crypto::SignatureDomain;
use agenc_relay_e2ee::identity::ClientIdentity;
use agenc_relay_e2ee::initial_authority::{
    ExpectedInitialAuthority, InitialPrincipalEvidence, PublicGenesisEvidence,
    first_welcome::{FirstAddEvidence, PublicFirstAdd, authenticate_first_add},
};
use agenc_relay_e2ee::object::ArcWireObjectRef;
use agenc_relay_e2ee::objects::sequencing::{
    ArcCommitFinalizationCertificate, terminal_certificate_view,
};
use agenc_relay_e2ee::route::verify_initial_member_plan;
use agenc_relay_e2ee::{ObjectId, TlsDecode, TlsVec};

struct Inputs {
    genesis: Genesis,
    binding: Vec<u8>,
    policy: Vec<u8>,
    signer: Vec<u8>,
    directory: Vec<(Vec<u8>, Vec<u8>)>,
    membership: Vec<u8>,
    roster: Vec<u8>,
    recipient: ClientIdentity,
}

impl Inputs {
    fn new() -> Result<Self, E2eeError> {
        let mut genesis = Genesis::new()?;
        let target = genesis.principal(1)?;
        let recipient = ClientIdentity {
            network_id: NETWORK,
            account_id: OTHER,
            root_fingerprint: root_fingerprint(&target.root)?,
            device_id: [9; 16],
        };
        let roster = object(ArcWireObjectKind::DeviceRoster, &target.roster)?;
        let mut entries = genesis
            .package
            .initial_member_plan
            .entries
            .as_slice()
            .to_vec();
        entries.push(ArcInitialMemberPlanEntry {
            account_id: target.root.tbs.account_id.clone(),
            root_fingerprint: recipient.root_fingerprint,
            device_id: recipient.device_id,
            capability_id: [101; 32],
        });
        genesis.package.initial_member_plan.entries = TlsVec::new(entries)?;
        let plan_id = verify_initial_member_plan(&genesis.package.initial_member_plan)?;
        genesis.core.initial_member_plan_id = plan_id;
        genesis.package.binding.tbs.initial_member_plan_id = plan_id;
        genesis.seal()?;
        let binding = object(ArcWireObjectKind::ConversationBinding, &genesis.package)?;
        let policy = object(ArcWireObjectKind::Policy, &genesis.bootstrap_policy)?;
        let signer = genesis.credential.encode()?;
        let directory = genesis
            .principals
            .iter()
            .map(|row| {
                Ok((
                    object(ArcWireObjectKind::RootIdentity, &row.root)?,
                    object(ArcWireObjectKind::DeviceRoster, &row.roster)?,
                ))
            })
            .collect::<Result<_, E2eeError>>()?;
        let membership = object(
            ArcWireObjectKind::LeafMembershipProof,
            &signed_membership(&genesis, &(0, 7, CREATOR_LEAF_SEED, 0, [55; 32]))?,
        )?;
        Ok(Self {
            genesis,
            binding,
            policy,
            signer,
            directory,
            membership,
            roster,
            recipient,
        })
    }

    fn certificate(
        &self,
        approvers: Vec<(usize, u8)>,
        voters: Vec<(usize, u8)>,
    ) -> Result<(Vec<u8>, [u8; 32]), E2eeError> {
        let genesis = &self.genesis;
        let mut log = Log::new(genesis)?;
        let (_, candidate) = log.candidate([91; 32])?;
        let council = Council {
            genesis,
            approvers,
            voters,
        };
        let tbs = log.authorization_tbs(
            &candidate,
            ArcCommitAuthorizationRule::ControlledTransition,
            action_bits::ADD_LEAF | action_bits::ROSTER | action_bits::PENDING_JOIN,
            log.policy_id,
            [0; 32],
        );
        let (request, id) =
            log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
        let policy = log.policy_id;
        let terminal = log.finalization(request, id, policy)?;
        let wire = terminal_certificate_view(&terminal.bytes)?
            .ok_or(E2eeError::WrongKind)?
            .encode()?;
        Ok((wire, id))
    }

    fn inspect(
        &self,
        pin: &ExpectedInitialAuthority,
        cert: &(Vec<u8>, [u8; 32]),
    ) -> Result<PublicFirstAdd, E2eeError> {
        self.inspect_address(pin, cert, ObjectId::compute(&cert.0))
    }

    fn inspect_address(
        &self,
        pin: &ExpectedInitialAuthority,
        cert: &(Vec<u8>, [u8; 32]),
        address: ObjectId,
    ) -> Result<PublicFirstAdd, E2eeError> {
        let pairs: Vec<_> = self
            .directory
            .iter()
            .map(|(root, roster)| InitialPrincipalEvidence {
                root_object: root,
                roster_object: roster,
            })
            .collect();
        authenticate_first_add(
            pin,
            &PublicGenesisEvidence {
                binding_object: &self.binding,
                initial_policy_object: &self.policy,
                sequencer_credential: &self.signer,
                principals: &pairs,
            },
            &FirstAddEvidence {
                recipient: &self.recipient,
                recipient_roster: &self.roster,
                creator_membership: &self.membership,
                certificate: &cert.0,
                expected_certificate: (address, cert.1),
            },
            &mut budget(),
        )
    }
}

#[test]
fn original_signed_first_add_requires_its_root_locks_controller_council_and_epoch_zero_leaf()
-> TestResult {
    let mut inputs = Inputs::new()?;
    let pin = inputs.genesis.expected;
    let signed = inputs.certificate(vec![(0, 7)], vec![(0, 7)])?;
    let under_quorum = inputs.certificate(vec![(0, 7)], vec![])?;
    let missing_controller = inputs.certificate(vec![], vec![(0, 7)])?;
    assert!(inputs.inspect(&pin, &under_quorum).is_err());
    assert!(inputs.inspect(&pin, &missing_controller).is_err());
    assert!(
        inputs
            .inspect(
                &ExpectedInitialAuthority {
                    binding_id: [9; 32],
                    ..pin
                },
                &signed
            )
            .is_err()
    );
    let ordinary = inputs.genesis.authority()?;
    let observed = inputs.inspect(&pin, &signed)?;
    assert_eq!(observed.identifiers().1, ObjectId::from_bytes([91; 32]));
    assert_eq!(observed.identifiers().2, signed.1);
    let complete = observed.complete_context(&inputs.genesis.core.encode()?, &mut budget())?;
    assert_eq!(complete.validation_time(), ordinary.validation_time());
    assert_eq!(complete.binding(), ordinary.binding());
    assert_eq!(complete.policy(), ordinary.policy());
    assert_eq!(complete.principals(), ordinary.principals());
    let mut changed = inputs.genesis.core.clone();
    changed.initial_validation_time += 1;
    assert!(
        inputs
            .inspect(&pin, &signed)?
            .complete_context(&changed.encode()?, &mut budget())
            .is_err()
    );
    inputs.membership = object(
        ArcWireObjectKind::LeafMembershipProof,
        &signed_membership(&inputs.genesis, &(1, 9, JOINER_LEAF_SEED, 0, [55; 32]))?,
    )?;
    assert!(inputs.inspect(&pin, &signed).is_err());
    Ok(())
}

fn changed_certificate(
    original: &(Vec<u8>, [u8; 32]),
    change: impl FnOnce(&mut ArcCommitFinalizationCertificate),
) -> Result<(Vec<u8>, [u8; 32]), E2eeError> {
    let object_ref = ArcWireObjectRef::parse(&original.0)?;
    let mut certificate =
        ArcCommitFinalizationCertificate::decode_exact(object_ref.body(), &mut budget())?;
    change(&mut certificate);
    certificate.sequencer_signature = sign(
        &key(SEQUENCER_SEED),
        SignatureDomain::CommitFinalization,
        &certificate.tbs,
    )?;
    Ok((
        object(ArcWireObjectKind::FinalizationCertificate, &certificate)?,
        original.1,
    ))
}

#[test]
fn first_add_checks_the_selected_delivery_original_recipient_roster_and_only_bootstrap_action()
-> TestResult {
    let mut inputs = Inputs::new()?;
    let pin = inputs.genesis.expected;
    let valid = inputs.certificate(vec![(0, 7)], vec![(0, 7)])?;
    assert!(
        inputs
            .inspect(&pin, &(inputs.policy.clone(), valid.1))
            .is_err()
    );
    assert!(
        inputs
            .inspect_address(&pin, &valid, ObjectId::compute(&inputs.binding))
            .is_err()
    );
    assert!(inputs.inspect(&pin, &(valid.0.clone(), [12; 32])).is_err());
    let different = changed_certificate(&valid, |cert| {
        cert.tbs.request.proof.authorization.tbs.authorization_rule =
            ArcCommitAuthorizationRule::RosterRecovery
    })?;
    assert!(inputs.inspect(&pin, &different).is_err());
    let different = changed_certificate(&valid, |cert| {
        cert.tbs.request.proof.authorization.tbs.action_bits = action_bits::ROSTER
    })?;
    assert!(inputs.inspect(&pin, &different).is_err());
    let decoded = ArcCommitFinalizationCertificate::decode_exact(
        ArcWireObjectRef::parse(&valid.0)?.body(),
        &mut budget(),
    )?;
    let original = decoded
        .tbs
        .request
        .proof
        .acknowledgements
        .as_slice()
        .first()
        .ok_or(E2eeError::InvalidValue)?;
    let duplicate = TlsVec::new(vec![original.clone(), original.clone()])?;
    let different = changed_certificate(&valid, |cert| {
        cert.tbs.request.proof.acknowledgements = duplicate
    })?;
    assert!(inputs.inspect(&pin, &different).is_err());
    let past = changed_certificate(&valid, |cert| {
        cert.tbs
            .request
            .proof
            .authorization
            .tbs
            .canonical_validation_time = 99
    })?;
    assert!(inputs.inspect(&pin, &past).is_err());
    inputs.recipient.network_id = [63; 32];
    assert!(inputs.inspect(&pin, &valid).is_err());
    inputs.recipient.network_id = NETWORK;
    inputs.recipient.device_id = [17; 16];
    assert!(inputs.inspect(&pin, &valid).is_err());
    inputs.recipient.device_id = [9; 16];
    inputs.roster = object(
        ArcWireObjectKind::DeviceRoster,
        &inputs.genesis.principal(0)?.roster,
    )?;
    assert!(inputs.inspect(&pin, &valid).is_err());
    Ok(())
}

#[test]
fn a_context_genuinely_committed_after_the_first_add_time_cannot_complete_that_receive()
-> TestResult {
    let mut inputs = Inputs::new()?;
    inputs.genesis.core.initial_validation_time = VALIDATION_TIME + 1;
    inputs.genesis.seal()?;
    inputs.binding = object(
        ArcWireObjectKind::ConversationBinding,
        &inputs.genesis.package,
    )?;
    let pin = inputs.genesis.expected;
    let signed = inputs.certificate(vec![(0, 7)], vec![(0, 7)])?;
    assert_eq!(
        inputs.genesis.authority()?.validation_time().0,
        VALIDATION_TIME + 1
    );
    let public = inputs.inspect(&pin, &signed)?;
    assert!(
        public
            .complete_context(&inputs.genesis.core.encode()?, &mut budget())
            .is_err()
    );
    Ok(())
}

#[test]
fn a_signed_plan_and_valid_quorum_do_not_supply_a_device_absent_from_the_resulting_roster()
-> TestResult {
    let mut inputs = Inputs::new()?;
    let genesis = &mut inputs.genesis;
    let mut entries = genesis
        .package
        .initial_member_plan
        .entries
        .as_slice()
        .to_vec();
    let recipient = entries
        .iter_mut()
        .find(|entry| entry.device_id == [9; 16])
        .ok_or(E2eeError::InvalidValue)?;
    recipient.device_id = [17; 16];
    inputs.recipient.device_id = recipient.device_id;
    genesis.package.initial_member_plan.entries = TlsVec::new(entries)?;
    let id = verify_initial_member_plan(&genesis.package.initial_member_plan)?;
    genesis.package.binding.tbs.initial_member_plan_id = id;
    genesis.core.initial_member_plan_id = id;
    genesis.seal()?;
    inputs.binding = object(ArcWireObjectKind::ConversationBinding, &genesis.package)?;
    let pin = genesis.expected;
    let signed = inputs.certificate(vec![(0, 7)], vec![(0, 7)])?;
    assert!(inputs.inspect(&pin, &signed).is_err());
    Ok(())
}
