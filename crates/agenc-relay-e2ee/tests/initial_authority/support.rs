#![forbid(unsafe_code)]

use agenc_relay_crypto::{SemanticHashDomain, SignatureDomain};
use agenc_relay_e2ee::ids::{conversation_id, semantic_id_of};
use agenc_relay_e2ee::initial_authority::{
    ExpectedInitialAuthority, InitialAuthority, InitialAuthorityEvidence, InitialPrincipalEvidence,
    authenticate_initial_authority,
};
use agenc_relay_e2ee::objects::conversation::*;
use agenc_relay_e2ee::{
    ArcWireObject, ArcWireObjectKind, DecodeBudget, E2eeError, Opaque, TlsEncode, TlsVec,
};
use agenc_relay_testkit::e2ee_client::*;

pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;
pub(super) const ACCOUNT: [u8; 24] = [b'a'; 24];
pub(super) const OTHER: [u8; 24] = [b'b'; 24];

pub(super) fn budget() -> DecodeBudget {
    DecodeBudget::new(16 * 1024 * 1024, 65536)
}

pub(super) fn object(
    kind: ArcWireObjectKind,
    value: &impl TlsEncode,
) -> Result<Vec<u8>, E2eeError> {
    ArcWireObject::new(kind, value.encode()?)?.encode()
}

pub(super) struct Fixture {
    pub(super) principals: Vec<Principal>,
    pub(super) package: ArcConversationBindingPackage,
    pub(super) core: ArcContextCoreTbs,
    pub(super) policy: ArcPolicy,
    pub(super) credential: ArcSequencerCredential,
    pub(super) expected: ExpectedInitialAuthority,
}

impl Fixture {
    pub(super) fn new() -> Result<Self, E2eeError> {
        Self::with_seed(40)
    }

    pub(super) fn with_seed(seed: u8) -> Result<Self, E2eeError> {
        let principals = vec![
            principal(seed, &ACCOUNT, &[7])?,
            principal(41, &OTHER, &[9])?,
        ];
        let refs = principals.iter().collect::<Vec<_>>();
        let conversation = conversation_id(&NETWORK, &[25; 32])?;
        let kind = ArcConversationKind::Channel;
        let policy = policy(&PolicySpec::bootstrap(&refs, conversation, kind)?)?;
        let operational = agenc_relay_testkit::e2ee_client::policy(&PolicySpec::operational(
            &refs,
            conversation,
            kind,
            policy_id_of(&policy)?,
        )?)?;
        let authority = root_fingerprint(&principals.first().ok_or(E2eeError::InvalidValue)?.root)?;
        let credential = sequencer_credential(&key(60), 0, (0, 1_000_000), None)?;
        let package = binding_package(&BindingSpec {
            principals: &refs,
            route: channel_route(b"#room", authority)?,
            channel_instance_id: Some([1; 16]),
            conversation_nonce: None,
            group_id: [25; 32],
            generation: 0,
            previous_binding_id: [0; 32],
            lock_sequence: 0,
            previous_lock_ids: Vec::new(),
            plan_devices: vec![(&ACCOUNT, authority, 7)],
            initial_policy_id: policy_id_of(&policy)?,
            required_operational_policy_id: policy_id_of(&operational)?,
            sequencer_credential_id: semantic_id_of(
                SemanticHashDomain::SequencerKey,
                &credential.tbs,
            )?,
        })?;
        let tbs = &package.binding.tbs;
        let core = ArcContextCoreTbs {
            profile_version: 1,
            mls_version: 1,
            cipher_suite: 1,
            group_id: tbs.group_id.clone(),
            network_id: NETWORK,
            conversation_id: conversation,
            kind,
            semantic_route_lock_id: tbs.semantic_route_lock_id,
            route_binding: tbs.route_binding,
            initial_validation_time: 100,
            initial_policy_id: tbs.initial_policy_id,
            required_operational_policy_id: tbs.required_operational_policy_id,
            initial_bootstrap_pending: 1,
            initial_member_plan_id: tbs.initial_member_plan_id,
            sequencer_credential_id: tbs.sequencer_credential_id,
            encoded_required_capabilities: Opaque::new(vec![
                0, 2, 0xf1, 0xc1, 0, 0, 0, 2, 0xf1, 0xc0,
            ])?,
        };
        let expected = ExpectedInitialAuthority {
            network_id: NETWORK,
            conversation_id: conversation,
            binding_id: [0; 32],
        };
        let mut fixture = Self {
            principals,
            package,
            core,
            policy,
            credential,
            expected,
        };
        fixture.seal()?;
        Ok(fixture)
    }

    /// Recompute the binding pin after a deliberate fixture change. Negative
    /// tests use this only to reach checks beyond exact source-ID agreement.
    pub(super) fn seal(&mut self) -> Result<(), E2eeError> {
        self.package.binding.tbs.context_core_id =
            semantic_id_of(SemanticHashDomain::ContextCoreId, &self.core)?;
        let binding_id = semantic_id_of(SemanticHashDomain::BindingId, &self.package.binding.tbs)?;
        let mut approvals = self.package.binding.approvals.as_slice().to_vec();
        for approval in &mut approvals {
            let seed = *approval
                .signer_device_id
                .first()
                .ok_or(E2eeError::InvalidValue)?;
            approval.device_signature = sign(
                &key(seed),
                SignatureDomain::ConversationBinding,
                &self.package.binding.tbs,
            )?;
        }
        self.package.binding.approvals = TlsVec::new(approvals)?;
        let mut locks = self.package.root_binding_locks.as_slice().to_vec();
        for lock in &mut locks {
            let principal = self
                .principals
                .iter()
                .find(|principal| principal.root.tbs.account_id == lock.tbs.account_id)
                .ok_or(E2eeError::InvalidValue)?;
            lock.tbs.binding_id = binding_id;
            lock.root_signature = sign(
                &principal.root_secret,
                SignatureDomain::RootBindingLock,
                &lock.tbs,
            )?;
        }
        self.package.root_binding_locks = TlsVec::new(locks)?;
        self.expected.binding_id = binding_id;
        Ok(())
    }

    pub(super) fn encoded(&self) -> Result<Encoded, E2eeError> {
        Ok(Encoded {
            expected: self.expected,
            binding: object(ArcWireObjectKind::ConversationBinding, &self.package)?,
            core: self.core.encode()?,
            policy: object(ArcWireObjectKind::Policy, &self.policy)?,
            credential: self.credential.encode()?,
            principals: self
                .principals
                .iter()
                .map(|principal| {
                    Ok((
                        object(ArcWireObjectKind::RootIdentity, &principal.root)?,
                        object(ArcWireObjectKind::DeviceRoster, &principal.roster)?,
                    ))
                })
                .collect::<Result<_, E2eeError>>()?,
        })
    }

    pub(super) fn verify(&self) -> Result<InitialAuthority, E2eeError> {
        self.encoded()?.verify(&mut budget())
    }
}

pub(super) struct Encoded {
    pub(super) expected: ExpectedInitialAuthority,
    pub(super) binding: Vec<u8>,
    pub(super) core: Vec<u8>,
    pub(super) policy: Vec<u8>,
    pub(super) credential: Vec<u8>,
    pub(super) principals: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Encoded {
    pub(super) fn verify(&self, budget: &mut DecodeBudget) -> Result<InitialAuthority, E2eeError> {
        let principals = self
            .principals
            .iter()
            .map(|(root, roster)| InitialPrincipalEvidence {
                root_object: root,
                roster_object: roster,
            })
            .collect::<Vec<_>>();
        authenticate_initial_authority(
            &self.expected,
            &InitialAuthorityEvidence {
                binding_object: &self.binding,
                context_core: &self.core,
                initial_policy_object: &self.policy,
                sequencer_credential: &self.credential,
                principals: &principals,
            },
            budget,
        )
    }
}
