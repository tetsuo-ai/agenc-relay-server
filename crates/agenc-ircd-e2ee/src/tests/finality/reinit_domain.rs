#![forbid(unsafe_code)]

//! ReInit quorum signatures use their own registered protocol domain.

use super::*;

type ReinitDomainResult<T = ()> = Result<T, Box<dyn Error>>;

struct ReinitDomainFixture {
    principals: Vec<Principal>,
    rosters: PrincipalRosters,
    policy: VerifiedPolicy,
    tbs: IrcReInitDispositionVoteTbs,
    terminal: Terminal,
}

impl ReinitDomainFixture {
    fn new() -> ReinitDomainResult<Self> {
        let principals = vec![
            principal(40, &ACCOUNT, &[7])?,
            principal(41, &OTHER_ACCOUNT, &[9])?,
        ];
        let rosters = principal_rosters(&principals)?;
        let policy = verify_policy(
            &NETWORK,
            &CONVERSATION,
            &policy(&PolicySpec::moderated(&principals, CONVERSATION))?,
            &rosters,
            None,
        )?;
        let terminal = Terminal::finalize([91; 32]);
        let tbs = reinit_vote_tbs(
            &ReinitVoteSlot {
                network_id: NETWORK,
                old_conversation_id: CONVERSATION,
                old_reinit_state_id: [90; 32],
                attempt_sequence: 0,
                predecessor_record_id: [90; 32],
            },
            [92; 32],
            terminal,
        );
        Ok(Self {
            principals,
            rosters,
            policy,
            tbs,
            terminal,
        })
    }

    fn vote(
        &self,
        principal_index: usize,
        domain: SignatureDomain,
    ) -> ReinitDomainResult<IrcFinalityVote> {
        let principal = self.principals.get(principal_index).ok_or("principal")?;
        let device = match principal_index {
            0 => 7,
            1 => 9,
            _ => return Err("principal index".into()),
        };
        Ok(IrcFinalityVote {
            signer_root_fingerprint: root_fingerprint(&principal.root)?,
            signer_device_id: [device; 16],
            signer_device_certificate_id: certificate_id_of(principal, device)?,
            device_signature: sign(&key(device), domain, &self.tbs)?,
        })
    }
}

#[test]
fn reinit_quorum_accepts_only_the_registered_reinit_signature_domain() -> TestResult {
    let fixture = ReinitDomainFixture::new()?;
    let mut ledger = QuorumLedger::new();
    for principal in 0..2 {
        let vote = fixture.vote(principal, SignatureDomain::ReinitDisposition)?;
        assert!(
            ledger
                .record_reinit(&fixture.policy, &fixture.rosters, &fixture.tbs, &vote)
                .is_ok(),
            "the registered ReInit domain must authenticate an otherwise valid old-council vote"
        );
    }
    assert_eq!(ledger.count(&fixture.terminal), 2);
    assert!(ledger.quorum_reached(&fixture.policy, &fixture.terminal));
    Ok(())
}

#[test]
fn reinit_quorum_refuses_the_ordinary_vote_domain_without_consuming_a_slot() -> TestResult {
    let fixture = ReinitDomainFixture::new()?;
    let wrong_domain = fixture.vote(0, SignatureDomain::DispositionVote)?;
    let mut ledger = QuorumLedger::new();
    assert_eq!(
        ledger.record_reinit(
            &fixture.policy,
            &fixture.rosters,
            &fixture.tbs,
            &wrong_domain,
        ),
        Err(E2eeError::SignatureInvalid),
        "an ordinary disposition signature cannot authenticate a ReInit vote"
    );
    assert_eq!(ledger.votes().count(), 0);
    let correct = fixture.vote(0, SignatureDomain::ReinitDisposition)?;
    ledger.record_reinit(&fixture.policy, &fixture.rosters, &fixture.tbs, &correct)?;
    assert_eq!(ledger.count(&fixture.terminal), 1);

    // Ordinary candidate votes retain their distinct existing domain.
    let ordinary_tbs = vote_tbs(&slot(), [52; 32], fixture.terminal);
    let principal = fixture.principals.first().ok_or("principal")?;
    let ordinary = finality_vote(principal, 7, &ordinary_tbs)?;
    let mut ordinary_ledger = QuorumLedger::new();
    ordinary_ledger.record(&fixture.policy, &fixture.rosters, &ordinary_tbs, &ordinary)?;
    assert_eq!(ordinary_ledger.count(&fixture.terminal), 1);
    Ok(())
}
