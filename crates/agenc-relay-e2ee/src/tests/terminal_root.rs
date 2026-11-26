use super::*;
use crate::test_support::{ACCOUNT, NETWORK, key, sequencer_credential};
use agenc_relay_crypto::sign_canonical;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn only_the_explicit_query_grammar_accepts_one_canonical_challenge() -> TestResult {
    use crate::wire::command::{
        ClientCommand, EkeyCommand, parse_command, parse_terminal_root_command,
    };
    use crate::wire::tokens::base64url_encode;
    let challenge = [7; 16];
    let token = base64url_encode(&challenge);
    let params = ["PROVE", "ROOT-HEAD", token.as_str()];
    assert!(parse_command("EKEY", &params).is_err());
    assert_eq!(
        parse_terminal_root_command("EKEY", &params)?,
        ClientCommand::Ekey(EkeyCommand::ProveRootHead(challenge))
    );
    for wrong in [
        &["PROVE", "ROOT-HEAD"][..],
        &["PROVE", "ROOT-HEAD", "removed", "extra"],
        &["PROVE", "ROOT-HEAD", "===="],
    ] {
        assert!(parse_terminal_root_command("EKEY", wrong).is_err());
    }
    assert!(parse_terminal_root_command("EGROUP", &params).is_err());
    Ok(())
}

#[test]
fn a_complete_independent_set_can_only_accept_its_current_signer_and_exact_scope() -> TestResult {
    let old = key(71);
    let next = key(72);
    let first = sequencer_credential(&old, 0, (100, 1_000_000), None)?;
    let second = sequencer_credential(&next, 1, (500_000, 2_000_000), Some((&old, &first)))?;
    let set = SequencerKeySet::verify(&NETWORK, &[first.clone(), second.clone()], 7, None)?;
    let login = TerminalRootLogin {
        network_id: NETWORK,
        recovery_epoch: [9; 16],
        account_id: ACCOUNT,
        account_session_generation: 4,
        login_completion_sha256: [10; 32],
    };
    let root = TerminalRootIdentity {
        generation: 17,
        fingerprint: [11; 32],
        object_id: [12; 32],
    };
    let challenge = [13; 16];
    let issued = ValidationTime(520_000);
    let current = set.current().ok_or("missing first signer")?;
    let next_credential = set.credentials.last().ok_or("missing successor")?;
    let tbs = TerminalRootHeadTbs {
        version: 1,
        login: login.clone(),
        challenge,
        root: root.clone(),
        sequencer_set_generation: set.set_generation,
        sequencer_set_digest: set.digest,
        sequencer_credential_id: current.credential_id,
        issued_at: issued.0,
        expires_at: issued.0 + 30,
    };
    let signed = |fields: TerminalRootHeadTbs,
                  signer: &agenc_relay_crypto::Ed25519SecretKey,
                  domain|
     -> Result<TerminalRootHead, Box<dyn std::error::Error>> {
        let signature = *sign_canonical(signer, domain, &fields.encode()?)?.as_bytes();
        Ok(TerminalRootHead {
            tbs: fields,
            signature,
        })
    };
    let verify = |proof: &TerminalRootHead| proof.verify(&login, &root, &challenge, &set, issued);
    let proof = signed(tbs.clone(), &old, SignatureDomain::TerminalRootHead)?;
    verify(&proof)?;
    let mut untrusted = tbs.clone();
    untrusted.sequencer_credential_id = next_credential.credential_id;
    assert!(
        verify(&signed(
            untrusted,
            &next,
            SignatureDomain::TerminalRootHead
        )?)
        .is_err()
    );
    assert!(
        verify(&signed(
            tbs.clone(),
            &old,
            SignatureDomain::DeviceAttachChallenge
        )?)
        .is_err()
    );
    let successor_set = SequencerKeySet::verify_opened(&NETWORK, &[second], 8)?;
    assert!(
        proof
            .verify(&login, &root, &challenge, &successor_set, issued)
            .is_err()
    );
    let mut other = login.clone();
    other.account_session_generation += 1;
    assert!(
        proof
            .verify(&other, &root, &challenge, &set, issued)
            .is_err()
    );
    other = login.clone();
    other.network_id = [14; 32];
    assert!(
        proof
            .verify(&other, &root, &challenge, &set, issued)
            .is_err()
    );
    other = login.clone();
    other.account_id = [b'b'; 24];
    assert!(
        proof
            .verify(&other, &root, &challenge, &set, issued)
            .is_err()
    );
    let mut competing = root.clone();
    competing.object_id = [15; 32];
    assert!(
        proof
            .verify(&login, &competing, &challenge, &set, issued)
            .is_err()
    );
    let mut late = tbs;
    late.expires_at += 1;
    assert!(verify(&signed(late, &old, SignatureDomain::TerminalRootHead)?).is_err());
    Ok(())
}
