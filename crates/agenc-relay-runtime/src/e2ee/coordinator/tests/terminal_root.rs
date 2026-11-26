#![forbid(unsafe_code)]

//! The optional operation reads the same authoritative account head as publication.
use super::*;
use agenc_relay_e2ee::identity::ValidationTime;
use agenc_relay_e2ee::terminal_root::{
    OBJECT_BYTES, TerminalRootHead, TerminalRootIdentity, TerminalRootLogin,
};

#[test]
fn terminal_root_is_signed_only_for_the_original_login_and_actual_directory_head() -> TestResult {
    let mut h = Harness::new()?;
    let challenge = [31; 16];
    assert_eq!(
        h.run(Op::ProveRootHead, &challenge, None)?
            .err()
            .ok_or("missing refusal")?
            .code,
        E2eeReplyCode::AccountRequired
    );
    let login = TerminalRootLogin {
        network_id: NETWORK,
        recovery_epoch: [92; 16],
        account_id: h.account,
        account_session_generation: 1,
        login_completion_sha256: [41; 32],
    };
    h.terminal_login = Some(login.clone());
    let no_root = ok(h.run(Op::ProveRootHead, &challenge, None)?)?;
    assert!(matches!(
        no_root.result,
        ResultBody::Empty(agenc_relay_domain::e2ee::projection::EmptyKind::Identity)
    ));
    assert!(no_root.responses.is_empty());
    h.publish_identity_and_roster()?;
    let published = h.principal.root.clone();
    let root = TerminalRootIdentity {
        generation: published.tbs.root_generation,
        fingerprint: root_fingerprint(&published)?,
        object_id: object_id(&wire(ArcWireObjectKind::RootIdentity, &published)?),
    };
    let out = ok(h.run(Op::ProveRootHead, &challenge, None)?)?;
    assert_eq!(out.responses.len(), 1);
    let bytes = &out.responses.first().ok_or("missing head")?.bytes;
    assert_eq!(bytes.len(), OBJECT_BYTES);
    let mut budget = DecodeBudget::new(OBJECT_BYTES * 4, 100);
    let object = ArcWireObject::decode_kind(
        bytes,
        Some(ArcWireObjectKind::TerminalRootHead),
        &mut budget,
    )?;
    let proof = TerminalRootHead::decode_exact(object.body(), &mut budget)?;
    let set = h.coordinator.key_set.as_ref().ok_or("missing active set")?;
    assert_eq!(proof.tbs.encode()?.len(), 290);
    proof.verify(&login, &root, &challenge, set, ValidationTime(NOW))?;
    proof.verify(&login, &root, &challenge, set, ValidationTime(NOW + 30))?;
    assert!(
        proof
            .verify(&login, &root, &challenge, set, ValidationTime(NOW + 31))
            .is_err()
    );
    assert!(
        proof
            .verify(&login, &root, &challenge, set, ValidationTime(NOW - 1))
            .is_err()
    );
    assert!(
        proof
            .verify(&login, &root, &[42; 16], set, ValidationTime(NOW))
            .is_err()
    );
    let mut other = login.clone();
    other.login_completion_sha256 = [42; 32];
    assert!(
        proof
            .verify(&other, &root, &challenge, set, ValidationTime(NOW))
            .is_err()
    );
    other = login.clone();
    other.recovery_epoch = [0; 16];
    h.terminal_login = Some(other);
    assert_eq!(
        h.run(Op::ProveRootHead, &challenge, None)?
            .err()
            .ok_or("missing epoch refusal")?
            .code,
        E2eeReplyCode::AccountRequired
    );
    let mut unrelated_account = login.clone();
    unrelated_account.account_id = [b'x'; 24];
    let mut unrelated_network = login.clone();
    unrelated_network.network_id = [13; 32];
    for unrelated in [unrelated_account, unrelated_network] {
        h.terminal_login = Some(unrelated);
        assert_eq!(
            h.run(Op::ProveRootHead, &challenge, None)?
                .err()
                .ok_or("expected scoped login refusal")?
                .code,
            E2eeReplyCode::AccountRequired
        );
    }
    h.terminal_login = Some(login);
    h.coordinator.signer = None;
    assert_eq!(
        h.run(Op::ProveRootHead, &challenge, None)?
            .err()
            .ok_or("missing signer refusal")?
            .code,
        E2eeReplyCode::Syncing
    );
    Ok(())
}
