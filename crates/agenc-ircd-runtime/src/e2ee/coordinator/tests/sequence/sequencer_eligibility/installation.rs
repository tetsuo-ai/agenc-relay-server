//! A rejected installation retains the prior public and private selection together.
#![forbid(unsafe_code)]
use super::*;
use agenc_ircd_e2ee::objects::conversation::IrcSequencerCredential;
use agenc_ircd_e2ee::signature::{RoleKey, SignerRole};

fn refuses(
    change: impl Fn(&mut IrcSequencerCredential, &mut SequencerKeySet) -> TestResult,
) -> TestResult {
    for installed in [false, true] {
        let harness = Harness::new()?;
        let mut current = harness
            .coordinator
            .current_credential()
            .ok_or("credential")?
            .clone();
        let mut set = harness.coordinator.key_set().ok_or("key set")?.clone();
        let mut coordinator = if installed {
            harness.coordinator
        } else {
            crate::e2ee::coordinator::CompanionCoordinator::new(
                NETWORK,
                agenc_ircd_types::ServerId::from_bytes([3; 16]),
                "coordinator.example".into(),
            )
        };
        let old_raw = coordinator.current_credential().cloned();
        let old_set = coordinator.key_set().cloned();
        let old_id = coordinator.signer().map(|signer| signer.credential_id);
        change(&mut current, &mut set)?;
        assert_eq!(
            coordinator.install_sequencer(key(90), set, current),
            Err(agenc_ircd_e2ee::E2eeError::KeyInvalid)
        );
        assert_eq!(coordinator.current_credential(), old_raw.as_ref());
        assert_eq!(coordinator.key_set(), old_set.as_ref());
        assert_eq!(
            coordinator.signer().map(|signer| signer.credential_id),
            old_id
        );
    }
    Ok(())
}

#[test]
fn wrong_key_role_cannot_be_installed() -> TestResult {
    refuses(|_, set| {
        set.credentials.first_mut().ok_or("credential")?.key =
            RoleKey::new(SignerRole::Device, *key(90).public_key().as_bytes())?;
        Ok(())
    })
}

#[test]
fn substituted_verified_public_key_cannot_be_installed() -> TestResult {
    refuses(|_, set| {
        set.credentials.first_mut().ok_or("credential")?.key =
            RoleKey::new(SignerRole::Sequencer, *key(91).public_key().as_bytes())?;
        Ok(())
    })
}

#[test]
fn substituted_verified_interval_cannot_be_installed() -> TestResult {
    refuses(|_, set| {
        set.credentials
            .first_mut()
            .ok_or("credential")?
            .interval
            .not_after += 1;
        Ok(())
    })
}

#[test]
fn substituted_verified_generation_cannot_be_installed() -> TestResult {
    refuses(|_, set| {
        set.credentials.first_mut().ok_or("credential")?.generation += 1;
        Ok(())
    })
}

#[test]
fn substituted_verified_predecessor_cannot_be_installed() -> TestResult {
    refuses(|_, set| {
        set.credentials
            .first_mut()
            .ok_or("credential")?
            .previous_key_id = [99; 32];
        Ok(())
    })
}

#[test]
fn credential_from_another_network_cannot_be_installed() -> TestResult {
    refuses(|raw, set| {
        *raw = crate::e2ee::coordinator::tests::support::sequencer_credential_in(
            [99; 32],
            &key(90),
            0,
            (0, 2_000_000),
            None,
        )?;
        *set = SequencerKeySet::verify(&[99; 32], std::slice::from_ref(raw), 0, None)?;
        Ok(())
    })
}

#[test]
fn shared_public_key_does_not_select_another_credential() -> TestResult {
    let mut harness = Harness::new()?;
    let old = sequencer_credential(&key(90), 0, (0, 2_000_000), None)?;
    let next = sequencer_credential(&key(90), 1, (100, 3_000_000), Some((&key(90), &old)))?;
    let set = SequencerKeySet::verify(&NETWORK, &[old, next.clone()], 1, None)?;
    let expected = semantic_id_of(SemanticHashDomain::SequencerKey, &next.tbs)?;
    harness.coordinator.install_sequencer(key(90), set, next)?;
    assert_eq!(
        harness.coordinator.signer().ok_or("signer")?.credential_id,
        expected
    );
    Ok(())
}
