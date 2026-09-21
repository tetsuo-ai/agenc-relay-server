//! Startup derives the required signers from the durable set, the credential
//! history, the route pins, and the unfinished receipts (companion 9.2.1).
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::tests::NOW;
use crate::e2ee::coordinator::{CompanionCoordinator, CompanionFault, SignerReport};
use agenc_relay_e2ee::limits::MAX_SEQUENCER_KEY_OVERLAP_SECONDS;
use agenc_relay_storage::e2ee_records::{
    KEYSET_ROW_KIND, KeySetRow, SEQUENCER_HISTORY_ROW_KIND, SequencerHistoryRow,
};
use std::collections::BTreeMap;

/// The old credential's overlap deadline: the successor's `not_before`
/// plus the maximum overlap.
const DEADLINE: u64 = 100 + MAX_SEQUENCER_KEY_OVERLAP_SECONDS;

/// The rows one startup reconciliation writes.
#[derive(Default)]
struct Startup {
    key_set: Option<KeySetRow>,
    history: BTreeMap<[u8; 32], SequencerHistoryRow>,
}

/// Runs the startup reconciliation of `harness` at `now`, and applies its
/// writes and effects as the daemon does once the batch is durable.
fn reconcile(harness: &mut Harness, now: u64) -> TestResult<Result<Startup, CompanionFault>> {
    let write = match harness.coordinator.next_restored_write(now) {
        Ok(write) => write.ok_or("the signer reconciliation")?,
        Err(fault) => return Ok(Err(fault)),
    };
    let mut startup = Startup::default();
    for durable in write.writes()? {
        let (table, key, bytes) = durable.encoded_record().ok_or("a put")?;
        let value = PersistentRecordValue::decode(table, bytes)?;
        match value.record_kind() {
            KEYSET_ROW_KIND => startup.key_set = Some(KeySetRow::decode(value.body())?),
            SEQUENCER_HISTORY_ROW_KIND => {
                startup.history.insert(
                    SequencerHistoryRow::parse_key(key)?,
                    SequencerHistoryRow::decode(value.body())?,
                );
            }
            _ => return Err("an unexpected startup row".into()),
        }
        harness.apply_logical_write(&durable)?;
    }
    write.apply(&mut harness.coordinator)?;
    Ok(Ok(startup))
}

fn refused(
    harness: &Harness,
    install: impl FnOnce(&mut CompanionCoordinator) -> TestResult,
    now: u64,
) -> TestResult<bool> {
    let mut fresh = harness.reloaded_with(install)?;
    Ok(matches!(
        fresh.coordinator.next_restored_write(now),
        Err(CompanionFault::Storage)
    ))
}

#[test]
fn the_first_startup_records_the_accepted_set_and_the_credential_history() -> TestResult {
    let (harness, conversation, old, next) = bootstrapped_old_pinned()?;
    let mut restored =
        harness.reloaded_with(|coordinator| install_overlap(coordinator).map(|_| ()))?;
    let startup = reconcile(&mut restored, NOW)?.map_err(|fault| format!("{fault:?}"))?;
    let set = startup.key_set.ok_or("the key set row")?;
    assert_eq!((set.generation, set.credential_ids), (1, vec![old, next]));
    assert_eq!(
        set.digest,
        restored.coordinator.key_set().ok_or("the set")?.digest
    );
    assert_eq!(startup.history.len(), 2);
    let old_row = startup.history.get(&old).ok_or("the old row")?;
    assert_eq!(
        (
            old_row.key_generation,
            old_row.introduced_set,
            old_row.retired_set,
            old_row.released
        ),
        (0, 1, None, false)
    );
    assert_eq!(old_row.public_key, *key(OLD).public_key().as_bytes());
    let next_row = startup.history.get(&next).ok_or("the successor row")?;
    assert_eq!(
        (
            next_row.key_generation,
            next_row.introduced_set,
            next_row.previous_key_id
        ),
        (1, 1, old)
    );
    assert_eq!(
        restored.coordinator.signer_report(),
        SignerReport::default()
    );
    assert_eq!(pin_of(&restored, conversation)?, (old, None));
    // The next startup under the same set has nothing to persist and keeps
    // every fact.
    let mut again =
        restored.reloaded_with(|coordinator| install_overlap(coordinator).map(|_| ()))?;
    let write = again
        .coordinator
        .next_restored_write(NOW)?
        .ok_or("the reconciliation")?;
    assert!(write.writes()?.is_empty());
    write.apply(&mut again.coordinator)?;
    assert_eq!(again.coordinator.signer_report(), SignerReport::default());
    assert_eq!(pin_of(&again, conversation)?, (old, None));
    // A set at the accepted generation with another digest, a set below
    // it, a skipped generation, and a set whose current credential the
    // accepted set never held are refused.
    let (old_raw, next_raw, _) = overlap()?;
    let same_generation =
        SequencerKeySet::verify(&NETWORK, std::slice::from_ref(&old_raw), 1, None)?;
    let below = SequencerKeySet::verify(&NETWORK, std::slice::from_ref(&old_raw), 0, None)?;
    let skipped = SequencerKeySet::verify(&NETWORK, &[old_raw.clone(), next_raw.clone()], 3, None)?;
    let unrelated_raw = sequencer_credential(&key(70), 0, (0, 2_000_000), None)?;
    let unrelated =
        SequencerKeySet::verify(&NETWORK, std::slice::from_ref(&unrelated_raw), 2, None)?;
    for (set, seed, current) in [
        (same_generation, OLD, old_raw.clone()),
        (below, OLD, old_raw.clone()),
        (skipped, OLD, old_raw.clone()),
        (unrelated, 70, unrelated_raw),
    ] {
        assert!(refused(
            &restored,
            |coordinator| Ok(coordinator.install_sequencer(key(seed), set, current)?),
            NOW
        )?);
    }
    Ok(())
}

#[test]
fn retirement_is_refused_before_the_deadline_and_blocks_the_route_after_it() -> TestResult {
    let (harness, conversation, old, next) = bootstrapped_old_pinned()?;
    let mut accepted =
        harness.reloaded_with(|coordinator| install_overlap(coordinator).map(|_| ()))?;
    reconcile(&mut accepted, NOW)?.map_err(|fault| format!("{fault:?}"))?;
    // Before the deadline a set omitting the credential a `normal` route
    // pins is refused, with or without the retired key.
    for retain in [false, true] {
        assert!(refused(
            &accepted,
            |coordinator| install_retired(coordinator, retain).map(|_| ()),
            DEADLINE - 1
        )?);
    }
    // At the deadline the set is accepted, the old credential is retired,
    // and the route is blocked; the missing retired key is reported.
    let mut blocked =
        accepted.reloaded_with(|coordinator| install_retired(coordinator, false).map(|_| ()))?;
    let startup = reconcile(&mut blocked, DEADLINE)?.map_err(|fault| format!("{fault:?}"))?;
    let set = startup.key_set.ok_or("the key set row")?;
    assert_eq!((set.generation, set.credential_ids), (2, vec![next]));
    let old_row = startup.history.get(&old).ok_or("the old row")?;
    assert_eq!((old_row.retired_set, old_row.released), (Some(2), false));
    assert!(!startup.history.contains_key(&next));
    assert_eq!(pin_of(&blocked, conversation)?, (old, Some(old)));
    assert_eq!(
        blocked.coordinator.signer_report(),
        SignerReport {
            blocked_routes: 1,
            retired_missing: true,
            released: 0,
        }
    );
    assert_eq!(blocked.coordinator.blocked_routes(), 1);
    assert!(
        blocked
            .coordinator
            .signers()
            .ok_or("signers")?
            .retired
            .is_none()
    );
    let commit = commit_bytes(&blocked, conversation, 1, 500)?;
    assert_eq!(
        code(blocked.run(Op::SubmitCandidate, &conversation, Some(&commit))?),
        Some(E2eeReplyCode::Syncing)
    );
    // The blocked state is derived again at every startup.
    let mut again =
        blocked.reloaded_with(|coordinator| install_retired(coordinator, false).map(|_| ()))?;
    let write = again
        .coordinator
        .next_restored_write(DEADLINE)?
        .ok_or("the reconciliation")?;
    assert!(write.writes()?.is_empty());
    write.apply(&mut again.coordinator)?;
    assert_eq!(pin_of(&again, conversation)?, (old, Some(old)));
    assert_eq!(again.coordinator.signer_report().blocked_routes, 1);
    // A retired key for a credential the history never accepted is refused.
    assert!(refused(
        &accepted,
        |coordinator| {
            install_retired(coordinator, false)?;
            coordinator.configure_retired_key(key(70));
            Ok(())
        },
        DEADLINE
    )?);
    Ok(())
}

#[test]
fn the_retired_signer_completes_old_receipts_and_a_transition_unblocks_the_route() -> TestResult {
    let (mut harness, conversation, old, next) = bootstrapped_old_pinned()?;
    // An old-credential receipt stays open across the restarts.
    let opened = open_finalization(&mut harness, conversation, 1)?;
    let (bytes, terminal) = transition_bytes(&harness, &opened, &[DEVICE])?;
    let mut accepted =
        harness.reloaded_with(|coordinator| install_overlap(coordinator).map(|_| ()))?;
    reconcile(&mut accepted, NOW)?.map_err(|fault| format!("{fault:?}"))?;
    // The configured old key installs as the retired-retained signer the
    // pin and the receipt require.
    let mut restored = accepted.reloaded_with(|coordinator| {
        install_retired(coordinator, false)?;
        coordinator.configure_retired_key(key(OLD));
        Ok(())
    })?;
    reconcile(&mut restored, DEADLINE)?.map_err(|fault| format!("{fault:?}"))?;
    assert_eq!(
        restored.coordinator.signer_report(),
        SignerReport {
            blocked_routes: 1,
            retired_missing: false,
            released: 0,
        }
    );
    assert_eq!(
        restored
            .coordinator
            .signers()
            .and_then(|signers| signers.retired.as_ref())
            .map(|(signer, _)| signer.credential_id),
        Some(old)
    );
    assert_eq!(pin_of(&restored, conversation)?, (old, Some(old)));
    // The open receipt's terminal signs under the old credential, and the
    // finalized successor transition unblocks the route.
    let outcome = ok(restored.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(_, _, id, _) if id == terminal));
    assert_eq!(record_signer(&restored, &outcome.result)?, old);
    assert_eq!(pin_of(&restored, conversation)?, (next, None));
    assert_eq!(stored_pin(&restored, conversation)?, (Some(next), None));
    assert_eq!(restored.coordinator.blocked_routes(), 0);
    let (receipt, ..) = submit_candidate(&mut restored, conversation, 2, 500)?;
    assert_eq!(receipt.tbs.sequencer_key_id, next);
    // Nothing requires the old credential now: the next startup records
    // its release, and from then on its key is refused as unrelated.
    let mut released =
        restored.reloaded_with(|coordinator| install_retired(coordinator, false).map(|_| ()))?;
    let startup = reconcile(&mut released, DEADLINE)?.map_err(|fault| format!("{fault:?}"))?;
    assert!(startup.key_set.is_none());
    let old_row = startup.history.get(&old).ok_or("the old row")?;
    assert_eq!((old_row.retired_set, old_row.released), (Some(2), true));
    assert_eq!(
        released.coordinator.signer_report(),
        SignerReport {
            blocked_routes: 0,
            retired_missing: false,
            released: 1,
        }
    );
    assert!(
        released
            .coordinator
            .signers()
            .ok_or("signers")?
            .retired
            .is_none()
    );
    assert!(refused(
        &released,
        |coordinator| {
            install_retired(coordinator, false)?;
            coordinator.configure_retired_key(key(OLD));
            Ok(())
        },
        DEADLINE
    )?);
    // The release fact itself is retained across the next startup.
    let mut after =
        released.reloaded_with(|coordinator| install_retired(coordinator, false).map(|_| ()))?;
    let write = after
        .coordinator
        .next_restored_write(DEADLINE)?
        .ok_or("the reconciliation")?;
    assert!(write.writes()?.is_empty());
    write.apply(&mut after.coordinator)?;
    assert_eq!(after.coordinator.signer_report().released, 0);
    Ok(())
}

#[test]
fn an_early_retirement_is_accepted_once_every_live_route_migrated() -> TestResult {
    let (mut harness, conversation, old, next) = bootstrapped_old_pinned()?;
    let opened = open_finalization(&mut harness, conversation, 1)?;
    let (bytes, _) = transition_bytes(&harness, &opened, &[DEVICE])?;
    ok(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    assert_eq!(pin_of(&harness, conversation)?, (next, None));
    let mut accepted =
        harness.reloaded_with(|coordinator| install_overlap(coordinator).map(|_| ()))?;
    reconcile(&mut accepted, NOW)?.map_err(|fault| format!("{fault:?}"))?;
    // Before the deadline, with no route pinned to the old credential, the
    // omitting set is accepted and the old signer is released at once.
    let mut early =
        accepted.reloaded_with(|coordinator| install_retired(coordinator, false).map(|_| ()))?;
    let startup = reconcile(&mut early, NOW)?.map_err(|fault| format!("{fault:?}"))?;
    let set = startup.key_set.ok_or("the key set row")?;
    assert_eq!((set.generation, set.credential_ids), (2, vec![next]));
    let old_row = startup.history.get(&old).ok_or("the old row")?;
    assert_eq!((old_row.retired_set, old_row.released), (Some(2), true));
    assert_eq!(
        early.coordinator.signer_report(),
        SignerReport {
            blocked_routes: 0,
            retired_missing: false,
            released: 1,
        }
    );
    assert_eq!(pin_of(&early, conversation)?, (next, None));
    // The released key is refused as unrelated from then on.
    assert!(refused(
        &accepted,
        |coordinator| {
            install_retired(coordinator, false)?;
            coordinator.configure_retired_key(key(OLD));
            Ok(())
        },
        NOW
    )?);
    Ok(())
}
