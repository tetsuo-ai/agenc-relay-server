#![forbid(unsafe_code)]

//! A candidate receipt is adopted only at the exact chain position: the
//! current epoch and its successor, the next candidate sequence, the
//! accepted state, and (for a fresh epoch) the accepted state as predecessor.

use super::*;

type LogEdit = fn(&mut Log);

#[test]
fn a_candidate_off_the_chain_position_is_refused_and_the_head_is_kept() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, log) = activated(&genesis)?;
    let head = *chain.head();
    let edits: [(&str, LogEdit); 5] = [
        ("prior epoch", |log| log.epoch = log.epoch.saturating_add(1)),
        ("prior epoch behind", |log| log.epoch = 0),
        ("candidate sequence", |log| log.candidate_sequence = 7),
        ("prior state", |log| log.accepted_state_id = [9; 32]),
        ("predecessor of a fresh epoch", |log| log.head = [8; 32]),
    ];
    for (name, edit) in edits {
        let mut fork = log.clone_for_fork();
        edit(&mut fork);
        let (record, _) = fork.candidate([2; 32])?;
        assert!(adopt(&mut chain, &record).is_err(), "{name}");
        assert_eq!(*chain.head(), head, "{name}");
    }
    let mut honest = log.clone_for_fork();
    let (record, _) = honest.candidate([2; 32])?;
    assert!(matches!(
        adopt(&mut chain, &record)?,
        ChainStep::Candidate(_)
    ));
    Ok(())
}

#[test]
fn a_second_candidate_is_refused_while_one_is_open() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let (first, _) = log.candidate([2; 32])?;
    adopt(&mut chain, &first)?;
    let head = *chain.head();
    let mut fork = log.clone_for_fork();
    let (second, _) = fork.candidate([3; 32])?;
    assert!(adopt(&mut chain, &second).is_err());
    assert_eq!(*chain.head(), head);
    Ok(())
}
