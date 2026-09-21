//! Valid mailbox pagination must preserve its original immutable scope.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_testkit::ScriptedEntropy;

#[path = "mailbox_cursor_bounds.rs"]
mod boundaries;

fn paged_mailbox() -> TestResult<(Harness, Vec<u8>, Outcome, ScriptedEntropy)> {
    let (mut source, _, _) = finalization_fixture()?;
    let binding = source.binding_bytes()?;
    for _ in 0..33 {
        deliver_binding(&mut source, &binding)?;
    }
    let mut entropy = ScriptedEntropy::new((1..=128_u8).flat_map(|byte| [byte; 32]).collect())?;
    let first = fetch(&mut source, &mut entropy, &[2, 0])?;
    assert_eq!(first.result, ResultBody::MailboxPage);
    assert_eq!(first.responses.len(), 32);
    assert!(first.snapshot_token.is_some());
    assert!(first.next_cursor.is_some());
    let tokens: std::collections::BTreeSet<_> = first
        .responses
        .iter()
        .map(|response| response.delivery_token.ok_or("delivery token"))
        .collect::<Result<_, _>>()?;
    assert_eq!(
        tokens.len(),
        32,
        "every delivered item has a distinct scripted token"
    );
    Ok((source, binding, first, entropy))
}

fn fetch(
    source: &mut Harness,
    entropy: &mut ScriptedEntropy,
    params: &[u8],
) -> TestResult<Outcome> {
    let mut outcome = ok(evaluate_request_with_entropy(
        source,
        Op::FetchMailbox,
        params,
        None,
        entropy,
    )?)?;
    source.sequence = source.sequence.checked_add(1).ok_or("request sequence")?;
    let origin = source
        .coordinator
        .state
        .origins
        .get_mut(&crate::e2ee::coordinator::tests::origin_key())
        .ok_or("origin")?;
    origin.next_sequence = source.sequence;
    for effect in std::mem::take(&mut outcome.effects) {
        effect(&mut source.coordinator.state);
    }
    for write in &outcome.writes {
        source.apply_logical_write(write)?;
    }
    Ok(outcome)
}

fn continuation(cursor: [u8; 32]) -> Vec<u8> {
    let mut parameters = vec![2, 32];
    parameters.extend_from_slice(&cursor);
    parameters
}

#[test]
fn mailbox_continuation_retains_the_original_snapshot_token() -> TestResult {
    let (mut source, _, first, mut entropy) = paged_mailbox()?;
    let parameters = continuation(first.next_cursor.ok_or("next cursor")?);
    let next = fetch(&mut source, &mut entropy, &parameters)?;
    assert_eq!(next.responses.len(), 1);
    assert_eq!(next.next_cursor, None);
    assert_eq!(next.snapshot_token, first.snapshot_token);
    Ok(())
}

#[test]
fn mailbox_continuation_cannot_splice_a_later_delivery_into_its_snapshot() -> TestResult {
    let (mut source, binding, first, mut entropy) = paged_mailbox()?;
    deliver_binding(&mut source, &binding)?;
    let parameters = continuation(first.next_cursor.ok_or("next cursor")?);
    let next = fetch(&mut source, &mut entropy, &parameters)?;
    assert_eq!(
        next.responses.len(),
        1,
        "the final snapshot row excludes the later delivery"
    );
    assert_eq!(next.next_cursor, None);
    Ok(())
}

#[test]
fn changing_the_opaque_mailbox_cursor_cannot_select_a_live_sequence() -> TestResult {
    let (source, _, first, mut entropy) = paged_mailbox()?;
    let mut cursor = first.next_cursor.ok_or("next cursor")?;
    let byte = cursor.first_mut().ok_or("cursor prefix")?;
    *byte ^= 1;
    let before = retained_state(&source)?;
    let remaining = entropy.remaining();
    assert!(
        evaluate_request_with_entropy(
            &source,
            Op::FetchMailbox,
            &continuation(cursor),
            None,
            &mut entropy
        )?
        .is_err()
    );
    assert_eq!(retained_state(&source)?, before);
    assert_eq!(entropy.remaining(), remaining);
    Ok(())
}
