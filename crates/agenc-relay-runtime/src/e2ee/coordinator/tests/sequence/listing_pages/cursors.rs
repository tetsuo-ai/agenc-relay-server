#![forbid(unsafe_code)]

//! A cut's one live cursor is valid only for its requester, request kind,
//! selector and first position, until its next page commits or the cut
//! expires (companion 11.7, 16). A forged, differently bound, expired or
//! consumed cursor, and every cursor after a restart, is refused with
//! `E2EE_OBJECT_NOT_FOUND` before any entropy is drawn, and never restarts
//! the listing.

use agenc_relay_e2ee::ids::account_id_digest;
use agenc_relay_e2ee::limits::MAX_BATCH_OBJECTS;

use super::directory::{locks_from, many_devices, provisioned, publish_statements, seed_locks};
use super::*;

/// A harness with a bound channel, its root's 40 binding locks and 40
/// receipts, and the first page of each listing.
fn listings() -> TestResult<(Harness, [u8; 32], Page, Page)> {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    seed_locks(&mut harness, 1, ENTRIES as u64 - 1)?;
    for sequence in 0..ENTRIES as u64 {
        seed_record(&mut harness, conversation, sequence, 900)?;
    }
    let prefix = locks_from(&harness, 0)?;
    let locks = page(&mut harness, Op::FetchBindingLocks, &prefix, None)?;
    let receipts = page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        None,
    )?;
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 2);
    Ok((harness, conversation, locks, receipts))
}

fn with_cursor(prefix: &[u8], cursor: [u8; 32]) -> Vec<u8> {
    [prefix, &cursor_param(Some(cursor))].concat()
}

#[test]
fn a_forged_cursor_is_refused_and_never_restarts_the_listing() -> TestResult {
    let (harness, conversation, locks, receipts) = listings()?;
    let lock_cursor = locks.next.ok_or("a lock cursor")?;
    let receipt_cursor = receipts.next.ok_or("a receipt cursor")?;
    let lock_prefix = locks_from(&harness, 0)?;
    let receipt_prefix = receipts_from(conversation, 0);
    for forged in [[0x33; 32], [0; 32]] {
        refused(
            &harness,
            Op::FetchBindingLocks,
            &with_cursor(&lock_prefix, forged),
        )?;
        refused(
            &harness,
            Op::FetchReceipts,
            &with_cursor(&receipt_prefix, forged),
        )?;
    }
    for (op, prefix, cursor) in [
        (Op::FetchBindingLocks, &lock_prefix, lock_cursor),
        (Op::FetchReceipts, &receipt_prefix, receipt_cursor),
    ] {
        for byte in [0, 31] {
            let mut altered = cursor;
            let flipped = altered.get_mut(byte).ok_or("a cursor byte")?;
            *flipped ^= 1;
            refused(&harness, op, &with_cursor(prefix, altered))?;
        }
    }
    Ok(())
}

#[test]
fn a_cursor_is_refused_under_any_other_kind_selector_or_first_position() -> TestResult {
    let (mut harness, conversation, locks, receipts) = listings()?;
    let lock_cursor = locks.next.ok_or("a lock cursor")?;
    let receipt_cursor = receipts.next.ok_or("a receipt cursor")?;
    let account = account_param(&harness.account);
    let fingerprint = root_fingerprint(&harness.principal.root)?;
    let mut other_account = harness.account;
    if let Some(byte) = other_account.last_mut() {
        *byte = if *byte == b'a' { b'b' } else { b'a' };
    }
    let first = 0_u64.to_be_bytes().to_vec();
    for (op, params) in [
        // Another request kind of the same account.
        (Op::FetchCapabilities, with_cursor(&account, lock_cursor)),
        (
            Op::FetchRootChain,
            with_cursor(&[account.clone(), first.clone()].concat(), lock_cursor),
        ),
        // Another root, account or first position.
        (
            Op::FetchBindingLocks,
            with_cursor(
                &[account.clone(), vec![0x77; 32], first.clone()].concat(),
                lock_cursor,
            ),
        ),
        (
            Op::FetchBindingLocks,
            with_cursor(
                &[
                    account_param(&other_account),
                    fingerprint.to_vec(),
                    first.clone(),
                ]
                .concat(),
                lock_cursor,
            ),
        ),
        (
            Op::FetchBindingLocks,
            with_cursor(&locks_from(&harness, 1)?, lock_cursor),
        ),
    ] {
        refused(&harness, op, &params)?;
    }
    // A receipt cursor names neither another conversation nor another first
    // position, and a lock cursor is no receipt cursor.
    let other_conversation = [0x42; 32];
    harness
        .coordinator
        .state
        .conversations
        .insert(other_conversation, Default::default());
    for (op, params) in [
        (
            Op::FetchReceipts,
            with_cursor(&receipts_from(other_conversation, 0), receipt_cursor),
        ),
        (
            Op::FetchReceipts,
            with_cursor(&receipts_from(conversation, 1), receipt_cursor),
        ),
        (
            Op::FetchReceipts,
            with_cursor(&receipts_from(conversation, 0), lock_cursor),
        ),
        (
            Op::FetchAcks,
            with_cursor(&[conversation, [0; 32]].concat(), receipt_cursor),
        ),
    ] {
        refused(&harness, op, &params)?;
    }
    // Both cuts still continue for their own requester and binding.
    let prefix = locks_from(&harness, 0)?;
    page(&mut harness, Op::FetchBindingLocks, &prefix, locks.next)?;
    page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        receipts.next,
    )?;
    Ok(())
}

#[test]
fn a_cursor_is_refused_to_any_other_requester() -> TestResult {
    let (mut harness, conversation, locks, receipts) = listings()?;
    let lock_params = with_cursor(&locks_from(&harness, 0)?, locks.next.ok_or("a cursor")?);
    let receipt_params = with_cursor(
        &receipts_from(conversation, 0),
        receipts.next.ok_or("a cursor")?,
    );
    let own = Requester::of(&harness)?;
    let other_digest = account_id_digest(&NETWORK, &[b'z'; 24])?;
    let others = [
        Requester {
            user: [0x61; 16],
            ..Requester::of(&harness)?
        },
        Requester {
            origin: CompanionOrigin {
                generation: own.origin.generation + 1,
                ..own.origin.clone()
            },
            ..Requester::of(&harness)?
        },
        Requester {
            origin: CompanionOrigin {
                origin_id: [0x62; 16],
                ..own.origin.clone()
            },
            ..Requester::of(&harness)?
        },
        Requester {
            origin: CompanionOrigin {
                home_server_id: [0x63; 16],
                ..own.origin.clone()
            },
            ..Requester::of(&harness)?
        },
        Requester {
            origin: CompanionOrigin {
                account_digest: Some(other_digest),
                ..own.origin.clone()
            },
            ..Requester::of(&harness)?
        },
    ];
    for other in &others {
        refused_as(&harness, other, Op::FetchBindingLocks, &lock_params)?;
    }
    // A device-bound cut is bound to its attachment too: attaching the
    // device again ends it.
    harness.attach()?;
    refused(&harness, Op::FetchReceipts, &receipt_params)?;
    // The account-bound cut binds no attachment: under the same origin
    // generation it continues.
    let prefix = locks_from(&harness, 0)?;
    page(&mut harness, Op::FetchBindingLocks, &prefix, locks.next)?;
    Ok(())
}

#[test]
fn a_cursor_expires_at_the_exact_directory_cursor_timeout() -> TestResult {
    let (mut harness, conversation, _, receipts) = listings()?;
    let params = with_cursor(
        &receipts_from(conversation, 0),
        receipts.next.ok_or("a cursor")?,
    );
    let mut requester = Requester::of(&harness)?;
    requester.monotonic_millis = harness.monotonic_millis + 599_999;
    let (outcome, _) = evaluate(&harness, &requester, Op::FetchReceipts, &params)?;
    assert_eq!(
        outcome.map(|outcome| outcome.result).ok(),
        Some(ResultBody::ObjectPage)
    );
    requester.monotonic_millis += 1;
    refused_as(&harness, &requester, Op::FetchReceipts, &params)?;
    harness.monotonic_millis = requester.monotonic_millis;
    refused(&harness, Op::FetchReceipts, &params)?;
    Ok(())
}

#[test]
fn a_consumed_cursor_is_refused_while_its_successor_continues() -> TestResult {
    let (mut harness, conversation, _, receipts) = listings()?;
    let prefix = receipts_from(conversation, 0);
    let first = receipts.next.ok_or("a cursor")?;
    // A page whose batch never commits consumes nothing.
    let (uncommitted, _) = evaluate(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &with_cursor(&prefix, first),
    )?;
    assert!(uncommitted.is_ok());
    let second = page(&mut harness, Op::FetchReceipts, &prefix, Some(first))?;
    assert_eq!(second.snapshot, receipts.snapshot);
    assert_eq!(second.next, None);
    refused(&harness, Op::FetchReceipts, &with_cursor(&prefix, first))?;
    assert_eq!(
        harness.coordinator.state.listing_snapshots.cursors(),
        1,
        "the last page released its cut; the lock cut remains"
    );
    Ok(())
}

#[test]
fn every_cursor_continues_once_in_a_cut_of_several_pages() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    for sequence in 0..100 {
        seed_record(&mut harness, conversation, sequence, 900)?;
    }
    let prefix = receipts_from(conversation, 0);
    let mut used = Vec::new();
    let mut cursor = None;
    let mut sizes = Vec::new();
    loop {
        let next = page(&mut harness, Op::FetchReceipts, &prefix, cursor)?;
        sizes.push(next.objects.len());
        used.extend(cursor);
        for consumed in &used {
            refused(
                &harness,
                Op::FetchReceipts,
                &with_cursor(&prefix, *consumed),
            )?;
        }
        match next.next {
            Some(successor) => cursor = Some(successor),
            None => break,
        }
    }
    assert_eq!(sizes, vec![32, 32, 32, 4]);
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 0);
    Ok(())
}

#[test]
fn a_restart_discards_every_cut_and_starts_a_new_one() -> TestResult {
    let devices = many_devices();
    let mut harness = provisioned(&devices)?;
    let statements = publish_statements(&mut harness, &devices)?;
    let prefix = account_param(&harness.account);
    let first = page(&mut harness, Op::FetchCapabilities, &prefix, None)?;
    let cursor = first.next.ok_or("a cursor")?;
    let mut restarted = harness.reloaded()?;
    assert_eq!(restarted.coordinator.state.listing_snapshots.cursors(), 0);
    refused(
        &restarted,
        Op::FetchCapabilities,
        &with_cursor(&prefix, cursor),
    )?;
    let fresh = pages(&mut restarted, Op::FetchCapabilities, &prefix)?;
    assert_eq!(
        counts(&fresh),
        vec![MAX_BATCH_OBJECTS, ENTRIES - MAX_BATCH_OBJECTS]
    );
    assert_eq!(objects(&fresh), statements);
    Ok(())
}

/// A cut whose object is no longer retained as it was captured cannot be
/// served: its continuation is refused rather than spliced (companion 11.6:
/// "A missing generation blocks identity advancement").
#[test]
fn a_cut_whose_object_is_gone_or_altered_is_refused_rather_than_spliced() -> TestResult {
    let (mut harness, conversation, _, receipts) = listings()?;
    let params = with_cursor(
        &receipts_from(conversation, 0),
        receipts.next.ok_or("a cursor")?,
    );
    let last = *harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .and_then(|known| known.records.get(&(ENTRIES as u64 - 1)))
        .ok_or("the last record")?;
    let bytes = harness
        .coordinator
        .state
        .objects
        .remove(&last)
        .ok_or("the last record's object")?;
    refused(&harness, Op::FetchReceipts, &params)?;
    let mut altered = bytes.clone();
    altered.push(0);
    harness.coordinator.state.objects.insert(last, altered);
    refused(&harness, Op::FetchReceipts, &params)?;
    harness.coordinator.state.objects.insert(last, bytes);
    let second = page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        receipts.next,
    )?;
    assert_eq!(second.snapshot, receipts.snapshot);
    Ok(())
}

/// The counter value from which the next 32-byte draw repeats `token`.
fn replaying(token: [u8; 32]) -> TestResult<Counter> {
    Ok(Counter(token.first().ok_or("a token")?.wrapping_sub(1)))
}

/// A successor cursor drawn equal to the cursor it consumes, or to another
/// live cursor, is refused: a consumed cursor never becomes live again, and
/// no two cuts share a cursor.
#[test]
fn a_cursor_drawn_equal_to_a_consumed_or_live_one_is_refused() -> TestResult {
    let (mut harness, conversation, locks, _) = listings()?;
    // A cut of three pages, whose first continuation draws a successor.
    for sequence in ENTRIES as u64..80 {
        seed_record(&mut harness, conversation, sequence, 900)?;
    }
    let prefix = receipts_from(conversation, 1);
    let receipts = page(&mut harness, Op::FetchReceipts, &prefix, None)?;
    let receipt_cursor = receipts.next.ok_or("a cursor")?;
    harness.entropy = replaying(receipt_cursor)?;
    let (outcome, _) = evaluate(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &with_cursor(&prefix, receipt_cursor),
    )?;
    assert_eq!(
        outcome
            .map(|outcome| outcome.result)
            .map_err(|fail| fail.code),
        Err(E2eeReplyCode::RateLimited)
    );
    // A new cut whose cursor would repeat the live lock cursor: its
    // snapshot token is drawn first, then the cursor.
    let lock_cursor = locks.next.ok_or("a cursor")?;
    harness.entropy = Counter(
        lock_cursor
            .first()
            .ok_or("a token")?
            .wrapping_sub(1)
            .wrapping_sub(32),
    );
    let (outcome, _) = evaluate(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &[receipts_from(conversation, 2), vec![0]].concat(),
    )?;
    assert_eq!(
        outcome
            .map(|outcome| outcome.result)
            .map_err(|fail| fail.code),
        Err(E2eeReplyCode::RateLimited)
    );
    // A successor that would repeat the live lock cursor.
    harness.entropy = replaying(lock_cursor)?;
    let (outcome, _) = evaluate(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &with_cursor(&prefix, receipt_cursor),
    )?;
    assert_eq!(
        outcome
            .map(|outcome| outcome.result)
            .map_err(|fail| fail.code),
        Err(E2eeReplyCode::RateLimited)
    );
    // Drawn apart, both succeed.
    harness.entropy = Counter(lock_cursor.first().ok_or("a token")?.wrapping_add(31));
    let (outcome, _) = evaluate(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &with_cursor(&prefix, receipt_cursor),
    )?;
    assert_eq!(
        outcome.map(|outcome| outcome.result).ok(),
        Some(ResultBody::ObjectPage)
    );
    Ok(())
}
