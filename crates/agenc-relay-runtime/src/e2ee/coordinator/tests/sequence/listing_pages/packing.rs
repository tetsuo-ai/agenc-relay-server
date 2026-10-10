#![forbid(unsafe_code)]

//! Receipt pages pack complete records against the object count, the
//! summed bytes and the summed per-object fragment counts together
//! (companion 11.7, 16), so a page of fewer than 32 records ends at the byte
//! or fragment ceiling, each at the exact limit and one unit over it, and
//! the edge's batch checks always admit it.

use agenc_relay_e2ee::limits::{
    MAX_BATCH_DECODED_BYTES, MAX_BATCH_FRAGMENTS, MAX_BATCH_OBJECTS, MAX_FRAGMENT_RAW,
};

use super::*;

/// A bound conversation whose records from sequence zero have `sizes`.
fn records(sizes: &[usize]) -> TestResult<(Harness, [u8; 32], Vec<Vec<u8>>)> {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let mut records = Vec::new();
    for (sequence, size) in (0_u64..).zip(sizes) {
        records.push(seed_record(&mut harness, conversation, sequence, *size)?);
    }
    Ok((harness, conversation, records))
}

/// Pages the receipts from sequence zero; requires every record once, in
/// order, every page within all three batch limits, and returns the page
/// sizes.
fn paged(sizes: &[usize]) -> TestResult<Vec<usize>> {
    let (mut harness, conversation, records) = records(sizes)?;
    let pages = pages(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
    )?;
    assert_eq!(objects(&pages), records);
    for page in &pages {
        assert!(page.objects.len() <= MAX_BATCH_OBJECTS);
        assert!(page.objects.iter().map(Vec::len).sum::<usize>() <= MAX_BATCH_DECODED_BYTES);
        assert!(
            page.objects
                .iter()
                .map(|object| object.len().div_ceil(MAX_FRAGMENT_RAW))
                .sum::<usize>()
                <= MAX_BATCH_FRAGMENTS
        );
    }
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 0);
    Ok(counts(&pages))
}

#[test]
fn a_receipt_page_holds_exactly_the_object_count_and_one_more_continues() -> TestResult {
    assert_eq!(
        paged(&vec![900; MAX_BATCH_OBJECTS])?,
        vec![MAX_BATCH_OBJECTS]
    );
    assert_eq!(
        paged(&vec![900; MAX_BATCH_OBJECTS + 1])?,
        vec![MAX_BATCH_OBJECTS, 1]
    );
    Ok(())
}

#[test]
fn a_receipt_page_holds_exactly_the_byte_ceiling_and_one_byte_more_continues() -> TestResult {
    // 713 and 714 fragments, exactly the fragment ceiling: only the bytes
    // decide.
    let first = 713 * MAX_FRAGMENT_RAW;
    let exact = [first, MAX_BATCH_DECODED_BYTES - first];
    assert_eq!(paged(&exact)?, vec![2]);
    assert_eq!(paged(&[exact[0], exact[1] + 1])?, vec![1, 1]);
    Ok(())
}

#[test]
fn fragment_rounding_ends_a_receipt_page_of_fewer_than_32_records() -> TestResult {
    // Two 2 MiB records fill the byte ceiling exactly and round to 1,428
    // fragments, one over the fragment ceiling.
    assert_eq!(paged(&[2_097_152, 2_097_152])?, vec![1, 1]);
    // Exactly the fragment ceiling fits, and one fragment more continues.
    let exact = [713 * MAX_FRAGMENT_RAW, 713 * MAX_FRAGMENT_RAW + 1];
    assert_eq!(paged(&exact)?, vec![2]);
    assert_eq!(paged(&[exact[0], exact[1], 900])?, vec![2, 1]);
    Ok(())
}

/// The byte, fragment and count ceilings end successive pages of one cut.
#[test]
fn every_page_of_one_cut_packs_against_all_three_limits() -> TestResult {
    let mut sizes = vec![2_097_152, 2_097_152];
    sizes.extend(vec![900; MAX_BATCH_OBJECTS + 3]);
    sizes.extend([
        713 * MAX_FRAGMENT_RAW,
        MAX_BATCH_DECODED_BYTES - 713 * MAX_FRAGMENT_RAW,
    ]);
    // The fragments end the first page; the second 2 MiB record opens the
    // second, which the count ends; the bytes end the third, before the
    // last record.
    assert_eq!(paged(&sizes)?, vec![1, MAX_BATCH_OBJECTS, 5, 1]);
    Ok(())
}
