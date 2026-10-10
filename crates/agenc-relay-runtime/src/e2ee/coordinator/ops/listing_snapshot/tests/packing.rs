//! Page packing against every batch limit together (companion 11.7, 16):
//! the object count, the summed decoded bytes and the summed per-object
//! fragment counts of a batch page, and the object ceiling of a root-chain
//! page, each at the exact limit and one unit over it.

#![forbid(unsafe_code)]

use super::{CHAIN_OVERHEAD, Entry, page_end};
use agenc_relay_e2ee::limits::{
    MAX_BATCH_DECODED_BYTES, MAX_BATCH_FRAGMENTS, MAX_BATCH_OBJECTS, MAX_FRAGMENT_RAW,
    MAX_ROOT_CHAIN_OBJECT, WIRE_OBJECT_ENVELOPE_BYTES,
};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::identity::ArcAccountRootChain;
use agenc_relay_e2ee::tls::{Opaque, TlsEncode, TlsVec};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn entries(sizes: &[usize]) -> Vec<Entry> {
    sizes
        .iter()
        .enumerate()
        .map(|(index, size)| Entry {
            object_id: [u8::try_from(index % 256).unwrap_or(0); 32],
            size: *size,
        })
        .collect()
}

/// The fragments one object of `size` bytes takes.
fn fragments(size: usize) -> usize {
    size.div_ceil(MAX_FRAGMENT_RAW)
}

fn end(sizes: &[usize], begin: usize, chain: bool) -> TestResult<usize> {
    page_end(&entries(sizes), begin, chain)
        .map_err(|fail| format!("page refused with {:?}", fail.code).into())
}

#[test]
fn a_batch_page_holds_the_object_count_ceiling_and_stops_one_over() -> TestResult {
    let exact = vec![100; MAX_BATCH_OBJECTS];
    assert_eq!(end(&exact, 0, false)?, MAX_BATCH_OBJECTS);
    let over = vec![100; MAX_BATCH_OBJECTS + 1];
    assert_eq!(end(&over, 0, false)?, MAX_BATCH_OBJECTS);
    assert_eq!(end(&over, MAX_BATCH_OBJECTS, false)?, MAX_BATCH_OBJECTS + 1);
    Ok(())
}

#[test]
fn a_batch_page_holds_the_byte_ceiling_and_stops_one_byte_over() -> TestResult {
    // 713 and 714 fragments: exactly the fragment ceiling, so only the bytes
    // can end the page.
    let exact = [
        713 * MAX_FRAGMENT_RAW,
        MAX_BATCH_DECODED_BYTES - 713 * MAX_FRAGMENT_RAW,
    ];
    assert_eq!(exact.iter().sum::<usize>(), MAX_BATCH_DECODED_BYTES);
    assert_eq!(
        exact.iter().map(|size| fragments(*size)).sum::<usize>(),
        MAX_BATCH_FRAGMENTS
    );
    assert_eq!(end(&exact, 0, false)?, 2);
    let over = [exact[0], exact[1] + 1];
    assert_eq!(fragments(over[1]), fragments(exact[1]));
    assert_eq!(end(&over, 0, false)?, 1);
    assert_eq!(end(&over, 1, false)?, 2);
    Ok(())
}

#[test]
fn fragment_rounding_ends_a_page_of_two_objects_within_the_byte_ceiling() -> TestResult {
    // Two 2 MiB objects fill the byte ceiling exactly, yet each rounds up to
    // 714 fragments: 1,428, one over the fragment ceiling.
    let rounded = [2_097_152, 2_097_152];
    assert_eq!(rounded.iter().sum::<usize>(), MAX_BATCH_DECODED_BYTES);
    assert_eq!(
        rounded.iter().map(|size| fragments(*size)).sum::<usize>(),
        MAX_BATCH_FRAGMENTS + 1
    );
    // Rounding the summed bytes once would undercount: 1,427.
    assert_eq!(fragments(MAX_BATCH_DECODED_BYTES), MAX_BATCH_FRAGMENTS);
    assert_eq!(end(&rounded, 0, false)?, 1);
    assert_eq!(end(&rounded, 1, false)?, 2);
    // Exactly the fragment ceiling below the byte ceiling fits, and one more
    // fragment does not.
    let exact = [713 * MAX_FRAGMENT_RAW, 713 * MAX_FRAGMENT_RAW + 1];
    assert_eq!(
        exact.iter().map(|size| fragments(*size)).sum::<usize>(),
        MAX_BATCH_FRAGMENTS
    );
    assert!(exact.iter().sum::<usize>() < MAX_BATCH_DECODED_BYTES);
    assert_eq!(end(&exact, 0, false)?, 2);
    let over = [exact[0], exact[1], 100];
    assert_eq!(end(&over, 0, false)?, 2);
    assert_eq!(end(&over, 2, false)?, 3);
    Ok(())
}

#[test]
fn a_root_chain_page_holds_its_object_ceiling_and_stops_one_byte_over() -> TestResult {
    let envelope = WIRE_OBJECT_ENVELOPE_BYTES;
    let quarter = 262_144;
    let rest = MAX_ROOT_CHAIN_OBJECT - CHAIN_OVERHEAD - 3 * (quarter - envelope) + envelope;
    let exact = [quarter, quarter, quarter, rest];
    assert_eq!(
        CHAIN_OVERHEAD
            + exact
                .iter()
                .map(|size| size - WIRE_OBJECT_ENVELOPE_BYTES)
                .sum::<usize>(),
        MAX_ROOT_CHAIN_OBJECT
    );
    assert_eq!(end(&exact, 0, true)?, 4);
    let over = [quarter, quarter, quarter, rest + 1];
    assert_eq!(end(&over, 0, true)?, 3);
    assert_eq!(end(&over, 3, true)?, 4);
    // A chain page counts no batch object ceiling: it is one object.
    let many = vec![200; MAX_BATCH_OBJECTS * 4];
    assert_eq!(end(&many, 0, true)?, MAX_BATCH_OBJECTS * 4);
    Ok(())
}

#[test]
fn the_chain_overhead_is_the_encoded_chain_around_its_roots() -> TestResult {
    use crate::e2ee::coordinator::tests::support::{key, root};
    let account = [b'a'; 24];
    let first = root(&key(1), &account, 0, (0, 10), None)?;
    let second = root(&key(2), &account, 1, (0, 10), Some((&key(1), &first)))?;
    let objects = [&first, &second]
        .iter()
        .map(|identity| {
            ArcWireObject::new(ArcWireObjectKind::RootIdentity, identity.encode()?)?.encode()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let chain = ArcAccountRootChain {
        account_id: Opaque::from_slice(&account)?,
        roots: TlsVec::new(vec![first, second])?,
    };
    let encoded =
        ArcWireObject::new(ArcWireObjectKind::RootIdentityChain, chain.encode()?)?.encode()?;
    assert_eq!(
        encoded.len(),
        CHAIN_OVERHEAD
            + objects
                .iter()
                .map(|object| object.len() - WIRE_OBJECT_ENVELOPE_BYTES)
                .sum::<usize>()
    );
    Ok(())
}

#[test]
fn a_page_never_begins_past_its_cut_or_holds_no_object() -> TestResult {
    let sizes = [100, 100];
    assert_eq!(
        page_end(&entries(&sizes), 3, false).map_err(|fail| fail.code),
        Err(E2eeReplyCode::ObjectNotFound)
    );
    assert_eq!(
        page_end(&entries(&sizes), 2, false).map_err(|fail| fail.code),
        Err(E2eeReplyCode::RateLimited)
    );
    let oversized = [MAX_BATCH_DECODED_BYTES + 1];
    assert_eq!(
        page_end(&entries(&oversized), 0, false).map_err(|fail| fail.code),
        Err(E2eeReplyCode::RateLimited)
    );
    let no_body = [WIRE_OBJECT_ENVELOPE_BYTES - 1];
    assert_eq!(
        page_end(&entries(&no_body), 0, true).map_err(|fail| fail.code),
        Err(E2eeReplyCode::ObjectNotFound)
    );
    Ok(())
}
