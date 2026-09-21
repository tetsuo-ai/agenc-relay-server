#![forbid(unsafe_code)]

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn snapshot_hash_checks_declared_length_before_accepting_input() -> TestResult {
    for length in [0, 19, 21, MAX_SNAPSHOT_CANONICAL_BYTES + 32, usize::MAX] {
        assert!(matches!(
            FederationSnapshotHash::new(length),
            Err(CryptoError::LimitExceeded)
        ));
    }
    let mut short = FederationSnapshotHash::new(20)?;
    short.update(&[1; 19])?;
    assert_eq!(short.finish(), Err(CryptoError::InvalidEncoding));
    let mut extra = FederationSnapshotHash::new(20)?;
    assert_eq!(extra.update(&[1; 21]), Err(CryptoError::LimitExceeded));
    extra.update(&[1; 20])?;
    assert_eq!(extra.update(&[2]), Err(CryptoError::LimitExceeded));
    assert_eq!(
        extra.finish()?,
        super::super::semantic_digest(SemanticHashDomain::FederationSnapshot, &[1; 20])?
    );
    Ok(())
}

#[test]
fn snapshot_digest_matches_the_registered_domain_across_chunk_boundaries() -> TestResult {
    let bytes = [23; 20 + 32 * 7];
    let expected = super::super::semantic_digest(SemanticHashDomain::FederationSnapshot, &bytes)?;
    for width in [1, 7, 20, 31, 32, 64, bytes.len()] {
        let mut hash = FederationSnapshotHash::new(bytes.len())?;
        for chunk in bytes.chunks(width) {
            hash.update(chunk)?;
        }
        assert_eq!(hash.finish()?, expected);
    }
    assert_ne!(
        expected,
        super::super::semantic_digest(SemanticHashDomain::FederationOriginState, &bytes)?
    );
    Ok(())
}
