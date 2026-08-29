//! Signed physical-growth qualification reports and tuple lookup.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use agenc_ircd_crypto::{
    Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, SignatureDomain, StorageDigest,
    sign_canonical, verify_canonical,
};

use crate::codec::{Decoder, Encoder};
use crate::{
    FilesystemTuple, MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH, StorageError, StorageQualification,
};

/// Release qualification's greatest allowed observed positive growth: half the physical growth
/// every admitted transaction reserves, so a qualified filesystem keeps a twofold margin.
pub const MAX_QUALIFIED_OBSERVED_GROWTH: u64 = MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH / 2;
/// Greatest number of independently measured cases in one report.
pub const MAX_QUALIFICATION_CASES: usize = 65_535;
/// Greatest canonical signed report bytes.
pub const MAX_QUALIFICATION_REPORT_BYTES: usize = 16_777_000;

/// Complete native workload required in every release qualification report.
pub const REQUIRED_QUALIFICATION_CASES: [&str; 21] = [
    "insert-empty",
    "insert-one",
    "replace-min",
    "delete-one",
    "insert-max-value",
    "replace-max-value",
    "delete-max-value",
    "insert-max-key",
    "insert-max-records",
    "delete-max-records",
    "mixed-max-records",
    "btree-split",
    "btree-merge",
    "fragmented",
    "checkpoint",
    "guard-temp-fsync",
    "guard-rename",
    "guard-directory-fsync",
    "reserve-equal",
    "reserve-minus-one",
    "reserve-plus-one",
];

/// Closed target registry accepted by version-one storage qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum QualificationTarget {
    /// Linux GNU ABI on x86-64.
    X86_64UnknownLinuxGnu = 1,
    /// Linux GNU ABI on AArch64.
    Aarch64UnknownLinuxGnu = 2,
}

impl QualificationTarget {
    /// Returns the target triple embedded in the release report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64UnknownLinuxGnu => "x86_64-unknown-linux-gnu",
            Self::Aarch64UnknownLinuxGnu => "aarch64-unknown-linux-gnu",
        }
    }

    /// Returns the native target selected by this release build.
    #[must_use]
    pub const fn native() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::X86_64UnknownLinuxGnu
        }
        #[cfg(target_arch = "aarch64")]
        {
            Self::Aarch64UnknownLinuxGnu
        }
    }

    fn decode(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::X86_64UnknownLinuxGnu),
            2 => Ok(Self::Aarch64UnknownLinuxGnu),
            _ => Err(StorageError::UnsupportedVersion),
        }
    }
}

/// One measured before/after allocated-block case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageGrowthCase {
    name: String,
    allocated_before: u64,
    allocated_after: u64,
}

impl StorageGrowthCase {
    /// Validates one canonical case name and its raw byte measurements.
    pub fn new(
        name: String,
        allocated_before: u64,
        allocated_after: u64,
    ) -> Result<Self, StorageError> {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            name,
            allocated_before,
            allocated_after,
        })
    }

    /// Borrows the canonical case name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns allocated bytes immediately before the measured boundary.
    #[must_use]
    pub const fn allocated_before(&self) -> u64 {
        self.allocated_before
    }

    /// Returns allocated bytes immediately after the measured boundary.
    #[must_use]
    pub const fn allocated_after(&self) -> u64 {
        self.allocated_after
    }

    /// Returns positive growth; reclaimed bytes contribute zero.
    #[must_use]
    pub const fn positive_delta(&self) -> u64 {
        self.allocated_after.saturating_sub(self.allocated_before)
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        encoder.put_vector_u32(self.name.as_bytes())?;
        encoder.put_u64(self.allocated_before)?;
        encoder.put_u64(self.allocated_after)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let name = std::str::from_utf8(decoder.vector_u32(64)?)
            .map_err(|_| StorageError::InvalidEncoding)?
            .to_owned();
        Self::new(name, decoder.u64()?, decoder.u64()?)
    }
}

/// Canonical report fields signed by the release authority.
pub struct StorageQualificationReportTbs {
    /// Qualified compilation target.
    pub target: QualificationTarget,
    /// Linux filesystem magic.
    pub filesystem_type: u64,
    /// Allocation block size.
    pub block_size: u64,
    /// Relevant mount flags.
    pub mount_flags: u64,
    /// Exact printable kernel release.
    pub kernel_release: String,
    /// Hash of the enabled redb feature registry.
    pub redb_features_hash: StorageDigest,
    /// Hash of the release profile used for measurement.
    pub release_profile_hash: StorageDigest,
    /// Hash of the generated boundary corpus.
    pub corpus_hash: StorageDigest,
    /// Per-case raw allocated-byte observations.
    pub cases: Vec<StorageGrowthCase>,
    /// Greatest positive delta across every case.
    pub maximum_observed_growth: u64,
    /// Hash of the immutable raw measurement log.
    pub raw_log_hash: StorageDigest,
}

impl StorageQualificationReportTbs {
    /// Validates tuple fields, complete required corpus, ordering, and exact maximum.
    // agenc-review: focus owner=storage reviewed=2026-08-28 reason=closed signed qualification matrix validates tuple corpus ordering and maximum as one statement
    pub fn validate(&self) -> Result<(), StorageError> {
        let zero = StorageDigest::from_bytes([0_u8; 32]);
        if self.filesystem_type == 0
            || self.block_size == 0
            || !self.block_size.is_power_of_two()
            || self.kernel_release.is_empty()
            || self.kernel_release.len() > 256
            || !self
                .kernel_release
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
            || self.cases.is_empty()
            || self.cases.len() > MAX_QUALIFICATION_CASES
            || self.maximum_observed_growth > MAX_QUALIFIED_OBSERVED_GROWTH
            || self.redb_features_hash == zero
            || self.release_profile_hash == zero
            || self.corpus_hash == zero
            || self.raw_log_hash == zero
        {
            return Err(StorageError::InvalidEncoding);
        }
        let mut names = BTreeSet::new();
        let mut previous: Option<&str> = None;
        let mut maximum = 0_u64;
        for case in &self.cases {
            if previous.is_some_and(|name| name >= case.name()) {
                return Err(StorageError::InvalidEncoding);
            }
            names.insert(case.name.as_str());
            maximum = maximum.max(case.positive_delta());
            previous = Some(case.name());
        }
        if maximum != self.maximum_observed_growth
            || REQUIRED_QUALIFICATION_CASES
                .iter()
                .any(|name| !names.contains(name))
        {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(1_024, MAX_QUALIFICATION_REPORT_BYTES)?;
        encoder.put_u16(1)?;
        encoder.put_u16(self.target as u16)?;
        encoder.put_u64(self.filesystem_type)?;
        encoder.put_u64(self.block_size)?;
        encoder.put_u64(self.mount_flags)?;
        encoder.put_vector_u32(self.kernel_release.as_bytes())?;
        encoder.put_fixed(self.redb_features_hash.as_bytes())?;
        encoder.put_fixed(self.release_profile_hash.as_bytes())?;
        encoder.put_fixed(self.corpus_hash.as_bytes())?;
        encoder
            .put_u32(u32::try_from(self.cases.len()).map_err(|_| StorageError::LimitExceeded)?)?;
        for case in &self.cases {
            case.encode(&mut encoder)?;
        }
        encoder.put_u64(self.maximum_observed_growth)?;
        encoder.put_fixed(self.raw_log_hash.as_bytes())?;
        Ok(encoder.finish())
    }

    /// Encodes the validated unsigned measurement for offline signing.
    pub fn encode_unsigned(&self) -> Result<Vec<u8>, StorageError> {
        self.encode()
    }

    fn decode(encoded: &[u8]) -> Result<Self, StorageError> {
        let mut decoder = Decoder::new(encoded);
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let target = QualificationTarget::decode(decoder.u16()?)?;
        let filesystem_type = decoder.u64()?;
        let block_size = decoder.u64()?;
        let mount_flags = decoder.u64()?;
        let kernel_release = std::str::from_utf8(decoder.vector_u32(256)?)
            .map_err(|_| StorageError::InvalidEncoding)?
            .to_owned();
        let redb_features_hash = StorageDigest::from_bytes(decoder.array()?);
        let release_profile_hash = StorageDigest::from_bytes(decoder.array()?);
        let corpus_hash = StorageDigest::from_bytes(decoder.array()?);
        let count = usize::try_from(decoder.u32()?).map_err(|_| StorageError::Overflow)?;
        if count == 0 || count > MAX_QUALIFICATION_CASES {
            return Err(StorageError::LimitExceeded);
        }
        let mut cases = Vec::new();
        cases
            .try_reserve_exact(count)
            .map_err(|_| StorageError::AllocationFailed)?;
        for _ in 0..count {
            cases.push(StorageGrowthCase::decode(&mut decoder)?);
        }
        let value = Self {
            target,
            filesystem_type,
            block_size,
            mount_flags,
            kernel_release,
            redb_features_hash,
            release_profile_hash,
            corpus_hash,
            cases,
            maximum_observed_growth: decoder.u64()?,
            raw_log_hash: StorageDigest::from_bytes(decoder.array()?),
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    /// Parses a full-consumption unsigned measurement produced by the native harness.
    pub fn decode_unsigned(encoded: &[u8]) -> Result<Self, StorageError> {
        if encoded.len() > MAX_QUALIFICATION_REPORT_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        Self::decode(encoded)
    }
}

/// Complete signed release qualification artifact.
pub struct StorageQualificationReport {
    tbs: StorageQualificationReportTbs,
    signature: Ed25519Signature,
}

impl StorageQualificationReport {
    /// Signs one fully validated report with the release key.
    pub fn sign(
        tbs: StorageQualificationReportTbs,
        release_key: &Ed25519SecretKey,
    ) -> Result<Self, StorageError> {
        let signature = sign_canonical(
            release_key,
            SignatureDomain::StorageQualificationReport,
            &tbs.encode()?,
        )?;
        Ok(Self { tbs, signature })
    }

    /// Encodes the canonical report followed by its fixed signature.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let tbs = self.tbs.encode()?;
        let capacity = 4_usize
            .checked_add(tbs.len())
            .and_then(|value| value.checked_add(64))
            .ok_or(StorageError::Overflow)?;
        let mut encoder = Encoder::with_capacity(capacity, MAX_QUALIFICATION_REPORT_BYTES)?;
        encoder.put_vector_u32(&tbs)?;
        encoder.put_fixed(self.signature.as_bytes())?;
        Ok(encoder.finish())
    }

    /// Parses and verifies one full-consumption signed report.
    pub fn decode_and_verify(
        encoded: &[u8],
        trusted_release_key: Ed25519PublicKey,
    ) -> Result<Self, StorageError> {
        if encoded.len() > MAX_QUALIFICATION_REPORT_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let mut decoder = Decoder::new(encoded);
        let tbs_bytes = decoder.vector_u32(MAX_QUALIFICATION_REPORT_BYTES - 68)?;
        let signature = Ed25519Signature::from_bytes(decoder.array()?);
        decoder.finish()?;
        verify_canonical(
            trusted_release_key,
            SignatureDomain::StorageQualificationReport,
            tbs_bytes,
            signature,
        )?;
        Ok(Self {
            tbs: StorageQualificationReportTbs::decode(tbs_bytes)?,
            signature,
        })
    }

    /// Selects this report only for the exact probed target/filesystem tuple.
    pub fn qualification_for(
        &self,
        tuple: FilesystemTuple,
    ) -> Result<StorageQualification, StorageError> {
        if tuple.target != self.tbs.target.as_str()
            || tuple.filesystem_type != self.tbs.filesystem_type
            || tuple.block_size != self.tbs.block_size
            || tuple.mount_flags != self.tbs.mount_flags
        {
            return Err(StorageError::FilesystemRejected);
        }
        StorageQualification::from_verified_report(tuple, self.tbs.maximum_observed_growth)
            .validate()
    }

    /// Borrows the authenticated report fields.
    #[must_use]
    pub const fn tbs(&self) -> &StorageQualificationReportTbs {
        &self.tbs
    }
}

/// Accumulates raw case measurements before report signing.
pub struct StorageGrowthRecorder {
    cases: Vec<StorageGrowthCase>,
}

impl StorageGrowthRecorder {
    /// Creates an empty bounded recorder.
    #[must_use]
    pub const fn new() -> Self {
        Self { cases: Vec::new() }
    }

    /// Adds one case without permitting duplicate names or excessive growth.
    pub fn record(&mut self, case: StorageGrowthCase) -> Result<(), StorageError> {
        if self.cases.len() == MAX_QUALIFICATION_CASES
            || case.positive_delta() > MAX_QUALIFIED_OBSERVED_GROWTH
            || self.cases.iter().any(|existing| existing.name == case.name)
        {
            return Err(StorageError::LimitExceeded);
        }
        self.cases.push(case);
        Ok(())
    }

    /// Measures actual allocated filesystem blocks around one durable workload case.
    pub fn measure_file<T>(
        &mut self,
        name: &str,
        file: &File,
        operation: impl FnOnce() -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        self.measure_file_set(name, &[file], || {
            let result = operation()?;
            file.sync_all()
                .map_err(|_| StorageError::FilesystemRejected)?;
            Ok(result)
        })
    }

    /// Measures one exact durable boundary across the database, guard files, and directory.
    ///
    /// The caller opens every inode that participates in the boundary before sampling and
    /// performs the actual `fsync` or rename inside `operation`. Directory file descriptors
    /// are ordinary members of `files`, so their allocated metadata blocks are included.
    pub fn measure_file_set<T>(
        &mut self,
        name: &str,
        files: &[&File],
        operation: impl FnOnce() -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        if files.is_empty() {
            return Err(StorageError::InvalidEncoding);
        }
        let allocated_before = allocated_file_set(files)?;
        let result = operation()?;
        let allocated_after = allocated_file_set(files)?;
        self.record(StorageGrowthCase::new(
            name.to_owned(),
            allocated_before,
            allocated_after,
        )?)?;
        Ok(result)
    }

    /// Measures a boundary by resolving every participating path before and after it.
    ///
    /// Missing paths contribute zero, which permits an atomic rename to remove a
    /// temporary name while replacing the final guard inode. The caller must pass
    /// the database, guard temporary/final, and parent-directory paths explicitly.
    pub fn measure_path_set<T>(
        &mut self,
        name: &str,
        paths: &[&Path],
        operation: impl FnOnce() -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        if paths.is_empty() {
            return Err(StorageError::InvalidEncoding);
        }
        let allocated_before = allocated_path_set(paths)?;
        let result = operation()?;
        let allocated_after = allocated_path_set(paths)?;
        self.record(StorageGrowthCase::new(
            name.to_owned(),
            allocated_before,
            allocated_after,
        )?)?;
        Ok(result)
    }

    /// Measures every required case against one real database file.
    pub fn measure_required_corpus(
        &mut self,
        file: &File,
        mut run_case: impl FnMut(&str) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        for name in REQUIRED_QUALIFICATION_CASES {
            self.measure_file(name, file, || run_case(name))?;
        }
        Ok(())
    }

    /// Measures every required case over the complete set of participating filesystem objects.
    ///
    /// Callers pass open database, guard, temporary, and directory descriptors and perform each
    /// case's real sync or rename before returning. The fixed case order becomes part of the
    /// signed report and cannot be shortened or reordered by a release harness.
    pub fn measure_required_file_set(
        &mut self,
        files: &[&File],
        mut run_case: impl FnMut(&str) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        for name in REQUIRED_QUALIFICATION_CASES {
            self.measure_file_set(name, files, || run_case(name))?;
        }
        Ok(())
    }

    /// Returns sorted cases and their exact maximum positive delta.
    pub fn finish(mut self) -> Result<(Vec<StorageGrowthCase>, u64), StorageError> {
        self.cases.sort_by(|left, right| left.name.cmp(&right.name));
        let maximum = self
            .cases
            .iter()
            .map(StorageGrowthCase::positive_delta)
            .max()
            .ok_or(StorageError::InvalidEncoding)?;
        Ok((self.cases, maximum))
    }
}

fn allocated_bytes(file: &File) -> Result<u64, StorageError> {
    file.metadata()
        .map_err(|_| StorageError::FilesystemRejected)?
        .blocks()
        .checked_mul(512)
        .ok_or(StorageError::Overflow)
}

fn allocated_file_set(files: &[&File]) -> Result<u64, StorageError> {
    files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(allocated_bytes(file)?)
            .ok_or(StorageError::Overflow)
    })
}

fn allocated_path_set(paths: &[&Path]) -> Result<u64, StorageError> {
    paths.iter().try_fold(0_u64, |total, path| {
        let blocks = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata
                .blocks()
                .checked_mul(512)
                .ok_or(StorageError::Overflow)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(_) => return Err(StorageError::FilesystemRejected),
        };
        total.checked_add(blocks).ok_or(StorageError::Overflow)
    })
}

impl Default for StorageGrowthRecorder {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifies the signed release report compiled for the native target.
pub fn embedded_storage_qualifications() -> Result<Vec<StorageQualification>, StorageError> {
    let public_key_bytes: [u8; 32] = *include_bytes!(
        "../../../conformance/evidence/storage-qualification/release-public-key.bin"
    );
    let public_key = Ed25519PublicKey::from_bytes(public_key_bytes)?;
    #[cfg(target_arch = "x86_64")]
    let reports: &[&[u8]] = &[include_bytes!(
        "../../../conformance/evidence/storage-qualification/x86_64-unknown-linux-gnu-ext4.report"
    )];
    #[cfg(target_arch = "aarch64")]
    let reports: &[&[u8]] = &[include_bytes!(
        "../../../conformance/evidence/storage-qualification/aarch64-unknown-linux-gnu-ext4.report"
    )];
    reports
        .iter()
        .map(|encoded| {
            let report = StorageQualificationReport::decode_and_verify(encoded, public_key)?;
            let tbs = report.tbs();
            let tuple = FilesystemTuple {
                target: tbs.target.as_str(),
                filesystem_type: tbs.filesystem_type,
                block_size: tbs.block_size,
                mount_flags: tbs.mount_flags,
            };
            report.qualification_for(tuple)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
    const NONZERO: StorageDigest = StorageDigest::from_bytes([1; 32]);

    struct TestFile {
        path: PathBuf,
        file: File,
    }

    impl TestFile {
        fn create() -> Result<Self, StorageError> {
            let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agenc-qualification-{}-{sequence}",
                std::process::id()
            ));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|_| StorageError::FilesystemRejected)?;
            Ok(Self { path, file })
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn required_cases() -> Result<Vec<StorageGrowthCase>, StorageError> {
        let mut cases = REQUIRED_QUALIFICATION_CASES
            .iter()
            .map(|name| StorageGrowthCase::new((*name).to_owned(), 1, 1))
            .collect::<Result<Vec<_>, _>>()?;
        cases.sort_by(|left, right| left.name().cmp(right.name()));
        Ok(cases)
    }

    fn valid_tbs() -> Result<StorageQualificationReportTbs, StorageError> {
        Ok(StorageQualificationReportTbs {
            target: QualificationTarget::X86_64UnknownLinuxGnu,
            filesystem_type: 0xef53,
            block_size: 4_096,
            mount_flags: 1,
            kernel_release: "6.16.0".to_owned(),
            redb_features_hash: NONZERO,
            release_profile_hash: NONZERO,
            corpus_hash: NONZERO,
            cases: required_cases()?,
            maximum_observed_growth: 0,
            raw_log_hash: NONZERO,
        })
    }

    #[test]
    fn growth_cases_validate_names_and_positive_delta() -> Result<(), StorageError> {
        let case = StorageGrowthCase::new("valid-case-2".to_owned(), 9, 4)?;
        assert_eq!(case.name(), "valid-case-2");
        assert_eq!(case.allocated_before(), 9);
        assert_eq!(case.allocated_after(), 4);
        assert_eq!(case.positive_delta(), 0);
        assert_eq!(
            StorageGrowthCase::new("growth".to_owned(), 4, 9)?.positive_delta(),
            5
        );
        for name in ["", "UPPER", "bad_name", "bad space"] {
            assert!(matches!(
                StorageGrowthCase::new(name.to_owned(), 0, 0),
                Err(StorageError::InvalidEncoding)
            ));
        }
        assert!(matches!(
            StorageGrowthCase::new("a".repeat(65), 0, 0),
            Err(StorageError::InvalidEncoding)
        ));
        assert_eq!(
            QualificationTarget::decode(1)?.as_str(),
            "x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            QualificationTarget::decode(2)?.as_str(),
            "aarch64-unknown-linux-gnu"
        );
        assert_eq!(
            QualificationTarget::decode(3),
            Err(StorageError::UnsupportedVersion)
        );
        Ok(())
    }

    #[test]
    fn report_tbs_rejects_every_independent_tuple_and_hash_boundary() -> Result<(), StorageError> {
        valid_tbs()?.validate()?;

        let mut invalid = valid_tbs()?;
        invalid.filesystem_type = 0;
        assert_eq!(invalid.validate(), Err(StorageError::InvalidEncoding));
        let mut invalid = valid_tbs()?;
        invalid.block_size = 0;
        assert_eq!(invalid.validate(), Err(StorageError::InvalidEncoding));
        let mut invalid = valid_tbs()?;
        invalid.block_size = 3;
        assert_eq!(invalid.validate(), Err(StorageError::InvalidEncoding));
        let mut invalid = valid_tbs()?;
        invalid.kernel_release.clear();
        assert_eq!(invalid.validate(), Err(StorageError::InvalidEncoding));
        let mut invalid = valid_tbs()?;
        invalid.kernel_release = "a".repeat(257);
        assert_eq!(invalid.validate(), Err(StorageError::InvalidEncoding));
        let mut invalid = valid_tbs()?;
        invalid.kernel_release = "contains space".to_owned();
        assert_eq!(invalid.validate(), Err(StorageError::InvalidEncoding));
        let mut invalid = valid_tbs()?;
        invalid.cases.clear();
        assert_eq!(invalid.validate(), Err(StorageError::InvalidEncoding));
        let mut invalid = valid_tbs()?;
        invalid.maximum_observed_growth = MAX_QUALIFIED_OBSERVED_GROWTH + 1;
        assert_eq!(invalid.validate(), Err(StorageError::InvalidEncoding));

        for field in 0..4 {
            let mut invalid = valid_tbs()?;
            match field {
                0 => invalid.redb_features_hash = StorageDigest::from_bytes([0; 32]),
                1 => invalid.release_profile_hash = StorageDigest::from_bytes([0; 32]),
                2 => invalid.corpus_hash = StorageDigest::from_bytes([0; 32]),
                _ => invalid.raw_log_hash = StorageDigest::from_bytes([0; 32]),
            }
            assert_eq!(invalid.validate(), Err(StorageError::InvalidEncoding));
        }
        Ok(())
    }

    #[test]
    fn report_tbs_rejects_order_duplicates_missing_cases_and_wrong_maximum()
    -> Result<(), StorageError> {
        let mut invalid = valid_tbs()?;
        invalid.cases.swap(0, 1);
        assert_eq!(invalid.validate(), Err(StorageError::InvalidEncoding));

        let mut invalid = valid_tbs()?;
        let duplicate_name = invalid
            .cases
            .first()
            .ok_or(StorageError::StaleState)?
            .name()
            .to_owned();
        *invalid.cases.get_mut(1).ok_or(StorageError::StaleState)? =
            StorageGrowthCase::new(duplicate_name, 1, 1)?;
        assert_eq!(invalid.validate(), Err(StorageError::InvalidEncoding));

        let mut invalid = valid_tbs()?;
        invalid.cases.pop();
        assert_eq!(invalid.validate(), Err(StorageError::StaleState));

        let mut invalid = valid_tbs()?;
        invalid.maximum_observed_growth = 1;
        assert_eq!(invalid.validate(), Err(StorageError::StaleState));
        Ok(())
    }

    #[test]
    fn signed_report_verification_binds_signature_and_exact_tuple() -> Result<(), StorageError> {
        let release = Ed25519SecretKey::from_bytes([2; 32]);
        let report = StorageQualificationReport::sign(valid_tbs()?, &release)?;
        let encoded = report.encode()?;
        let verified =
            StorageQualificationReport::decode_and_verify(&encoded, release.public_key())?;
        let tuple = FilesystemTuple {
            target: verified.tbs().target.as_str(),
            filesystem_type: verified.tbs().filesystem_type,
            block_size: verified.tbs().block_size,
            mount_flags: verified.tbs().mount_flags,
        };
        verified.qualification_for(tuple)?;
        assert!(matches!(
            StorageQualificationReport::decode_and_verify(
                &encoded,
                Ed25519SecretKey::from_bytes([3; 32]).public_key(),
            ),
            Err(StorageError::AuthenticationFailed)
        ));

        for mismatch in 0..4 {
            let mut wrong = tuple;
            match mismatch {
                0 => wrong.target = "aarch64-unknown-linux-gnu",
                1 => wrong.filesystem_type += 1,
                2 => wrong.block_size += 1,
                _ => wrong.mount_flags += 1,
            }
            assert_eq!(
                verified.qualification_for(wrong),
                Err(StorageError::FilesystemRejected)
            );
        }
        assert_eq!(
            StorageQualificationReportTbs::decode_unsigned(&vec![
                0;
                MAX_QUALIFICATION_REPORT_BYTES + 1
            ])
            .map(|_| ()),
            Err(StorageError::LimitExceeded)
        );
        assert_eq!(
            StorageQualificationReport::decode_and_verify(
                &vec![0; MAX_QUALIFICATION_REPORT_BYTES + 1],
                release.public_key(),
            )
            .map(|_| ()),
            Err(StorageError::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn recorder_rejects_duplicates_growth_and_empty_measurement_sets() -> Result<(), StorageError> {
        let recorder = StorageGrowthRecorder::new();
        assert_eq!(recorder.finish(), Err(StorageError::InvalidEncoding));

        let mut recorder = StorageGrowthRecorder::new();
        recorder.record(StorageGrowthCase::new("one".to_owned(), 0, 1)?)?;
        assert_eq!(
            recorder.record(StorageGrowthCase::new("one".to_owned(), 0, 1)?),
            Err(StorageError::LimitExceeded)
        );
        assert_eq!(
            recorder.record(StorageGrowthCase::new(
                "too-large".to_owned(),
                0,
                MAX_QUALIFIED_OBSERVED_GROWTH + 1,
            )?),
            Err(StorageError::LimitExceeded)
        );

        let file = TestFile::create()?;
        let mut recorder = StorageGrowthRecorder::new();
        assert_eq!(
            recorder.measure_file_set("empty", &[], || Ok(())),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            recorder.measure_path_set("empty", &[], || Ok(())),
            Err(StorageError::InvalidEncoding)
        );
        recorder.measure_file("file", &file.file, || Ok(()))?;
        let missing = file.path.with_extension("missing");
        recorder.measure_path_set("missing", &[missing.as_path()], || Ok(()))?;
        let (cases, maximum) = recorder.finish()?;
        assert_eq!(cases.len(), 2);
        assert_eq!(maximum, 0);
        Ok(())
    }

    #[test]
    fn recorder_rejects_the_first_case_beyond_capacity() -> Result<(), StorageError> {
        let mut recorder = StorageGrowthRecorder::new();
        for index in 0..MAX_QUALIFICATION_CASES {
            recorder.record(StorageGrowthCase::new(format!("case-{index}"), 1, 1)?)?;
        }
        assert_eq!(
            recorder.record(StorageGrowthCase::new("case-overflow".to_owned(), 1, 1)?),
            Err(StorageError::LimitExceeded),
        );
        Ok(())
    }
}
