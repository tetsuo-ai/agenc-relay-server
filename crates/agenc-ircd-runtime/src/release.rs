//! Public profile identities and detached release-decision inspection.
//!
//! A release decision is a directory the qualification runner signs after
//! every job passed: `release.json` in canonical form and `release.sig`, a raw
//! Ed25519 signature over the decision under its own domain. The daemon never
//! trusts a key found beside a signature. The operator supplies the trust
//! anchor explicitly, and the decision grants this executable claims only
//! when its recorded source commit, target, and artifact digest match.

use std::fmt;
use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use agenc_ircd_config::{
    MAX_RELEASE_DECISION_BYTES, MAX_RELEASE_PUBLIC_KEY_BYTES, ReleaseClaim,
    ReleaseDecisionDocument, ReleaseDecisionError, parse_release_public_key_pem,
};
use agenc_ircd_crypto::{
    Digest32, Ed25519PublicKey, Ed25519Signature, Sha256Stream, SignatureDomain, verify_canonical,
};

/// Normative document and negotiated-profile digests compiled into the daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseProfiles {
    /// Raw architecture document SHA-256.
    pub architecture_document: [u8; 32],
    /// Appendix-B base federation profile SHA-256.
    pub base_profile: [u8; 32],
    /// Raw companion document SHA-256.
    pub encrypted_document: [u8; 32],
    /// Negotiated companion profile SHA-256.
    pub encrypted_profile: [u8; 32],
}

/// Compiled identities, independent of any untrusted runtime configuration.
pub const RELEASE_PROFILES: ReleaseProfiles = ReleaseProfiles {
    architecture_document: agenc_ircd_federation_wire::ARCHITECTURE_DOCUMENT_SHA256,
    base_profile: agenc_ircd_federation_wire::BASE_FEDERATION_PROFILE_SHA256,
    encrypted_document: agenc_ircd_federation_wire::E2EE_DOCUMENT_SHA256,
    encrypted_profile: agenc_ircd_federation_wire::E2EE_PROFILE_SHA256,
};

/// The largest executable the inspection hashes, matching the release builder.
pub const MAX_INSPECTED_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const SIGNATURE_BYTES: usize = 64;
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// Identity of the executable asking whether a decision covers it.
#[derive(Clone, Copy)]
pub struct CompiledIdentity<'a> {
    /// The source commit compiled into the executable, or `unknown`.
    pub source_commit: &'a str,
    /// The Rust target the executable was compiled for.
    pub target: &'a str,
    /// The executable to hash, normally `/proc/self/exe`.
    pub executable: &'a Path,
}

/// Why a verified decision grants this executable no claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseExclusion {
    /// The decision names another source commit.
    SourceCommit,
    /// The decision does not cover the compiled target.
    Target,
    /// The decision's artifact digest for this target differs from the executable.
    ArtifactDigest,
}

impl ReleaseExclusion {
    /// The fixed label reported in metadata output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SourceCommit => "signed release decision names another source commit",
            Self::Target => "signed release decision does not cover this target",
            Self::ArtifactDigest => {
                "signed release decision artifact digest differs from this executable"
            }
        }
    }
}

/// The claims and identity a covering decision grants.
#[derive(Clone, Eq, PartialEq)]
pub struct ReleaseGrant {
    /// Granted claims in canonical order.
    pub claims: Vec<ReleaseClaim>,
    /// SHA-256 of the candidate record the decision closed.
    pub candidate_sha256: [u8; 32],
    /// The UTC decision time.
    pub decided_at: String,
    /// SHA-256 of the PEM trust anchor that signed the decision.
    pub public_key_sha256: [u8; 32],
    /// Every target the decision covers.
    pub targets: Vec<String>,
}

/// The outcome of inspecting a verified decision against one executable.
#[derive(Clone, Eq, PartialEq)]
pub enum ReleaseCoverage {
    /// The decision covers this executable.
    Covered(ReleaseGrant),
    /// The decision verified but does not describe this executable.
    Excluded(ReleaseExclusion),
}

/// Closed reasons a decision could not be inspected at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseInspectionError {
    /// The trust anchor was not a PEM Ed25519 public key.
    TrustAnchorRejected,
    /// The decision names a different trust anchor than the one supplied.
    TrustAnchorMismatch,
    /// `release.json` could not be read within its bound.
    DecisionUnreadable,
    /// `release.sig` was absent or not exactly one raw Ed25519 signature.
    SignatureUnreadable,
    /// The signature does not verify under the supplied trust anchor.
    SignatureRejected,
    /// The signed document is not a valid decision.
    DocumentRejected(ReleaseDecisionError),
    /// The executable could not be hashed within its bound.
    ExecutableUnreadable,
}

impl ReleaseInspectionError {
    /// The fixed operator-facing label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TrustAnchorRejected => "trusted public key is not a PEM Ed25519 public key",
            Self::TrustAnchorMismatch => "release decision was signed by another public key",
            Self::DecisionUnreadable => "release.json is missing or exceeds its size limit",
            Self::SignatureUnreadable => "release.sig is missing or is not one raw signature",
            Self::SignatureRejected => "release decision signature does not verify",
            Self::DocumentRejected(ReleaseDecisionError::TooLarge) => {
                "release decision exceeds its size limit"
            }
            Self::DocumentRejected(ReleaseDecisionError::InvalidJson) => {
                "release decision is not canonical JSON"
            }
            Self::DocumentRejected(ReleaseDecisionError::InvalidSchema) => {
                "release decision does not match the decision schema"
            }
            Self::DocumentRejected(ReleaseDecisionError::InvalidPublicKey) => {
                "release decision trust anchor is invalid"
            }
            Self::ExecutableUnreadable => "this executable could not be hashed",
        }
    }
}

impl fmt::Display for ReleaseInspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

impl std::error::Error for ReleaseInspectionError {}

/// Verifies `directory/release.json` under the PEM trust anchor and reports
/// whether it covers the identified executable.
pub fn inspect_release_decision(
    directory: &Path,
    trusted_key_pem: &[u8],
    identity: CompiledIdentity<'_>,
) -> Result<ReleaseCoverage, ReleaseInspectionError> {
    if trusted_key_pem.len() > MAX_RELEASE_PUBLIC_KEY_BYTES {
        return Err(ReleaseInspectionError::TrustAnchorRejected);
    }
    let key_bytes = parse_release_public_key_pem(trusted_key_pem)
        .map_err(|_| ReleaseInspectionError::TrustAnchorRejected)?;
    let key = Ed25519PublicKey::from_bytes(key_bytes)
        .map_err(|_| ReleaseInspectionError::TrustAnchorRejected)?;
    let document_bytes = read_bounded(&directory.join("release.json"), MAX_RELEASE_DECISION_BYTES)
        .ok_or(ReleaseInspectionError::DecisionUnreadable)?;
    let signature_bytes = read_bounded(&directory.join("release.sig"), SIGNATURE_BYTES)
        .ok_or(ReleaseInspectionError::SignatureUnreadable)?;
    let signature: [u8; SIGNATURE_BYTES] = signature_bytes
        .try_into()
        .map_err(|_| ReleaseInspectionError::SignatureUnreadable)?;
    verify_canonical(
        key,
        SignatureDomain::ReleaseDecision,
        &document_bytes,
        Ed25519Signature::from_bytes(signature),
    )
    .map_err(|_| ReleaseInspectionError::SignatureRejected)?;
    let document = ReleaseDecisionDocument::parse(&document_bytes)
        .map_err(ReleaseInspectionError::DocumentRejected)?;
    let mut anchor = Sha256Stream::new();
    anchor.update(trusted_key_pem);
    if *anchor.finish().as_bytes() != document.public_key_sha256 {
        return Err(ReleaseInspectionError::TrustAnchorMismatch);
    }
    coverage(&document, identity)
}

fn coverage(
    document: &ReleaseDecisionDocument,
    identity: CompiledIdentity<'_>,
) -> Result<ReleaseCoverage, ReleaseInspectionError> {
    if hexadecimal(&document.source_commit) != identity.source_commit {
        return Ok(ReleaseCoverage::Excluded(ReleaseExclusion::SourceCommit));
    }
    let Some(expected) = document.artifact_digest(identity.target) else {
        return Ok(ReleaseCoverage::Excluded(ReleaseExclusion::Target));
    };
    let actual = digest_file(identity.executable, MAX_INSPECTED_EXECUTABLE_BYTES)
        .ok_or(ReleaseInspectionError::ExecutableUnreadable)?;
    if actual.as_bytes() != expected {
        return Ok(ReleaseCoverage::Excluded(ReleaseExclusion::ArtifactDigest));
    }
    Ok(ReleaseCoverage::Covered(ReleaseGrant {
        claims: document.claims.clone(),
        candidate_sha256: document.candidate_sha256,
        decided_at: document.decided_at.clone(),
        public_key_sha256: document.public_key_sha256,
        targets: document.targets.clone(),
    }))
}

/// Reads a regular file of at most `maximum` bytes, or nothing.
fn read_bounded(path: &Path, maximum: usize) -> Option<Vec<u8>> {
    let file = File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let limit = u64::try_from(maximum).ok()?.checked_add(1)?;
    let mut bytes = Vec::new();
    bytes.try_reserve(maximum).ok()?;
    file.take(limit).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= maximum).then_some(bytes)
}

/// Hashes a regular file of at most `maximum` bytes in fixed chunks.
fn digest_file(path: &Path, maximum: u64) -> Option<Digest32> {
    let file = File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut reader = file.take(maximum.checked_add(1)?);
    let mut hasher = Sha256Stream::new();
    let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
    let mut total: u64 = 0;
    loop {
        let read = reader.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        total = total.checked_add(u64::try_from(read).ok()?)?;
        if total > maximum {
            return None;
        }
        hasher.update(chunk.get(..read)?);
    }
    Some(hasher.finish())
}

/// Lowercase hexadecimal of any byte string.
#[must_use]
pub fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use agenc_ircd_config::{ReleaseClaim, ReleaseDecisionError};
    use agenc_ircd_crypto::{Ed25519SecretKey, SignatureDomain, sign_canonical};

    use super::{
        CompiledIdentity, ReleaseCoverage, ReleaseExclusion, ReleaseInspectionError,
        inspect_release_decision,
    };
    use crate::test_support::TestDirectory;

    type TestResult = Result<(), Box<dyn core::error::Error>>;

    /// The seed behind `test-data/release-decision/release-public.pem`.
    const FIXTURE_SEED: [u8; 32] = *b"agenc-ircd release decision seed";
    const FIXTURE_COMMIT: &str = "ffffffffffffffffffffffffffffffffffffffff";
    const FIXTURE_TARGET: &str = "x86_64-unknown-linux-gnu";
    const FIXTURE_EXECUTABLE: &[u8] = b"agenc-ircd release decision fixture executable\n";

    fn fixture_directory() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-data/release-decision")
    }

    fn fixture_pem() -> Result<Vec<u8>, std::io::Error> {
        fs::read(fixture_directory().join("release-public.pem"))
    }

    fn identity<'a>(
        commit: &'a str,
        target: &'a str,
        executable: &'a Path,
    ) -> CompiledIdentity<'a> {
        CompiledIdentity {
            source_commit: commit,
            target,
            executable,
        }
    }

    #[test]
    fn onboarding_tokens_match_the_compiled_profile_hashes() {
        // The descriptor tokens are literals in the config crate; the negotiated
        // profile hashes are generated in federation-wire. A profile revision
        // must move both, which Stage 09 missed for the base profile (CLM-1).
        let profiles = super::RELEASE_PROFILES;
        assert_eq!(
            agenc_ircd_config::encode_base64url_32(&profiles.base_profile),
            agenc_ircd_config::BASE_PROFILE_SHA256_TOKEN
        );
        assert_eq!(
            agenc_ircd_config::encode_base64url_32(&profiles.encrypted_profile),
            agenc_ircd_config::E2EE_PROFILE_SHA256_TOKEN
        );
    }

    #[test]
    fn python_signed_fixture_verifies_and_covers_its_executable() -> TestResult {
        let scratch = TestDirectory::create()?;
        let executable = scratch.0.join("executable");
        fs::write(&executable, FIXTURE_EXECUTABLE)?;
        let pem = fixture_pem()?;
        let covered = inspect_release_decision(
            &fixture_directory(),
            &pem,
            identity(FIXTURE_COMMIT, FIXTURE_TARGET, &executable),
        )?;
        let ReleaseCoverage::Covered(grant) = covered else {
            return Err("fixture decision did not cover the fixture executable".into());
        };
        assert_eq!(
            grant.claims,
            vec![
                ReleaseClaim::CoreV1,
                ReleaseClaim::FederatedV1,
                ReleaseClaim::Wss
            ]
        );
        assert_eq!(grant.targets, vec![FIXTURE_TARGET.to_owned()]);
        assert_eq!(grant.decided_at, "2026-09-05T12:00:00Z");

        let seed_key = Ed25519SecretKey::from_bytes(FIXTURE_SEED);
        let pem_key = agenc_ircd_config::parse_release_public_key_pem(&pem)?;
        assert_eq!(seed_key.public_key().as_bytes(), &pem_key);
        Ok(())
    }

    #[test]
    fn verified_decision_excludes_other_commits_targets_and_binaries() -> TestResult {
        let scratch = TestDirectory::create()?;
        let executable = scratch.0.join("executable");
        fs::write(&executable, FIXTURE_EXECUTABLE)?;
        let other = scratch.0.join("other");
        fs::write(&other, b"another executable\n")?;
        let pem = fixture_pem()?;
        let cases = [
            (
                identity("unknown", FIXTURE_TARGET, &executable),
                ReleaseExclusion::SourceCommit,
            ),
            (
                identity(FIXTURE_COMMIT, "aarch64-unknown-linux-gnu", &executable),
                ReleaseExclusion::Target,
            ),
            (
                identity(FIXTURE_COMMIT, FIXTURE_TARGET, &other),
                ReleaseExclusion::ArtifactDigest,
            ),
        ];
        for (identity, expected) in cases {
            let coverage = inspect_release_decision(&fixture_directory(), &pem, identity)?;
            assert!(coverage == ReleaseCoverage::Excluded(expected));
        }
        let missing = scratch.0.join("absent");
        assert_eq!(
            inspect_release_decision(
                &fixture_directory(),
                &pem,
                identity(FIXTURE_COMMIT, FIXTURE_TARGET, &missing)
            )
            .err(),
            Some(ReleaseInspectionError::ExecutableUnreadable)
        );
        Ok(())
    }

    #[test]
    fn untrusted_keys_tampered_bytes_and_foreign_anchors_are_refused() -> TestResult {
        let scratch = TestDirectory::create()?;
        let executable = scratch.0.join("executable");
        fs::write(&executable, FIXTURE_EXECUTABLE)?;
        let fixture = fixture_directory();
        let pem = fixture_pem()?;
        let untrusted = fs::read(fixture.join("untrusted-public.pem"))?;
        let who = identity(FIXTURE_COMMIT, FIXTURE_TARGET, &executable);
        assert_eq!(
            inspect_release_decision(&fixture, &untrusted, who).err(),
            Some(ReleaseInspectionError::SignatureRejected)
        );
        assert_eq!(
            inspect_release_decision(&fixture, b"not a key", who).err(),
            Some(ReleaseInspectionError::TrustAnchorRejected)
        );

        let copy = scratch.0.join("decision");
        fs::create_dir(&copy)?;
        let document = fs::read(fixture.join("release.json"))?;
        let signature = fs::read(fixture.join("release.sig"))?;
        let tampered = String::from_utf8(document.clone())?.replace("core-v1", "history");
        fs::write(copy.join("release.json"), tampered.as_bytes())?;
        fs::write(copy.join("release.sig"), &signature)?;
        assert_eq!(
            inspect_release_decision(&copy, &pem, who).err(),
            Some(ReleaseInspectionError::SignatureRejected)
        );
        fs::write(copy.join("release.json"), &document)?;
        fs::write(
            copy.join("release.sig"),
            signature.get(..63).unwrap_or_default(),
        )?;
        assert_eq!(
            inspect_release_decision(&copy, &pem, who).err(),
            Some(ReleaseInspectionError::SignatureUnreadable)
        );
        fs::remove_file(copy.join("release.json"))?;
        assert_eq!(
            inspect_release_decision(&copy, &pem, who).err(),
            Some(ReleaseInspectionError::DecisionUnreadable)
        );

        // A document that names another anchor verifies but is not trusted.
        let foreign = String::from_utf8(document.clone())?
            .replace(
                &format!("\"public_key_sha256\":\"{}\"", public_key_field(&document)?),
                &format!("\"public_key_sha256\":\"{}\"", "0".repeat(64)),
            )
            .into_bytes();
        assert!(foreign != document);
        let key = Ed25519SecretKey::from_bytes(FIXTURE_SEED);
        let resigned = sign_canonical(&key, SignatureDomain::ReleaseDecision, &foreign)?;
        fs::write(copy.join("release.json"), &foreign)?;
        fs::write(copy.join("release.sig"), resigned.as_bytes())?;
        assert_eq!(
            inspect_release_decision(&copy, &pem, who).err(),
            Some(ReleaseInspectionError::TrustAnchorMismatch)
        );

        // A well-signed document outside the schema is still rejected.
        let broken = b"{\"schema_version\":1}\n";
        let resigned = sign_canonical(&key, SignatureDomain::ReleaseDecision, broken)?;
        fs::write(copy.join("release.json"), broken)?;
        fs::write(copy.join("release.sig"), resigned.as_bytes())?;
        assert_eq!(
            inspect_release_decision(&copy, &pem, who).err(),
            Some(ReleaseInspectionError::DocumentRejected(
                ReleaseDecisionError::InvalidSchema
            ))
        );
        Ok(())
    }

    fn public_key_field(document: &[u8]) -> Result<String, Box<dyn core::error::Error>> {
        let text = std::str::from_utf8(document)?;
        let start = text
            .find("\"public_key_sha256\":\"")
            .ok_or("fixture lacks its public key digest")?
            .checked_add("\"public_key_sha256\":\"".len())
            .ok_or("offset overflow")?;
        Ok(text
            .get(start..start.checked_add(64).ok_or("offset overflow")?)
            .ok_or("fixture public key digest is truncated")?
            .to_owned())
    }
}
