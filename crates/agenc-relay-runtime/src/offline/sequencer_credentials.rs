//! `arcd sequencer-credentials create`: the public sequencer credentials
//! document of a new encrypted network (architecture Appendix C.7,
//! companion 9.2), written offline from the coordinator's sequencer key.
//!
//! The document holds key-set generation zero with the single
//! generation-zero credential of one key. It carries no private material;
//! the coordinator keeps the key and every node names the same document in
//! `e2ee.sequencer_credentials_file`.
#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use agenc_relay_config::{SecretLength, ValidationDepth, load_config, open_secret_file};
use agenc_relay_crypto::{Ed25519SecretKey, OsEntropy};
use agenc_relay_e2ee::limits::PROFILE_VERSION;
use agenc_relay_e2ee::objects::conversation::{ArcSequencerCredential, ArcSequencerCredentialTbs};
use agenc_relay_e2ee::sequencer::SequencerCredentialsFile;
use agenc_relay_e2ee::{Opaque, TlsEncode, TlsVec};
use agenc_relay_storage::rename_path_no_replace;
use zeroize::Zeroizing;

use super::{
    OfflineError, require_absent, safe_absolute_path, sync_parent, validate_creation_parent,
};

/// The document is public: readable by every local account, the service
/// account included, and never group- or world-writable, which the
/// daemon's protected read requires (spec 22.2). The staged file is set to
/// exactly this mode, so the caller's umask cannot narrow it.
const PUBLIC_DOCUMENT_MODE: u32 = 0o644;

/// One `arcd sequencer-credentials create` request.
pub struct SequencerCredentialsRequest {
    /// Configuration naming the network the credential belongs to.
    pub config_path: PathBuf,
    /// The sequencer's raw 32-byte Ed25519 seed, read under the
    /// protected-file rules.
    pub sequencer_key_file: PathBuf,
    /// Earliest second the credential is valid.
    pub not_before: u64,
    /// Latest second the credential is valid, after `not_before`.
    pub not_after: u64,
    /// New file to create; an existing path is never replaced.
    pub output: PathBuf,
}

/// The key-set facts of a created document, which the ECAP tuple and every
/// onboarding descriptor of the network carry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequencerCredentialsReceipt {
    /// Key-set generation, zero for a new network.
    pub set_generation: u64,
    /// Key-set hash.
    pub key_set_hash: [u8; 32],
}

/// Creates the generation-zero `e2ee.sequencer_credentials_file` document of
/// the network named by the configuration for the key in the key file: one
/// credential at key generation zero, valid from `not_before` to
/// `not_after`, with the all-zero previous key ID and no continuity
/// signature. The bytes are the shared canonical encoding, checked by the
/// parser and key-set verification startup runs before the file is
/// published under its final name.
pub fn create_sequencer_credentials(
    request: &SequencerCredentialsRequest,
) -> Result<SequencerCredentialsReceipt, OfflineError> {
    if request.not_before >= request.not_after
        || !safe_absolute_path(&request.output)
        || request.output.file_name().is_none()
    {
        return Err(OfflineError::InvalidRequest);
    }
    validate_creation_parent(&request.output, None)?;
    require_absent(&request.output)?;
    let config = load_config(&request.config_path, ValidationDepth::Document)?;
    let network_id = *config.network.network_id.as_bytes();
    let public_key = sequencer_public_key(&request.sequencer_key_file)?;
    let document = generation_zero_document(network_id, public_key, request)?;
    let key_set = SequencerCredentialsFile::parse(&document)
        .and_then(|parsed| parsed.key_set(&network_id))
        .map_err(|_| OfflineError::Cryptography)?;
    publish_public_document(&request.output, &document)?;
    Ok(SequencerCredentialsReceipt {
        set_generation: key_set.set_generation,
        key_set_hash: key_set.digest,
    })
}

/// Reads the raw 32-byte Ed25519 seed under the protected-file rules (spec
/// 22.2) and returns its public key; every copy of the seed is zeroized.
fn sequencer_public_key(key_file: &Path) -> Result<[u8; 32], OfflineError> {
    let (secret, _) = open_secret_file(key_file, SecretLength::Exact(32))?;
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        secret
            .as_slice()
            .try_into()
            .map_err(|_| OfflineError::Configuration)?,
    );
    Ok(*Ed25519SecretKey::from_bytes(*seed).public_key().as_bytes())
}

fn generation_zero_document(
    network_id: [u8; 32],
    sequencer_public_key: [u8; 32],
    request: &SequencerCredentialsRequest,
) -> Result<Vec<u8>, OfflineError> {
    let credential = ArcSequencerCredential {
        tbs: ArcSequencerCredentialTbs {
            profile_version: PROFILE_VERSION,
            network_id,
            key_generation: 0,
            sequencer_public_key,
            not_before: request.not_before,
            not_after: request.not_after,
            previous_key_id: [0; 32],
        },
        continuity_signature: Opaque::new(Vec::new()).map_err(|_| OfflineError::Cryptography)?,
    };
    SequencerCredentialsFile {
        set_generation: 0,
        credentials: TlsVec::new(vec![credential]).map_err(|_| OfflineError::Cryptography)?,
    }
    .encode()
    .map_err(|_| OfflineError::Cryptography)
}

/// Writes the document beside its final name and renames it into place
/// without replacing anything, so no reader ever sees a partial document.
fn publish_public_document(path: &Path, bytes: &[u8]) -> Result<(), OfflineError> {
    let staged = path.with_file_name(staged_name()?);
    let written = write_staged(&staged, bytes)
        .and_then(|()| rename_path_no_replace(&staged, path).map_err(|_| OfflineError::Filesystem));
    if let Err(error) = written {
        let _cleanup = fs::remove_file(&staged);
        return Err(error);
    }
    sync_parent(path)
}

fn write_staged(path: &Path, bytes: &[u8]) -> Result<(), OfflineError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(PUBLIC_DOCUMENT_MODE);
    let mut file = options.open(path).map_err(|_| OfflineError::Filesystem)?;
    // The creation mode passes through the umask: under root's 027 or 077
    // the service account could not open the document it must read.
    file.set_permissions(fs::Permissions::from_mode(PUBLIC_DOCUMENT_MODE))
        .map_err(|_| OfflineError::Filesystem)?;
    file.write_all(bytes)
        .map_err(|_| OfflineError::Filesystem)?;
    file.sync_all().map_err(|_| OfflineError::Filesystem)
}

fn staged_name() -> Result<String, OfflineError> {
    let mut random = [0_u8; 8];
    OsEntropy::fill(&mut random).map_err(|_| OfflineError::Cryptography)?;
    let mut name = String::from(".sequencer-credentials-");
    for byte in random {
        write!(name, "{byte:02x}").map_err(|_| OfflineError::Filesystem)?;
    }
    Ok(name)
}
