#![forbid(unsafe_code)]
//! Reading the independent ReInit vectors under `test-data/vectors/e2ee/reinit`
//! (written by `scripts/generate-e2ee-vectors.py`, never by this crate) and
//! opening the conversation they describe at its pinned genesis.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use agenc_relay_e2ee::history::{ChainLimits, ChainStep, HistoricalChain, RecordReferences};
use agenc_relay_e2ee::initial_authority::{
    ExpectedInitialAuthority, InitialAuthorityEvidence, InitialPrincipalEvidence,
    authenticate_initial_authority,
};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind, ObjectId};
use agenc_relay_e2ee::objects::reinit::ArcReInitAttempt;
use agenc_relay_e2ee::objects::sequencing::{ArcFinalizationProof, ArcSequencerRecord};
use agenc_relay_e2ee::reinit_target::{ReinitProposal, ReinitTarget, reconstruct_reinit_target};
use agenc_relay_e2ee::route::{PrincipalRosters, VerifiedBinding};
use agenc_relay_e2ee::{DecodeBudget, E2eeError, TlsDecode};

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

pub(crate) fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test-data/vectors/e2ee/reinit")
}

pub(crate) fn budget() -> DecodeBudget {
    DecodeBudget::new(64 << 20, 1 << 18)
}

fn manifest_text() -> TestResult<String> {
    Ok(fs::read_to_string(directory().join("manifest.toml"))?)
}

fn value_of(block: &str, key: &str) -> TestResult<String> {
    let prefix = format!("{key} = ");
    let line = block
        .lines()
        .find(|line| line.starts_with(&prefix))
        .ok_or_else(|| format!("missing manifest key {key}"))?;
    Ok(line
        .trim_start_matches(&prefix)
        .trim_matches('"')
        .to_owned())
}

/// The value of `key` in the manifest entry for `file`.
pub(crate) fn entry(file: &str, key: &str) -> TestResult<String> {
    let text = manifest_text()?;
    let marker = format!("file = \"{file}\"");
    let block = text
        .split("[[vectors]]")
        .find(|block| block.lines().any(|line| line == marker))
        .ok_or_else(|| format!("missing manifest entry {file}"))?;
    value_of(block, key)
}

/// One manifest value outside every entry.
pub(crate) fn global(key: &str) -> TestResult<String> {
    let text = manifest_text()?;
    let header = text.split("[[vectors]]").next().unwrap_or_default();
    value_of(header, key)
}

pub(crate) fn hex(text: &str) -> TestResult<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|index| {
            let pair = text.get(index..index + 2).ok_or("odd hex length")?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect()
}

pub(crate) fn hex32(text: &str) -> TestResult<[u8; 32]> {
    Ok(hex(text)?.as_slice().try_into()?)
}

/// A 32-byte manifest value of `file`.
pub(crate) fn id(file: &str, key: &str) -> TestResult<[u8; 32]> {
    hex32(&entry(file, key)?)
}

/// The bytes of `name`, after checking their length and SHA-256 against the
/// manifest.
pub(crate) fn read(name: &str) -> TestResult<Vec<u8>> {
    let bytes = fs::read(directory().join(name))?;
    if bytes.len().to_string() != entry(name, "encoded_length")?
        || ObjectId::compute(&bytes).as_bytes() != &hex32(&entry(name, "sha256")?)?
    {
        return Err(format!("{name} differs from its manifest entry").into());
    }
    Ok(bytes)
}

pub(crate) fn network() -> TestResult<[u8; 32]> {
    hex32(&global("network_id")?)
}

pub(crate) fn old_conversation() -> TestResult<[u8; 32]> {
    hex32(&global("old_conversation_id")?)
}

/// The conversation opened at its independently pinned genesis binding.
pub(crate) fn genesis_chain() -> TestResult<HistoricalChain> {
    let expected = ExpectedInitialAuthority {
        network_id: network()?,
        conversation_id: old_conversation()?,
        binding_id: hex32(&global("genesis_binding_id")?)?,
    };
    let objects = [
        read("root-c.bin")?,
        read("roster-c.bin")?,
        read("root-d.bin")?,
        read("roster-d.bin")?,
    ];
    let [root_c, roster_c, root_d, roster_d] = &objects;
    let principals = [
        InitialPrincipalEvidence {
            root_object: root_c,
            roster_object: roster_c,
        },
        InitialPrincipalEvidence {
            root_object: root_d,
            roster_object: roster_d,
        },
    ];
    let authority = authenticate_initial_authority(
        &expected,
        &InitialAuthorityEvidence {
            binding_object: &read("genesis-binding.bin")?,
            context_core: &read("genesis-context-core.bin")?,
            initial_policy_object: &read("policy-bootstrap.bin")?,
            sequencer_credential: &read("sequencer-credential.bin")?,
            principals: &principals,
        },
        &mut budget(),
    )?;
    Ok(HistoricalChain::open(
        &expected.network_id,
        &expected.conversation_id,
        &authority,
        ChainLimits::DEFAULT,
    )?)
}

/// Adopts one record file that carries no reference.
pub(crate) fn advance(chain: &mut HistoricalChain, file: &str) -> TestResult<ChainStep> {
    Ok(chain.advance(&read(file)?, &RecordReferences::default(), &mut budget())?)
}

/// Adopts one attempt receipt file with its attempt object file.
pub(crate) fn advance_attempt(
    chain: &mut HistoricalChain,
    receipt: &str,
    attempt: &str,
) -> TestResult<ChainStep> {
    let attempt = read(attempt)?;
    Ok(chain.advance(
        &read(receipt)?,
        &RecordReferences {
            attempt_object: Some(&attempt),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?)
}

/// The chain after its genesis bootstrap activation installed the
/// operational policy.
pub(crate) fn activated_chain() -> TestResult<HistoricalChain> {
    let mut chain = genesis_chain()?;
    advance(&mut chain, "record-00-bootstrap-candidate.bin")?;
    let policy = read("policy-operational.bin")?;
    chain.advance(
        &read("record-01-bootstrap-finalization.bin")?,
        &RecordReferences {
            policy_object: Some(&policy),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    Ok(chain)
}

/// The group ID, suite and encoded extension list of one successor suite.
pub(crate) struct Proposal {
    pub(crate) group_id: Vec<u8>,
    pub(crate) suite: u16,
    pub(crate) extensions: Vec<u8>,
}

impl Proposal {
    pub(crate) fn of(suite: u16) -> TestResult<Self> {
        let file = format!("suite-{suite:04x}-extensions.bin");
        Ok(Self {
            group_id: hex(&entry(&file, "group_id")?)?,
            suite: entry(&file, "cipher_suite")?.parse()?,
            extensions: read(&file)?,
        })
    }

    pub(crate) fn fields(&self) -> ReinitProposal<'_> {
        ReinitProposal {
            group_id: &self.group_id,
            version: 1,
            cipher_suite: self.suite,
            encoded_extensions: &self.extensions,
        }
    }

    pub(crate) fn reconstruct(&self) -> TestResult<ReinitTarget> {
        Ok(reconstruct(&self.fields())??)
    }
}

/// The old conversation's current binding and its principals' rosters when
/// the ReInit is prepared: the pinned genesis binding, which no finalization
/// in the vectors replaces.
pub(crate) fn old_authority() -> TestResult<(VerifiedBinding, PrincipalRosters)> {
    let chain = genesis_chain()?;
    Ok((chain.binding().clone(), chain.principals().clone()))
}

/// Reconstructs a target from `fields` for the old conversation, under its
/// current binding and rosters.
pub(crate) fn reconstruct(
    fields: &ReinitProposal<'_>,
) -> TestResult<Result<ReinitTarget, E2eeError>> {
    let (binding, rosters) = old_authority()?;
    Ok(reconstruct_reinit_target(
        &network()?,
        &binding,
        &rosters,
        fields,
        &mut budget(),
    ))
}

/// One complete sequencer record file, decoded.
pub(crate) fn record(file: &str) -> TestResult<ArcSequencerRecord> {
    let mut budget = budget();
    let object = ArcWireObject::decode_kind(
        &read(file)?,
        Some(ArcWireObjectKind::SequencerRecord),
        &mut budget,
    )?;
    Ok(ArcSequencerRecord::decode_exact(
        object.body(),
        &mut budget,
    )?)
}

/// The proof of one finalization record file.
pub(crate) fn finalization_proof(file: &str) -> TestResult<ArcFinalizationProof> {
    match record(file)? {
        ArcSequencerRecord::Finalization(certificate) => Ok(certificate.tbs.request.proof),
        _ => Err(format!("{file} is not a finalization record").into()),
    }
}

/// One `reinit_attempt` object file, decoded.
pub(crate) fn attempt(file: &str) -> TestResult<ArcReInitAttempt> {
    let mut budget = budget();
    let object = ArcWireObject::decode_kind(
        &read(file)?,
        Some(ArcWireObjectKind::ReinitAttempt),
        &mut budget,
    )?;
    Ok(ArcReInitAttempt::decode_exact(object.body(), &mut budget)?)
}
