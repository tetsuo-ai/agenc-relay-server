#![forbid(unsafe_code)]
//! Cross-implementation MLS tests (companion Section 21 gate 3): the same
//! scripted group lifecycle runs through openmls and mls-rs for both
//! enabled suites, and what the daemon sees of their framing is compared:
//! KeyPackage public fields and references, Welcome headers, and
//! PrivateMessage headers. Each library also joins a group the other one
//! created and decrypts a message from it. Every outcome is recorded in
//! `conformance/e2ee-interop-matrix.toml`; the test fails when an observed
//! outcome differs from the recorded one, so a deviation is visible rather
//! than hidden.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::Path;

use agenc_relay_e2ee::DecodeBudget;
use agenc_relay_e2ee::limits::{
    MAX_KEY_PACKAGE_OBJECT, MAX_LIVE_OBJECT, MAX_WELCOME_MAILBOX_OBJECT,
};
use agenc_relay_e2ee::mls_outer::{
    MlsContentType, MlsOuterMessage, parse_mls_message, verify_key_package_signatures,
};
use mls_rs::client_builder::MlsConfig;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential as RsBasicCredential, BasicIdentityProvider};
use mls_rs::mls_rules::{CommitOptions, DefaultMlsRules};
use mls_rs::{CipherSuite as RsSuite, CipherSuiteProvider, Client, CryptoProvider, MlsMessage};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const GROUP_ID: &[u8] = b"interop-group";
const MESSAGE: &[u8] = b"the daemon sees only the header";

/// The suites the profile enables, in both libraries' vocabularies.
fn suites() -> [(u16, Ciphersuite, RsSuite); 2] {
    [
        (
            1,
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            RsSuite::CURVE25519_AES128,
        ),
        (
            3,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            RsSuite::CURVE25519_CHACHA,
        ),
    ]
}

// ---------------------------------------------------------------------------
// openmls party.

struct OpenMlsParty {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    suite: Ciphersuite,
}

impl OpenMlsParty {
    fn new(name: &[u8], suite: Ciphersuite) -> TestResult<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(suite.signature_algorithm())?;
        signer.store(provider.storage())?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self {
            provider,
            signer,
            credential,
            suite,
        })
    }

    fn key_package(&self) -> TestResult<(KeyPackage, Vec<u8>)> {
        let bundle = KeyPackage::builder().build(
            self.suite,
            &self.provider,
            &self.signer,
            self.credential.clone(),
        )?;
        let package = bundle.key_package().clone();
        let bytes = MlsMessageOut::from(package.clone()).to_bytes()?;
        Ok((package, bytes))
    }

    fn create_group(&self) -> TestResult<MlsGroup> {
        Ok(MlsGroup::builder()
            .with_group_id(GroupId::from_slice(GROUP_ID))
            .ciphersuite(self.suite)
            .use_ratchet_tree_extension(true)
            .build(&self.provider, &self.signer, self.credential.clone())?)
    }

    fn import_key_package(&self, bytes: &[u8]) -> TestResult<KeyPackage> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes)?;
        let MlsMessageBodyIn::KeyPackage(package) = message.extract() else {
            return Err("not a key package".into());
        };
        Ok(package.validate(self.provider.crypto(), ProtocolVersion::Mls10)?)
    }

    /// Adds `package`, merges the commit, and returns the welcome bytes.
    fn add(&self, group: &mut MlsGroup, package: KeyPackage) -> TestResult<Vec<u8>> {
        let (_commit, welcome, _info) =
            group.add_members(&self.provider, &self.signer, &[package])?;
        group.merge_pending_commit(&self.provider)?;
        Ok(welcome.to_bytes()?)
    }

    fn join(&self, welcome: &[u8]) -> TestResult<MlsGroup> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err("not a welcome".into());
        };
        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            None,
        )?;
        Ok(staged.into_group(&self.provider)?)
    }

    fn encrypt(&self, group: &mut MlsGroup) -> TestResult<Vec<u8>> {
        Ok(group
            .create_message(&self.provider, &self.signer, MESSAGE)?
            .to_bytes()?)
    }

    fn decrypt(&self, group: &mut MlsGroup, bytes: &[u8]) -> TestResult<Vec<u8>> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes)?;
        let processed =
            group.process_message(&self.provider, message.try_into_protocol_message()?)?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                Ok(application.into_bytes())
            }
            _ => Err("not an application message".into()),
        }
    }

    fn reference(&self, package: &KeyPackage) -> TestResult<Vec<u8>> {
        Ok(package
            .hash_ref(self.provider.crypto())?
            .as_slice()
            .to_vec())
    }
}

// ---------------------------------------------------------------------------
// mls-rs party: the client configuration type is unnameable, so every helper
// is generic over it.

fn rs_client(name: &[u8], suite: RsSuite) -> TestResult<Client<impl MlsConfig>> {
    let crypto = RustCryptoProvider::default();
    let cipher_suite = crypto
        .cipher_suite_provider(suite)
        .ok_or("suite unsupported by mls-rs rust-crypto")?;
    let (secret, public) = cipher_suite.signature_key_generate()?;
    let identity = SigningIdentity::new(
        RsBasicCredential::new(name.to_vec()).into_credential(),
        public,
    );
    let rules = DefaultMlsRules::new()
        .with_commit_options(CommitOptions::new().with_ratchet_tree_extension(true));
    Ok(Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .mls_rules(rules)
        .signing_identity(identity, secret, suite)
        .build())
}

fn rs_key_package<C: MlsConfig>(client: &Client<C>) -> TestResult<Vec<u8>> {
    Ok(client
        .generate_key_package_message(Default::default(), Default::default(), None)?
        .to_bytes()?)
}

fn rs_create_group<C: MlsConfig>(client: &Client<C>) -> TestResult<mls_rs::Group<C>> {
    Ok(client.group_builder()?.build()?)
}

/// Adds the key package message, applies the commit, and returns the
/// welcome bytes.
fn rs_add<C: MlsConfig>(group: &mut mls_rs::Group<C>, package: &[u8]) -> TestResult<Vec<u8>> {
    let output = group
        .commit_builder()
        .add_member(MlsMessage::from_bytes(package)?)?
        .build()?;
    group.apply_pending_commit()?;
    let welcome = output
        .welcome_messages
        .first()
        .ok_or("no welcome message")?;
    Ok(welcome.to_bytes()?)
}

fn rs_join<C: MlsConfig>(client: &Client<C>, welcome: &[u8]) -> TestResult<mls_rs::Group<C>> {
    let (group, _info) = client.join_group(None, &MlsMessage::from_bytes(welcome)?, None)?;
    Ok(group)
}

fn rs_encrypt<C: MlsConfig>(group: &mut mls_rs::Group<C>) -> TestResult<Vec<u8>> {
    Ok(group
        .encrypt_application_message(MESSAGE, Vec::new())?
        .to_bytes()?)
}

fn rs_decrypt<C: MlsConfig>(group: &mut mls_rs::Group<C>, bytes: &[u8]) -> TestResult<Vec<u8>> {
    match group.process_incoming_message(MlsMessage::from_bytes(bytes)?)? {
        mls_rs::group::ReceivedMessage::ApplicationMessage(message) => Ok(message.data().to_vec()),
        _ => Err("not an application message".into()),
    }
}

// ---------------------------------------------------------------------------
// The daemon's view.

fn daemon_key_package(bytes: &[u8], suite: u16) -> TestResult<Vec<u8>> {
    let mut budget = DecodeBudget::new(MAX_KEY_PACKAGE_OBJECT, 1 << 14);
    let MlsOuterMessage::KeyPackage(package) = parse_mls_message(bytes, &mut budget)? else {
        return Err("daemon: not a key package".into());
    };
    if package.cipher_suite != suite {
        return Err("daemon: key package suite differs".into());
    }
    verify_key_package_signatures(&package)?;
    Ok(package.key_package_ref.to_vec())
}

fn daemon_welcome(bytes: &[u8], suite: u16, joiner: &[u8]) -> TestResult {
    let mut budget = DecodeBudget::new(MAX_WELCOME_MAILBOX_OBJECT, 1 << 14);
    let MlsOuterMessage::Welcome(header) = parse_mls_message(bytes, &mut budget)? else {
        return Err("daemon: not a welcome".into());
    };
    if header.cipher_suite != suite {
        return Err("daemon: welcome suite differs".into());
    }
    if !header.new_member_refs.iter().any(|member| member == joiner) {
        return Err("daemon: welcome does not address the joiner".into());
    }
    Ok(())
}

fn daemon_private(bytes: &[u8], group_id: &[u8]) -> TestResult {
    let mut budget = DecodeBudget::new(MAX_LIVE_OBJECT, 1 << 14);
    let MlsOuterMessage::Private(header) = parse_mls_message(bytes, &mut budget)? else {
        return Err("daemon: not a private message".into());
    };
    if header.group_id != group_id {
        return Err("daemon: private message names another group".into());
    }
    if header.content_type != MlsContentType::Application {
        return Err("daemon: private message is not application content".into());
    }
    if header.epoch != 1 {
        return Err(format!("daemon: epoch {} after one add", header.epoch).into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The scripted lifecycle.

/// What one lifecycle run leaves for the daemon to inspect.
struct Lifecycle {
    /// The joiner's KeyPackage as sent on the wire.
    package: Vec<u8>,
    /// The joiner's KeyPackage reference as openmls computes it.
    reference: Vec<u8>,
    /// The Welcome the creator sent.
    welcome: Vec<u8>,
    /// The creator's application message.
    from_creator: Vec<u8>,
    /// The joiner's application message.
    from_joiner: Vec<u8>,
    /// The group identifier both members share.
    group_id: Vec<u8>,
}

struct Observed {
    outcomes: BTreeMap<String, String>,
    notes: Vec<String>,
}

impl Observed {
    fn record(&mut self, id: &str, result: TestResult) {
        match result {
            Ok(()) => {
                self.outcomes.insert(id.to_owned(), "agree".to_owned());
            }
            Err(error) => {
                self.outcomes
                    .insert(id.to_owned(), "deviation-recorded".to_owned());
                self.notes.push(format!("{id}: {error}"));
            }
        }
    }
}

/// openmls creates the group and adds an mls-rs member; both then send.
fn openmls_creates(observed: &mut Observed, suite: u16, open: Ciphersuite, rs: RsSuite) {
    let id = |name: &str| format!("{name}-s{suite}");
    let run = || -> TestResult<Lifecycle> {
        let alice = OpenMlsParty::new(b"alice", open)?;
        let bob = rs_client(b"bob", rs)?;
        let bob_package = rs_key_package(&bob)?;
        let imported = alice.import_key_package(&bob_package)?;
        let bob_reference = alice.reference(&imported)?;
        let mut group = alice.create_group()?;
        let welcome = alice.add(&mut group, imported)?;
        let mut bob_group = rs_join(&bob, &welcome)?;
        let from_alice = alice.encrypt(&mut group)?;
        let heard = rs_decrypt(&mut bob_group, &from_alice)?;
        if heard != MESSAGE {
            return Err("mls-rs decrypted other content".into());
        }
        let from_bob = rs_encrypt(&mut bob_group)?;
        let heard = alice.decrypt(&mut group, &from_bob)?;
        if heard != MESSAGE {
            return Err("openmls decrypted other content".into());
        }
        Ok(Lifecycle {
            package: bob_package,
            reference: bob_reference,
            welcome,
            from_creator: from_alice,
            from_joiner: from_bob,
            group_id: GROUP_ID.to_vec(),
        })
    };
    match run() {
        Err(error) => {
            for name in [
                "kp-mls-rs",
                "welcome-openmls-to-mls-rs",
                "private-openmls",
                "private-mls-rs-in-openmls-group",
            ] {
                observed.record(&id(name), Err(format!("lifecycle: {error}").into()));
            }
        }
        Ok(run) => record_daemon_view(
            observed,
            suite,
            &run,
            [
                &id("kp-mls-rs"),
                &id("welcome-openmls-to-mls-rs"),
                &id("private-openmls"),
                &id("private-mls-rs-in-openmls-group"),
            ],
        ),
    }
}

/// mls-rs creates the group and adds an openmls member; both then send.
fn mls_rs_creates(observed: &mut Observed, suite: u16, open: Ciphersuite, rs: RsSuite) {
    let id = |name: &str| format!("{name}-s{suite}");
    let run = || -> TestResult<Lifecycle> {
        let alice = rs_client(b"alice", rs)?;
        let bob = OpenMlsParty::new(b"bob", open)?;
        let (bob_key_package, bob_package) = bob.key_package()?;
        let bob_reference = bob.reference(&bob_key_package)?;
        let mut group = rs_create_group(&alice)?;
        let group_id = group.group_id().to_vec();
        let welcome = rs_add(&mut group, &bob_package)?;
        let mut bob_group = bob.join(&welcome)?;
        let from_alice = rs_encrypt(&mut group)?;
        let heard = bob.decrypt(&mut bob_group, &from_alice)?;
        if heard != MESSAGE {
            return Err("openmls decrypted other content".into());
        }
        let from_bob = bob.encrypt(&mut bob_group)?;
        let heard = rs_decrypt(&mut group, &from_bob)?;
        if heard != MESSAGE {
            return Err("mls-rs decrypted other content".into());
        }
        Ok(Lifecycle {
            package: bob_package,
            reference: bob_reference,
            welcome,
            from_creator: from_alice,
            from_joiner: from_bob,
            group_id,
        })
    };
    match run() {
        Err(error) => {
            for name in [
                "kp-openmls",
                "welcome-mls-rs-to-openmls",
                "private-mls-rs",
                "private-openmls-in-mls-rs-group",
            ] {
                observed.record(&id(name), Err(format!("lifecycle: {error}").into()));
            }
        }
        Ok(run) => record_daemon_view(
            observed,
            suite,
            &run,
            [
                &id("kp-openmls"),
                &id("welcome-mls-rs-to-openmls"),
                &id("private-mls-rs"),
                &id("private-openmls-in-mls-rs-group"),
            ],
        ),
    }
}

/// Records what the daemon sees of one lifecycle under the four result
/// identifiers: the joiner's KeyPackage and reference, the Welcome, the
/// creator's message, and the joiner's message.
fn record_daemon_view(observed: &mut Observed, suite: u16, run: &Lifecycle, ids: [&str; 4]) {
    let [package_id, welcome_id, creator_id, joiner_id] = ids;
    let reference = daemon_key_package(&run.package, suite).and_then(|reference| {
        if reference == run.reference {
            Ok(reference)
        } else {
            Err("daemon and openmls disagree on the key package reference".into())
        }
    });
    let joiner = reference.as_ref().cloned().unwrap_or_default();
    observed.record(package_id, reference.map(|_| ()));
    observed.record(welcome_id, daemon_welcome(&run.welcome, suite, &joiner));
    observed.record(creator_id, daemon_private(&run.from_creator, &run.group_id));
    observed.record(joiner_id, daemon_private(&run.from_joiner, &run.group_id));
}

fn recorded(root: &Path) -> TestResult<BTreeMap<String, String>> {
    let text = fs::read_to_string(root.join("conformance/e2ee-interop-matrix.toml"))?;
    let mut matrix = BTreeMap::new();
    let mut id: Option<String> = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_owned();
        match key.trim() {
            // Lifecycle rules belong to the daemon's real-client test.
            "id" if value.starts_with("lifecycle-") => id = None,
            "id" => id = Some(value),
            "outcome" => {
                if let Some(id) = id.take() {
                    matrix.insert(id, value);
                }
            }
            _ => {}
        }
    }
    Ok(matrix)
}

#[test]
fn two_independent_mls_libraries_agree_with_the_daemon_view() -> TestResult {
    let mut observed = Observed {
        outcomes: BTreeMap::new(),
        notes: Vec::new(),
    };
    for (suite, open, rs) in suites() {
        openmls_creates(&mut observed, suite, open, rs);
        mls_rs_creates(&mut observed, suite, open, rs);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let recorded = recorded(&root)?;
    assert_eq!(
        observed.outcomes, recorded,
        "the interop matrix must record what the libraries do; notes: {:?}",
        observed.notes
    );
    assert!(
        observed
            .outcomes
            .values()
            .filter(|outcome| *outcome == "agree")
            .count()
            >= 8,
        "at least the framing of both libraries must agree with the daemon"
    );
    Ok(())
}
