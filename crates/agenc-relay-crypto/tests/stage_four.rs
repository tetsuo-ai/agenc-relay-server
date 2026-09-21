#![forbid(unsafe_code)]

//! Adversarial Stage-04 tests for the public cryptographic adapter boundaries.

use std::collections::HashSet;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::Duration;

use agenc_relay_crypto::{
    ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES, ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES,
    AccountHpkePrivateKey, AccountRequestBinding, BoundedCryptoPool, CryptoError, CryptoJob,
    CryptoPort, CryptoWorkerConfig, CryptoWorkerError, DatabaseBinding, Ed25519PublicKey,
    Ed25519SecretKey, Ed25519Signature, JobClass, LoginIndexKey, MAX_STORAGE_CIPHERTEXT_BYTES,
    MAX_STORAGE_PLAINTEXT_BYTES, OpaqueFakeCredentialKey, SealedStorageRecord, SemanticHashDomain,
    SignatureDomain, StorageMasterKey, StorageNonce, StorageTable, derive_fake_credential_id,
    derive_login_index, derive_storage_index, derive_storage_record_key, open_account_request,
    open_storage_record, seal_account_request, seal_storage_record, semantic_digest,
    sign_canonical, verify_canonical,
};
use agenc_relay_types::{
    AccountServiceMessageKind, AccountServiceResponseKind, DatabaseId, NetworkId, NormalizedLogin,
    RecoveryEpoch, RequestId, ServerId, ServerIncarnation,
};

/// Upper bound for an OS worker thread to dequeue a job on a saturated host.
const WORKER_START_BUDGET: Duration = Duration::from_secs(30);

fn database_binding(seed: u8) -> DatabaseBinding {
    DatabaseBinding::new(
        NetworkId::from_bytes([seed; 32]),
        ServerId::from_bytes([seed.wrapping_add(1); 16]),
        ServerIncarnation::from_bytes([seed.wrapping_add(2); 16]),
        DatabaseId::from_bytes([seed.wrapping_add(3); 16]),
    )
}

fn request_binding(
    key_id: agenc_relay_crypto::AccountHpkeKeyId,
    request_kind: AccountServiceMessageKind,
) -> AccountRequestBinding {
    AccountRequestBinding::new(
        NetworkId::from_bytes([1_u8; 32]),
        RecoveryEpoch::from_bytes([2_u8; 16]),
        key_id,
        RequestId::from_bytes([3_u8; 16]),
        request_kind,
    )
}

fn opened_request(
    request_kind: AccountServiceMessageKind,
) -> Result<
    (
        AccountHpkePrivateKey,
        agenc_relay_crypto::AccountResponseOpenToken,
        agenc_relay_crypto::AccountResponseSealToken,
    ),
    CryptoError,
> {
    let private_key = AccountHpkePrivateKey::generate()?;
    let public_key = private_key.public_key()?;
    let binding = request_binding(public_key.key_id(), request_kind);
    let plaintext = [0_u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES];
    let (sealed, open_token) = seal_account_request(public_key, binding, &plaintext)?;
    let (_opened, seal_token) = open_account_request(
        &private_key,
        binding,
        sealed.encapsulated_key(),
        sealed.ciphertext(),
    )?;
    Ok((private_key, open_token, seal_token))
}

#[test]
fn hpke_rejects_every_public_binding_and_ciphertext_substitution()
-> Result<(), Box<dyn core::error::Error>> {
    let private_key = AccountHpkePrivateKey::generate()?;
    let public_key = private_key.public_key()?;
    let binding = request_binding(
        public_key.key_id(),
        AccountServiceMessageKind::OpaqueAuthStart,
    );
    let plaintext = [7_u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES];
    let wrong_binding = AccountRequestBinding::new(
        binding.network_id(),
        RecoveryEpoch::from_bytes([9_u8; 16]),
        agenc_relay_crypto::AccountHpkeKeyId::from_bytes([8_u8; 32]),
        binding.client_request_id(),
        binding.message_kind(),
    );
    assert_eq!(
        seal_account_request(public_key, wrong_binding, &plaintext).err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let (sealed, _unused_token) = seal_account_request(public_key, binding, &plaintext)?;
    let wrong_private_key = AccountHpkePrivateKey::generate()?;
    assert_eq!(
        open_account_request(
            &wrong_private_key,
            binding,
            sealed.encapsulated_key(),
            sealed.ciphertext(),
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let changed_epoch = AccountRequestBinding::new(
        binding.network_id(),
        RecoveryEpoch::from_bytes([10_u8; 16]),
        binding.recipient_key_id(),
        binding.client_request_id(),
        binding.message_kind(),
    );
    assert_eq!(
        open_account_request(
            &private_key,
            changed_epoch,
            sealed.encapsulated_key(),
            sealed.ciphertext(),
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let changed_kind = AccountRequestBinding::new(
        binding.network_id(),
        RecoveryEpoch::from_bytes([2_u8; 16]),
        binding.recipient_key_id(),
        binding.client_request_id(),
        AccountServiceMessageKind::AccountCreateStart,
    );
    assert_eq!(
        open_account_request(
            &private_key,
            changed_kind,
            sealed.encapsulated_key(),
            sealed.ciphertext(),
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let mut changed_encapsulation = *sealed.encapsulated_key();
    let first = changed_encapsulation
        .first_mut()
        .ok_or("encapsulated key is empty")?;
    *first ^= 1;
    assert_eq!(
        open_account_request(
            &private_key,
            binding,
            &changed_encapsulation,
            sealed.ciphertext(),
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let mut changed_ciphertext = *sealed.ciphertext();
    let last = changed_ciphertext
        .last_mut()
        .ok_or("request ciphertext is empty")?;
    *last ^= 1;
    assert_eq!(
        open_account_request(
            &private_key,
            binding,
            sealed.encapsulated_key(),
            &changed_ciphertext,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );

    let response_plaintext = [11_u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES];
    let (_private, _open, seal) = opened_request(AccountServiceMessageKind::OpaqueAuthStart)?;
    assert_eq!(
        seal.seal_response(
            0,
            AccountServiceResponseKind::AccountCreateChallenge,
            &response_plaintext,
        )
        .err(),
        Some(CryptoError::KindMismatch)
    );
    let (_private, _open, seal) = opened_request(AccountServiceMessageKind::OpaqueAuthStart)?;
    assert_eq!(
        seal.seal_response(
            u64::MAX,
            AccountServiceResponseKind::OpaqueAuthChallenge,
            &response_plaintext,
        )
        .err(),
        Some(CryptoError::Overflow)
    );
    let (_private, open, seal) = opened_request(AccountServiceMessageKind::OpaqueAuthStart)?;
    let sealed_response = seal.seal_response(
        4,
        AccountServiceResponseKind::OpaqueAuthChallenge,
        &response_plaintext,
    )?;
    assert_eq!(sealed_response.next_response_count(), 5);
    assert_eq!(
        open.open_response(
            AccountServiceResponseKind::AccountCreateChallenge,
            sealed_response.response_salt(),
            sealed_response.ciphertext(),
        )
        .err(),
        Some(CryptoError::KindMismatch)
    );
    let (_private, open, seal) = opened_request(AccountServiceMessageKind::OpaqueAuthStart)?;
    let sealed_response = seal.seal_response(
        0,
        AccountServiceResponseKind::OpaqueAuthChallenge,
        &response_plaintext,
    )?;
    let mut changed_salt = *sealed_response.response_salt();
    let salt_byte = changed_salt.first_mut().ok_or("response salt is empty")?;
    *salt_byte ^= 1;
    assert_eq!(
        open.open_response(
            sealed_response.response_kind(),
            &changed_salt,
            sealed_response.ciphertext(),
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let (_private, open, seal) = opened_request(AccountServiceMessageKind::OpaqueAuthStart)?;
    let sealed_response = seal.seal_response(
        0,
        AccountServiceResponseKind::OpaqueAuthChallenge,
        &response_plaintext,
    )?;
    let mut changed_response = *sealed_response.ciphertext();
    let response_byte = changed_response
        .last_mut()
        .ok_or("response ciphertext is empty")?;
    *response_byte ^= 1;
    assert_eq!(
        open.open_response(
            sealed_response.response_kind(),
            sealed_response.response_salt(),
            &changed_response,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    Ok(())
}

#[test]
fn storage_adapter_rejects_all_key_nonce_aad_tag_and_limit_changes()
-> Result<(), Box<dyn core::error::Error>> {
    assert_eq!(StorageTable::new(27), Err(CryptoError::InvalidEncoding));
    let table = StorageTable::new(3)?;
    let master = StorageMasterKey::from_bytes([7_u8; 32]);
    let binding = database_binding(1);
    assert_eq!(
        derive_storage_record_key(&master, binding, table, 0).err(),
        Some(CryptoError::InvalidEncoding)
    );
    assert_eq!(
        derive_storage_index(&master, binding, table, 0, b"key").err(),
        Some(CryptoError::InvalidEncoding)
    );
    assert_eq!(
        derive_storage_index(&master, binding, table, 1, &vec![0_u8; 4_097]).err(),
        Some(CryptoError::LimitExceeded)
    );
    assert_eq!(
        SealedStorageRecord::from_bytes(vec![0_u8; 15]).err(),
        Some(CryptoError::InvalidEncoding)
    );
    let index = derive_storage_index(&master, binding, table, 1, b"semantic")?;
    let changed_index = derive_storage_index(&master, binding, table, 1, b"semantic-2")?;
    assert_ne!(
        index.expose_for_storage_key(),
        changed_index.expose_for_storage_key()
    );
    let key = derive_storage_record_key(&master, binding, table, 1)?;
    let nonce_bytes = [9_u8; 24];
    let sealed = seal_storage_record(
        &key,
        StorageNonce::from_reserved_bytes(nonce_bytes),
        1,
        b"record-key",
        b"secret value",
    )?;
    assert_eq!(
        seal_storage_record(
            &key,
            StorageNonce::from_reserved_bytes(nonce_bytes),
            0,
            b"record-key",
            b"secret value",
        )
        .err(),
        Some(CryptoError::InvalidEncoding)
    );
    assert_eq!(
        seal_storage_record(
            &key,
            StorageNonce::from_reserved_bytes(nonce_bytes),
            1,
            &vec![0_u8; 4_097],
            b"secret value",
        )
        .err(),
        Some(CryptoError::InvalidEncoding)
    );
    let nonce = StorageNonce::from_reserved_bytes(nonce_bytes);
    let opened = open_storage_record(&key, &nonce, 1, b"record-key", &sealed)?;
    assert_eq!(opened.expose_for_storage_codec(), b"secret value");
    assert_eq!(
        open_storage_record(&key, &nonce, 2, b"record-key", &sealed).err(),
        Some(CryptoError::AuthenticationFailed)
    );
    assert_eq!(
        open_storage_record(&key, &nonce, 1, b"different-key", &sealed).err(),
        Some(CryptoError::AuthenticationFailed)
    );
    assert_eq!(
        open_storage_record(
            &key,
            &StorageNonce::from_reserved_bytes([8_u8; 24]),
            1,
            b"record-key",
            &sealed,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let wrong_key =
        derive_storage_record_key(&StorageMasterKey::from_bytes([6_u8; 32]), binding, table, 1)?;
    assert_eq!(
        open_storage_record(&wrong_key, &nonce, 1, b"record-key", &sealed).err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let mut tampered = sealed.as_bytes().to_vec();
    let tag_byte = tampered.last_mut().ok_or("storage ciphertext is empty")?;
    *tag_byte ^= 1;
    let tampered = SealedStorageRecord::from_bytes(tampered)?;
    assert_eq!(
        open_storage_record(&key, &nonce, 1, b"record-key", &tampered).err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let truncated_bytes = sealed
        .as_bytes()
        .get(..16)
        .ok_or("storage ciphertext is shorter than its tag")?;
    let truncated = SealedStorageRecord::from_bytes(truncated_bytes.to_vec())?;
    assert_eq!(
        open_storage_record(&key, &nonce, 1, b"record-key", &truncated).err(),
        Some(CryptoError::AuthenticationFailed)
    );
    Ok(())
}

#[test]
fn storage_ciphertext_rejects_the_maximum_plus_one() {
    assert_eq!(
        SealedStorageRecord::from_bytes(vec![0_u8; MAX_STORAGE_CIPHERTEXT_BYTES + 1]).err(),
        Some(CryptoError::InvalidEncoding)
    );
}

#[test]
fn storage_adapter_accepts_the_exact_maximum_plaintext_and_ciphertext()
-> Result<(), Box<dyn core::error::Error>> {
    assert!(SealedStorageRecord::from_bytes(vec![0_u8; MAX_STORAGE_CIPHERTEXT_BYTES]).is_ok());
    let table = StorageTable::new(3)?;
    let master = StorageMasterKey::from_bytes([7_u8; 32]);
    let key = derive_storage_record_key(&master, database_binding(1), table, 1)?;
    let plaintext = vec![0x5a_u8; MAX_STORAGE_PLAINTEXT_BYTES];
    let sealed = seal_storage_record(
        &key,
        StorageNonce::from_reserved_bytes([9_u8; 24]),
        1,
        b"record-key",
        &plaintext,
    )?;
    assert_eq!(sealed.as_bytes().len(), MAX_STORAGE_CIPHERTEXT_BYTES);
    let opened = open_storage_record(
        &key,
        &StorageNonce::from_reserved_bytes([9_u8; 24]),
        1,
        b"record-key",
        &sealed,
    )?;
    assert_eq!(opened.expose_for_storage_codec(), plaintext.as_slice());
    Ok(())
}

#[test]
fn hash_and_signature_registries_are_domain_separated_and_strict()
-> Result<(), Box<dyn core::error::Error>> {
    let domains = [
        SemanticHashDomain::RootFingerprint,
        SemanticHashDomain::AccountId,
        SemanticHashDomain::EnrollmentId,
        SemanticHashDomain::DeviceCertificateId,
        SemanticHashDomain::RosterId,
        SemanticHashDomain::CapabilityId,
        SemanticHashDomain::LeafSignatureKey,
        SemanticHashDomain::LeafCapabilities,
        SemanticHashDomain::SafetyNumber,
        SemanticHashDomain::Conversation,
        SemanticHashDomain::ChannelRoute,
        SemanticHashDomain::DirectRoute,
        SemanticHashDomain::PolicyId,
        SemanticHashDomain::BindingId,
        SemanticHashDomain::RootBindingLockId,
        SemanticHashDomain::SemanticRouteLock,
        SemanticHashDomain::SequencerKey,
        SemanticHashDomain::SequencerKeySet,
        SemanticHashDomain::InitialMemberPlanId,
        SemanticHashDomain::KeyPackagePlanId,
        SemanticHashDomain::ContextCoreId,
        SemanticHashDomain::ContextHash,
        SemanticHashDomain::CloseIntentId,
        SemanticHashDomain::CloseAuthorizationId,
        SemanticHashDomain::CommitAuthorizationId,
        SemanticHashDomain::GroupGenesisId,
        SemanticHashDomain::CandidateId,
        SemanticHashDomain::GroupContextDigest,
        SemanticHashDomain::RatchetTreeDigest,
        SemanticHashDomain::GroupInfoDigest,
        SemanticHashDomain::OldCredentialHash,
        SemanticHashDomain::ResultingLeafCredential,
        SemanticHashDomain::FinalizationId,
        SemanticHashDomain::AbortId,
        SemanticHashDomain::ReinitTarget,
        SemanticHashDomain::ReinitInitialCommit,
        SemanticHashDomain::ReinitAttemptAuthorizationId,
        SemanticHashDomain::ReinitAttemptId,
        SemanticHashDomain::ReinitActivationId,
        SemanticHashDomain::ReinitAbortId,
        SemanticHashDomain::FederationOriginState,
        SemanticHashDomain::CanonicalChannelName,
        SemanticHashDomain::FederationSnapshot,
        SemanticHashDomain::AcknowledgementSet,
        SemanticHashDomain::ReinitAcknowledgementSet,
    ];
    let mut digests = HashSet::new();
    for domain in domains {
        assert!(digests.insert(semantic_digest(domain, b"same canonical object")?));
    }
    let login = NormalizedLogin::prepare("alice")?;
    let login_digest = derive_login_index(
        &LoginIndexKey::from_bytes([1_u8; 32]),
        NetworkId::from_bytes([2_u8; 32]),
        &login,
    )?;
    let other_network = derive_login_index(
        &LoginIndexKey::from_bytes([1_u8; 32]),
        NetworkId::from_bytes([3_u8; 32]),
        &login,
    )?;
    let fake = derive_fake_credential_id(
        &OpaqueFakeCredentialKey::from_bytes([1_u8; 32]),
        NetworkId::from_bytes([2_u8; 32]),
        &login,
    )?;
    assert_ne!(
        login_digest.expose_for_storage_key(),
        other_network.expose_for_storage_key()
    );
    assert_ne!(
        login_digest.expose_for_storage_key(),
        fake.expose_for_account_service()
    );

    let key = Ed25519SecretKey::from_bytes([11_u8; 32]);
    let direct = sign_canonical(&key, SignatureDomain::AccountCreationInvite, b"canonical")?;
    verify_canonical(
        key.public_key(),
        SignatureDomain::AccountCreationInvite,
        b"canonical",
        direct,
    )?;
    let irc = sign_canonical(&key, SignatureDomain::PolicyApproval, b"canonical")?;
    verify_canonical(
        key.public_key(),
        SignatureDomain::PolicyApproval,
        b"canonical",
        irc,
    )?;
    assert_eq!(
        verify_canonical(
            key.public_key(),
            SignatureDomain::ConversationBinding,
            b"canonical",
            irc,
        ),
        Err(CryptoError::AuthenticationFailed)
    );
    assert_eq!(
        verify_canonical(
            key.public_key(),
            SignatureDomain::PolicyApproval,
            b"changed",
            irc,
        ),
        Err(CryptoError::AuthenticationFailed)
    );
    let mut changed_signature = *irc.as_bytes();
    let signature_byte = changed_signature.last_mut().ok_or("signature is empty")?;
    *signature_byte ^= 1;
    assert_eq!(
        verify_canonical(
            key.public_key(),
            SignatureDomain::PolicyApproval,
            b"canonical",
            Ed25519Signature::from_bytes(changed_signature),
        ),
        Err(CryptoError::AuthenticationFailed)
    );
    let invalid_key = (0_u8..=u8::MAX)
        .find_map(|byte| Ed25519PublicKey::from_bytes([byte; 32]).err())
        .ok_or("finite invalid-key corpus unexpectedly contained only curve points")?;
    assert_eq!(invalid_key, CryptoError::InvalidEncoding);
    assert_eq!(
        sign_canonical(
            &key,
            SignatureDomain::PolicyApproval,
            &vec![0_u8; 16_777_216],
        )
        .err(),
        Some(CryptoError::LimitExceeded)
    );
    Ok(())
}

struct BlockingJob {
    class: JobClass,
    started: SyncSender<()>,
    release: Receiver<()>,
}

struct PanickingJob {
    actual: u8,
    expected: u8,
}

impl CryptoJob for PanickingJob {
    type Output = u8;

    fn class(&self) -> JobClass {
        JobClass::Opaque
    }

    fn execute(self) -> Self::Output {
        assert_eq!(
            self.actual, self.expected,
            "intentional Stage-04 worker containment probe"
        );
        self.actual
    }
}

impl CryptoJob for BlockingJob {
    type Output = u8;

    fn class(&self) -> JobClass {
        self.class
    }

    fn execute(self) -> Self::Output {
        let _started = self.started.send(());
        let _released = self.release.recv();
        7
    }
}

#[tokio::test]
async fn worker_configuration_and_both_admission_classes_are_closed()
-> Result<(), Box<dyn core::error::Error>> {
    for invalid in [
        (0, 1, 1),
        (65, 1, 1),
        (1, 0, 1),
        (1, 129, 1),
        (1, 1, 0),
        (1, 1, 129),
        (1, 1, 3),
    ] {
        assert_eq!(
            CryptoWorkerConfig::new(invalid.0, invalid.1, invalid.2),
            Err(CryptoWorkerError::InvalidConfiguration)
        );
    }
    let default = CryptoWorkerConfig::default();
    assert_eq!(default.reserved_memory_bytes()?, 4 * 75_497_472);
    let pool = BoundedCryptoPool::start(CryptoWorkerConfig::new(1, 1, 1)?)?;
    let (started_sender, started_receiver) = sync_channel(1);
    let (release_sender, release_receiver) = sync_channel(1);
    let first = pool
        .try_submit(BlockingJob {
            class: JobClass::Channel,
            started: started_sender,
            release: release_receiver,
        })
        .map_err(|error| error.reason())?;
    started_receiver.recv_timeout(WORKER_START_BUDGET)?;
    let (rejected_started, _unused_started) = sync_channel(1);
    let (_unused_release, rejected_release) = sync_channel(1);
    let rejected = pool
        .try_submit(BlockingJob {
            class: JobClass::Channel,
            started: rejected_started,
            release: rejected_release,
        })
        .err()
        .ok_or("channel class should be full")?;
    assert_eq!(rejected.reason(), CryptoWorkerError::QueueFull);
    assert_eq!(rejected.into_job().class, JobClass::Channel);
    release_sender.send(())?;
    assert_eq!(first.completion().await?, 7);

    let (started_sender, started_receiver) = sync_channel(1);
    let (release_sender, release_receiver) = sync_channel(1);
    let opaque = pool
        .try_submit(BlockingJob {
            class: JobClass::Opaque,
            started: started_sender,
            release: release_receiver,
        })
        .map_err(|error| error.reason())?;
    started_receiver.recv_timeout(WORKER_START_BUDGET)?;
    release_sender.send(())?;
    assert_eq!(opaque.completion().await?, 7);
    Ok(())
}

#[tokio::test]
async fn worker_panic_and_queued_cancellation_are_terminal_and_bounded()
-> Result<(), Box<dyn core::error::Error>> {
    let panicking_pool = BoundedCryptoPool::start(CryptoWorkerConfig::new(1, 1, 1)?)?;
    let panicking = panicking_pool
        .try_submit(PanickingJob {
            actual: 0,
            expected: 1,
        })
        .map_err(|error| error.reason())?;
    assert_eq!(
        panicking.completion().await,
        Err(CryptoWorkerError::WorkerPanicked)
    );
    let refused = panicking_pool
        .try_submit(PanickingJob {
            actual: 0,
            expected: 1,
        })
        .err()
        .ok_or("failed crypto pool accepted a second job")?;
    assert_eq!(refused.reason(), CryptoWorkerError::WorkerPanicked);
    let _recovered = refused.into_job();

    let cancellation_pool = BoundedCryptoPool::start(CryptoWorkerConfig::new(2, 1, 1)?)?;
    let (first_started_sender, first_started_receiver) = sync_channel(1);
    let (first_release_sender, first_release_receiver) = sync_channel(1);
    let first = cancellation_pool
        .try_submit(BlockingJob {
            class: JobClass::Channel,
            started: first_started_sender,
            release: first_release_receiver,
        })
        .map_err(|error| error.reason())?;
    first_started_receiver.recv_timeout(WORKER_START_BUDGET)?;
    let (cancelled_started_sender, cancelled_started_receiver) = sync_channel(1);
    let (_cancelled_release_sender, cancelled_release_receiver) = sync_channel(1);
    let cancelled = cancellation_pool
        .try_submit(BlockingJob {
            class: JobClass::Channel,
            started: cancelled_started_sender,
            release: cancelled_release_receiver,
        })
        .map_err(|error| error.reason())?;
    cancelled.cancel_before_start();
    first_release_sender.send(())?;
    assert_eq!(first.completion().await?, 7);
    assert_eq!(
        cancelled.completion().await,
        Err(CryptoWorkerError::CancelledBeforeStart)
    );
    assert!(cancelled_started_receiver.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn dropping_a_queued_handle_requests_prestart_cancellation()
-> Result<(), Box<dyn core::error::Error>> {
    let pool = BoundedCryptoPool::start(CryptoWorkerConfig::new(2, 1, 1)?)?;
    let (first_started_sender, first_started_receiver) = sync_channel(1);
    let (first_release_sender, first_release_receiver) = sync_channel(1);
    let first = pool
        .try_submit(BlockingJob {
            class: JobClass::Channel,
            started: first_started_sender,
            release: first_release_receiver,
        })
        .map_err(|error| error.reason())?;
    first_started_receiver.recv_timeout(WORKER_START_BUDGET)?;

    let (cancelled_started_sender, cancelled_started_receiver) = sync_channel(1);
    let (_cancelled_release_sender, cancelled_release_receiver) = sync_channel(1);
    let cancelled = pool
        .try_submit(BlockingJob {
            class: JobClass::Channel,
            started: cancelled_started_sender,
            release: cancelled_release_receiver,
        })
        .map_err(|error| error.reason())?;
    drop(cancelled);

    first_release_sender.send(())?;
    assert_eq!(first.completion().await?, 7);
    drop(pool);
    assert!(cancelled_started_receiver.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn dropping_a_pending_completion_future_requests_prestart_cancellation()
-> Result<(), Box<dyn core::error::Error>> {
    let pool = BoundedCryptoPool::start(CryptoWorkerConfig::new(2, 1, 1)?)?;
    let (first_started_sender, first_started_receiver) = sync_channel(1);
    let (first_release_sender, first_release_receiver) = sync_channel(1);
    let first = pool
        .try_submit(BlockingJob {
            class: JobClass::Channel,
            started: first_started_sender,
            release: first_release_receiver,
        })
        .map_err(|error| error.reason())?;
    first_started_receiver.recv_timeout(WORKER_START_BUDGET)?;

    let (queued_started_sender, queued_started_receiver) = sync_channel(1);
    let (queued_release_sender, queued_release_receiver) = sync_channel(1);
    let queued = pool
        .try_submit(BlockingJob {
            class: JobClass::Channel,
            started: queued_started_sender,
            release: queued_release_receiver,
        })
        .map_err(|error| error.reason())?;
    let timed_out = tokio::time::timeout(Duration::from_millis(10), queued.completion()).await;
    assert!(
        timed_out.is_err(),
        "queued job finished behind a blocked worker"
    );
    // A regression would start the queued job; releasing it here turns that
    // into a failed assertion below instead of a hung worker join.
    drop(queued_release_sender);

    first_release_sender.send(())?;
    assert_eq!(first.completion().await?, 7);
    drop(pool);
    assert!(queued_started_receiver.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn shutdown_joins_workers_after_in_flight_work_finishes()
-> Result<(), Box<dyn core::error::Error>> {
    let pool = BoundedCryptoPool::start(CryptoWorkerConfig::new(1, 1, 1)?)?;
    let (started_sender, started_receiver) = sync_channel(1);
    let (release_sender, release_receiver) = sync_channel(1);
    let job = pool
        .try_submit(BlockingJob {
            class: JobClass::Channel,
            started: started_sender,
            release: release_receiver,
        })
        .map_err(|error| error.reason())?;
    started_receiver.recv_timeout(WORKER_START_BUDGET)?;
    let shutdown = tokio::task::spawn_blocking(move || pool.shutdown());
    release_sender.send(())?;
    assert_eq!(job.completion().await?, 7);
    shutdown.await?;
    Ok(())
}
