#![forbid(unsafe_code)]

//! Bounded adapters for the cryptographic suites fixed by the protocol.
//!
//! This crate owns algorithm selection, domain separation, secret lifetimes,
//! and the blocking-worker boundary. It does not implement cryptographic
//! primitives.

mod account_hpke;
mod entropy;
mod error;
mod hash;
mod secret;
mod signature;
mod storage;
mod storage_integrity;
mod tls_ticket;
mod worker;

pub use account_hpke::{
    ACCOUNT_HPKE_ENCAPSULATED_KEY_BYTES, ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES,
    ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES, ACCOUNT_HPKE_RESPONSE_CIPHERTEXT_BYTES,
    ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES, AccountHpkeKeyId, AccountHpkePrivateKey,
    AccountHpkePublicKey, AccountRequestBinding, AccountResponseOpenToken,
    AccountResponseSealToken, OpenedAccountRequest, OpenedAccountResponse, SealedAccountRequest,
    SealedAccountResponse, open_account_request, seal_account_request,
};
pub use entropy::OsEntropy;
pub use error::{CryptoError, CryptoWorkerError};
pub use hash::{
    Digest32, LoginIndexDigest, LoginIndexKey, LoginIndexKeyId, OpaqueFakeCredentialKey,
    SemanticHashDomain, Sha256Stream, derive_fake_credential_id, derive_login_index,
    semantic_digest,
};
pub use signature::{
    Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, SignatureDomain, sign_canonical,
    verify_canonical,
};
pub use storage::{
    DATABASE_BINDING_BYTES, DatabaseBinding, MAX_STORAGE_CIPHERTEXT_BYTES, MAX_STORAGE_KEY_BYTES,
    MAX_STORAGE_PLAINTEXT_BYTES, OpenedStoragePlaintext, SealedStorageRecord, StorageIndex,
    StorageMasterKey, StorageNonce, StorageRecordKey, StorageTable, derive_storage_index,
    derive_storage_record_key, open_storage_record, seal_storage_record,
};
pub use storage_integrity::{
    BackupStreamHasher, ConstructionPlanHasher, QueryCursorKey, RollbackGuardRootKey,
    StorageAuthenticator, StorageDigest, StorageIntegrityContext, StorageIntegrityKeys,
    TrackedStateHasher, admin_audit_checkpoint_hash, admin_audit_event_hash,
    admin_confirmation_token_hash, audit_signing_key_id, authenticate_nonce_reservation,
    authenticate_query_cursor, authenticate_rollback_guard, authenticate_state_meta,
    backup_signing_key_id, database_header_hash, database_key_check, derive_storage_integrity_keys,
    integrity_checkpoint_hash, integrity_manifest_hash, nonce_reservation_hash,
    rekey_transform_profile_hash, restore_transform_profile_hash, rollback_guard_hash,
    sealed_record_id, storage_migration_profile_hash, storage_operation_id,
    storage_operation_key_id, storage_output_path_hash, storage_qualification_component_hash,
    tracked_record_commitment, tracked_state_digest,
};
pub use tls_ticket::{
    MAX_TLS_TICKET_BYTES, MAX_TLS_TICKET_PLAINTEXT_BYTES, OpenedTlsTicket, TlsTicketKey,
    TlsTicketKeyId, tls_ticket_key_id,
};
pub use worker::{
    BoundedCryptoPool, CRYPTO_QUEUE_SLOTS_PER_WORKER, CRYPTO_WORKER_RESERVED_BYTES, CryptoJob,
    CryptoPoolShutdown, CryptoPort, CryptoSubmissionError, CryptoWorkerConfig,
    JobCancellationToken, JobClass, JobHandle,
};

#[cfg(feature = "wss")]
mod websocket;
#[cfg(feature = "wss")]
pub use websocket::websocket_accept_digest;
