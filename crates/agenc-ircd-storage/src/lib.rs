#![forbid(unsafe_code)]

//! Durable record codecs, bounded transaction ownership, backup, and recovery.

mod backup;
mod bounded;
mod codec;
mod construction;
mod construction_directory;
mod construction_runtime;
mod construction_schema;
mod control;
mod domain_records;
pub mod e2ee_records;
mod engine;
mod error;
mod fault;
pub mod federation_records;
pub mod history_records;
mod initialize;
mod integrity;
mod login_index;
mod mutation;
mod owner;
mod platform;
mod qualification;
mod qualification_workload;
mod records;
mod recovery;
mod redb_store;
mod restore_command;
mod schema;
mod sealed;
mod source_validation;

pub use source_validation::{AuthenticatedSourceRecord, SourceRecordValidator};

pub use backup::{
    BACKUP_FIXED_STREAM_BYTES, BackupHeader, BackupReceipt, BackupRecord, BackupStreamWriter,
    BackupTrailer, BackupTrustKey, MAX_BACKUP_TRUST_KEYS, VerifiedBackup, backup_stream_bytes,
    verify_backup,
};
pub use bounded::{LIVE_DATABASE_REGION_BYTES, guard_replacement_charge};
pub use construction::{
    MAX_CONSTRUCTION_PLAN_BYTES, STORAGE_CONSTRUCTION_KEY, StorageConstruction,
    StorageConstructionAction, StorageConstructionCursor, StorageConstructionKind,
    StorageConstructionPlanEntry, StorageConstructionSource, StorageConstructionSourceKind,
    StorageOperationCompletion, StorageOperationIdentity, construction_plan_hash,
};
pub use construction_directory::{ConstructionDirectory, ConstructionDirectoryPhase};
pub use construction_runtime::{
    BackupConstructionSourceReader, ConstructionCommitReceipt, ConstructionExecutor,
    ConstructionFinalizationCounters, ConstructionLimits, ConstructionPlan,
    ConstructionPlanBuilder, ConstructionPreflight, ConstructionSourceDatabase,
    ConstructionSourceFacts, ConstructionSourceReader, ConstructionSourceRecord,
    ConstructionTarget, ConstructionTargetBatch, ConstructionTargetRecord,
    ConstructionTargetWriter, ConstructionTransformer, DatabaseConstructionSourceReader,
    ExactCopyTransformer, MAX_CONSTRUCTION_BATCH_BYTES, MAX_CONSTRUCTION_BATCH_RECORDS,
    MAX_CONSTRUCTION_SOURCE_BYTES, MAX_CONSTRUCTION_TARGET_BYTES, RecoveryTransformV1,
    RestoreBackupSource, RestoreBackupSourceConfig, VerifiedConstructionOutput,
    recovery_transform_prefix,
};
pub use control::{
    DATABASE_HEADER_BYTES, DatabaseHeader, DatabaseHeaderTbs, NONCE_RESERVATION_BYTES,
    NonceReservationState, NonceReservationTbs, ROLLBACK_GUARD_BYTES, RollbackGuard,
    RollbackGuardPhase, RollbackGuardTbs, STATE_META_BYTES, StateMeta, StateMetaTbs,
    verify_guard_pair,
};
pub use domain_records::{
    AccountRecordBody, ChannelNameRecordBody, ChannelRecordBody, DecodedChannelNameRecord,
    LIVE_RECORD_KIND, MAX_ACCOUNT_RECORD_BODY_BYTES, MAX_CHANNEL_NAME_RECORD_BODY_BYTES,
    MAX_CHANNEL_RECORD_BODY_BYTES, MAX_SANCTION_RECORD_BODY_BYTES, MAX_SESSION_RECORD_BODY_BYTES,
    SanctionRecordBody, SessionRecordBody,
};
pub use engine::{
    CheckpointOutcome, CheckpointReceipt, RecoveredStorageState, StorageEngineLimits,
    StorageInspectionConfig, StorageOpenConfig, StorageRuntimeLimits, StorageStatistics,
    inspect_storage,
};
pub use error::{
    AllowancePhase, FilesystemCause, FilesystemFailure, StorageError, filesystem_rejected,
};
pub use fault::{
    StorageFaultBoundary, StorageFaultCase, StorageFaultInjector, StorageFaultSchedule,
    StorageFaultSite,
};
pub use federation_records::{
    COMPLETION_COVERAGE_KIND, COORDINATOR_RESULT_KIND, CompletionCoverageRecord,
    CoordinatorResultRecord, DeliveryCursorRecord, EDGE_REQUEST_KIND, EdgeRequestPhase,
    EdgeRequestRecord, FederationOriginRecord, FederationPeerRecord, MAX_ACCEPTED_EPOCHS,
    ORIGIN_FLAG_PENDING_DEL, ORIGIN_FLAG_SINK_GONE, ORIGIN_RECORD_KIND, OUTBOX_EVENT_KIND,
    OriginKeyParts, OriginRowStatus, OutboxEventRecord, OutboxKeyParts, PEER_RECORD_KIND,
    PROJECTION_ENTRY_KIND, PROJECTION_MARKER_KIND, PeerPhase, ProjectionEntryRecord,
    ProjectionGenerationState, ProjectionKeyParts, ProjectionMarkerRecord, origin_key, outbox_key,
    outbox_range, parse_origin_key, parse_outbox_key, parse_projection_key, peer_key,
    projection_entry_key, projection_marker_key, projection_range, request_result_key,
};
pub use initialize::{
    InitialStorageRecord, StorageInitializationConfig, StorageInitializationMode,
    StorageInitializationOutcome, initialize_storage,
};
pub use integrity::{
    INTEGRITY_CHECKPOINT_BYTES, IntegrityCheckpoint, IntegrityCheckpointTbs, IntegrityManifest,
    IntegrityManifestTbs, IntegrityRecordMutation, IntegrityRecordVersion,
    MAX_INTEGRITY_PLAINTEXT_BYTES, compute_tracked_state_digest, logical_meta_charge,
    logical_record_charge,
};
pub use login_index::{
    LOGIN_INDEX_KEY_STATE_KEY, LOGIN_INDEX_STORED_KEY_BYTES, LoginIndexKeyState,
    LoginIndexLazyMigration, LoginIndexLookupSchedule, LoginIndexStoredKey,
    LoginIndexTransitionBatch, LoginIndexTransitionPreflight, LoginIndexValue, LoginIndexValueKind,
};
pub use mutation::{
    CommitOutcome, CommitReceipt, ExistingRecord, MAX_RETENTION_DELETIONS,
    MAX_STORAGE_MUTATION_BATCH_BYTES, ReadPlan, ReadRecord, ReadResult, RecordMutation,
    StorageAccountingLimits, StorageMutationBatch, StorageMutationHead,
};
pub use owner::{
    STORAGE_COMPLETION_QUEUE_CAPACITY, STORAGE_REQUEST_QUEUE_CAPACITY,
    STORAGE_SHUTDOWN_THREAD_NAME, StorageCompletion, StorageLimitWriter, StorageOwner, StoragePort,
    StorageShutdown,
};
pub use platform::{
    BackupDestination, BackupDirectoryReader, BackupOutput, FilesystemCapacity, FilesystemTuple,
    InspectionStateDirectory, StateDirectory, StorageQualification, rename_path_no_replace,
};
pub use qualification::{
    MAX_GROWTH_SAMPLES, MAX_QUALIFICATION_CASES, MAX_QUALIFICATION_REPORT_BYTES,
    MAX_QUALIFIED_OBSERVED_GROWTH, PhaseGrowth, QualificationTarget, REQUIRED_QUALIFICATION_CASES,
    StorageGrowthCase, StorageGrowthProbe, StorageGrowthRecorder, StorageGrowthSample,
    StorageQualificationReport, StorageQualificationReportTbs, allocated_directory_bytes,
    embedded_storage_qualifications, phase_growth,
};
pub use qualification_workload::{
    QualificationFailure, QualificationOutcome, QualificationRequest, WORKLOAD_DESCRIPTION,
    qualify_production_storage, required_case_names,
};
pub use records::{
    E2eeRecoveryGate, E2eeRecoveryKind, KEY_CHECK_STORED_KEY, MAX_DOMAIN_RECORD_BODY_BYTES,
    MAX_PROTOCOL_BODY_BYTES, MAX_RECORD_REFERENCES, OPAQUE_FAKE_RECORD_KEY, PersistentRecordValue,
    ProtocolRecordBody, RecordCodecKind, RecordReference, STATE_META_STORED_KEY, StoredKeyShape,
    TableSchema, table_schema, table_schemas, validate_record_plaintext, validate_sealed_record,
};
pub use recovery::{RecoveryDisposition, classify_recovery_state};
pub use restore_command::{
    RestoreCommandReceipt, RestoreCommandRequest, RestoreTrustKey, execute_restore_command,
};
pub use schema::{
    DATABASE_FORMAT, MAX_NONCE_DRAWS, MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH,
    MAX_STORED_KEY_BYTES, MAX_TRACKED_MUTATIONS, MAX_TRANSACTION_PLANS, SCHEMA_GENERATION,
    STORAGE_HANDOFF_SLOT_BYTES, StoredKey, TableId,
};
pub use sealed::{
    MAX_SEALED_RECORD_BYTES, MIN_SEALED_RECORD_BYTES, SealedRecord, StorageSealContext,
};
