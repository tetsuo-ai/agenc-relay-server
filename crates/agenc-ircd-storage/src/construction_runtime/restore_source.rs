//! A usable restore source requires the exact closed generation's admission.
#![forbid(unsafe_code)]

use std::io::{Read, Seek, SeekFrom};

use agenc_ircd_crypto::{DatabaseBinding, LoginIndexKey, RollbackGuardRootKey, StorageMasterKey};

use super::RestoreBackupSource;
use crate::{BackupTrustKey, SourceRecordValidator, StorageError, VerifiedBackup};

/// Independent key roles and bounds for one signed restore source.
pub struct RestoreBackupSourceConfig<'a> {
    /// Master key that opens the original sealed records.
    pub source_master_key: StorageMasterKey,
    /// Root key that authenticates the source rollback guard.
    pub source_guard_root: RollbackGuardRootKey,
    /// Configured current login-index key.
    pub login_index_key: LoginIndexKey,
    /// Configured previous login-index key during a transition.
    pub previous_login_index_key: Option<LoginIndexKey>,
    /// Offline-authorized backup signing keys.
    pub trusted_keys: &'a [BackupTrustKey],
    /// Inclusive complete signed-stream byte ceiling.
    pub maximum_bytes: u64,
}

pub(crate) enum RestoreSourceAdmission<'a> {
    Current,
    WithLegacy(&'a mut dyn SourceRecordValidator),
}

impl RestoreSourceAdmission<'_> {
    fn admit<R: Read + Seek>(
        self,
        input: &mut R,
        config: &RestoreBackupSourceConfig<'_>,
        verified: VerifiedBackup,
    ) -> Result<VerifiedBackup, StorageError> {
        match (
            verified.header.source_header().tbs().schema_generation,
            self,
        ) {
            (3 | 4, _) => Ok(verified),
            (2, Self::WithLegacy(validator)) => crate::backup::admit_verified_legacy_backup(
                input,
                verified,
                &config.source_master_key,
                &config.source_guard_root,
                config.trusted_keys,
                config.maximum_bytes,
                validator,
            ),
            _ => Err(StorageError::UnsupportedMigration),
        }
    }
}

impl<R: Read + Seek> RestoreBackupSource<R> {
    /// Requires complete semantic admission for a legacy schema-two backup.
    /// Schema-three and schema-four backups retain their original restore profile.
    pub fn open_with_legacy_validation(
        input: R,
        config: RestoreBackupSourceConfig<'_>,
        validator: &mut dyn SourceRecordValidator,
    ) -> Result<Self, StorageError> {
        Self::open_admitted(input, config, RestoreSourceAdmission::WithLegacy(validator))
    }

    pub(crate) fn open_admitted(
        mut input: R,
        config: RestoreBackupSourceConfig<'_>,
        admission: RestoreSourceAdmission<'_>,
    ) -> Result<Self, StorageError> {
        input
            .seek(SeekFrom::Start(0))
            .map_err(|_| StorageError::FilesystemRejected)?;
        let verified = crate::verify_backup(
            &mut input,
            &config.source_master_key,
            &config.source_guard_root,
            config.trusted_keys,
            config.maximum_bytes,
        )?;
        let verified = admission.admit(&mut input, &config, verified)?;
        let source = verified.header.source_header();
        let binding = DatabaseBinding::new(
            source.tbs().network_id,
            source.tbs().server_id,
            source.tbs().server_incarnation,
            source.tbs().database_instance_id,
        );
        Ok(Self {
            input,
            source_master_key: config.source_master_key,
            login_index_key: config.login_index_key,
            previous_login_index_key: config.previous_login_index_key,
            binding,
            verified,
        })
    }
}
