//! Closed immediate-successor profiles with disjoint construction rules.
#![forbid(unsafe_code)]

use agenc_ircd_crypto::StorageDigest;

use crate::{StorageConstructionSource, StorageError, TableId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MigrationProfile {
    OneToTwo,
    TwoToThree,
    ThreeToFour,
}

impl MigrationProfile {
    pub(crate) fn select(source: u64, target: u64) -> Result<Self, StorageError> {
        match (source, target) {
            (1, 2) => Ok(Self::OneToTwo),
            (2, 3) => Ok(Self::TwoToThree),
            (3, 4) => Ok(Self::ThreeToFour),
            _ => Err(StorageError::UnsupportedMigration),
        }
    }

    pub(crate) fn hash(self) -> Result<StorageDigest, StorageError> {
        match self {
            Self::OneToTwo => crate::migration::profile_hash(),
            Self::TwoToThree => crate::migration_v2::profile_hash(),
            Self::ThreeToFour => crate::migration_v3::profile_hash(),
        }
    }

    pub(crate) const fn source_generation(self) -> u64 {
        match self {
            Self::OneToTwo => 1,
            Self::TwoToThree => 2,
            Self::ThreeToFour => 3,
        }
    }

    pub(crate) const fn target_generation(self) -> u64 {
        match self {
            Self::OneToTwo => 2,
            Self::TwoToThree => 3,
            Self::ThreeToFour => 4,
        }
    }

    pub(crate) fn copy_rule(self, table: TableId) -> Result<u16, StorageError> {
        let base = match self {
            Self::OneToTwo => return Err(StorageError::UnsupportedMigration),
            Self::TwoToThree => 256,
            Self::ThreeToFour => 512,
        };
        Ok(base + table.as_u16())
    }

    pub(crate) fn validate_copy_source(
        self,
        source: &StorageConstructionSource,
        plaintext: &[u8],
    ) -> Result<(), StorageError> {
        match self {
            Self::OneToTwo => Err(StorageError::UnsupportedMigration),
            Self::TwoToThree => crate::migration_v2::validate_source(
                source.table(),
                source.key(),
                source.record_schema(),
                plaintext,
            ),
            Self::ThreeToFour => crate::migration_v3::validate_source(
                source.table(),
                source.key(),
                source.record_schema(),
                plaintext,
            ),
        }
    }

    pub(crate) fn transformer(self, state_generation: u64) -> MigrationTransformer {
        match self {
            Self::OneToTwo => {
                MigrationTransformer::One(crate::MigrationTransformV1::new(state_generation))
            }
            Self::TwoToThree => MigrationTransformer::Two(crate::MigrationTransformV2),
            Self::ThreeToFour => MigrationTransformer::Three(crate::MigrationTransformV3),
        }
    }
}

pub(crate) enum MigrationTransformer {
    One(crate::MigrationTransformV1),
    Two(crate::MigrationTransformV2),
    Three(crate::MigrationTransformV3),
}

impl crate::ConstructionTransformer for MigrationTransformer {
    fn transform(
        &mut self,
        kind: crate::StorageConstructionKind,
        entry: &crate::StorageConstructionPlanEntry,
        sources: &[crate::ConstructionSourceRecord],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, StorageError> {
        match self {
            Self::One(transformer) => transformer.transform(kind, entry, sources),
            Self::Two(transformer) => transformer.transform(kind, entry, sources),
            Self::Three(transformer) => transformer.transform(kind, entry, sources),
        }
    }
}

pub(crate) fn registered_rule_sources(
    sources: &[StorageConstructionSource],
    target: TableId,
    rule: u16,
) -> bool {
    crate::migration::valid_rule_sources(sources, target, rule)
        || crate::migration_v2::valid_rule_sources(sources, target, rule)
        || crate::migration_v3::valid_rule_sources(sources, target, rule)
}
