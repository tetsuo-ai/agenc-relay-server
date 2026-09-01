//! Closed administrative permission registry.
//!
//! Architecture Appendix C.7 fixes exactly nine permission names and forbids a
//! wildcard, so the registry is a closed enum and a set is a bounded bit set
//! that can never hold an unnamed member.

use std::fmt;

use crate::ValidationError;

/// One administrative permission from the closed registry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdminPermission {
    /// Read-only statistics, health, and session listing.
    Observe,
    /// Configuration reload and inspection.
    Configure,
    /// Client session management.
    Sessions,
    /// Account suspension and related account controls.
    Accounts,
    /// Channel moderation controls.
    Channels,
    /// Federation peer management.
    Federation,
    /// Backup creation.
    Backup,
    /// Audit export.
    Audit,
    /// Process control such as DIE and RESTART.
    Process,
}

impl AdminPermission {
    /// Every permission in registry order.
    pub const ALL: [Self; 9] = [
        Self::Observe,
        Self::Configure,
        Self::Sessions,
        Self::Accounts,
        Self::Channels,
        Self::Federation,
        Self::Backup,
        Self::Audit,
        Self::Process,
    ];

    /// Parses exactly one lowercase registry name.
    pub fn parse(text: &str) -> Result<Self, ValidationError> {
        match text {
            "observe" => Ok(Self::Observe),
            "configure" => Ok(Self::Configure),
            "sessions" => Ok(Self::Sessions),
            "accounts" => Ok(Self::Accounts),
            "channels" => Ok(Self::Channels),
            "federation" => Ok(Self::Federation),
            "backup" => Ok(Self::Backup),
            "audit" => Ok(Self::Audit),
            "process" => Ok(Self::Process),
            _ => Err(ValidationError::InvalidCharacter),
        }
    }

    /// Returns the exact registry name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Configure => "configure",
            Self::Sessions => "sessions",
            Self::Accounts => "accounts",
            Self::Channels => "channels",
            Self::Federation => "federation",
            Self::Backup => "backup",
            Self::Audit => "audit",
            Self::Process => "process",
        }
    }

    const fn bit(self) -> u16 {
        match self {
            Self::Observe => 1,
            Self::Configure => 1 << 1,
            Self::Sessions => 1 << 2,
            Self::Accounts => 1 << 3,
            Self::Channels => 1 << 4,
            Self::Federation => 1 << 5,
            Self::Backup => 1 << 6,
            Self::Audit => 1 << 7,
            Self::Process => 1 << 8,
        }
    }
}

impl fmt::Display for AdminPermission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A bounded set of registry permissions.
///
/// The private bit field can only be populated through registry members, so
/// the set never represents a wildcard or an unnamed permission.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct AdminPermissionSet(u16);

impl AdminPermissionSet {
    /// The empty set.
    pub const EMPTY: Self = Self(0);

    /// Adds one permission and reports whether it was newly inserted.
    pub fn insert(&mut self, permission: AdminPermission) -> bool {
        let bit = permission.bit();
        let inserted = self.0 & bit == 0;
        self.0 |= bit;
        inserted
    }

    /// Reports whether the permission is a member.
    #[must_use]
    pub const fn contains(self, permission: AdminPermission) -> bool {
        self.0 & permission.bit() != 0
    }

    /// Reports whether no permission is a member.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns the member count.
    #[must_use]
    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Iterates the members in registry order.
    pub fn iter(self) -> impl Iterator<Item = AdminPermission> {
        AdminPermission::ALL
            .into_iter()
            .filter(move |permission| self.contains(*permission))
    }

    /// Builds a nonempty set from registry names, refusing unknown or repeated names.
    pub fn from_names<'a>(
        names: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ValidationError> {
        let mut set = Self::EMPTY;
        for name in names {
            let permission = AdminPermission::parse(name)?;
            if !set.insert(permission) {
                return Err(ValidationError::NonCanonical);
            }
        }
        if set.is_empty() {
            return Err(ValidationError::Empty);
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::{AdminPermission, AdminPermissionSet};
    use crate::ValidationError;

    #[test]
    fn registry_names_round_trip_in_order() -> Result<(), ValidationError> {
        let expected = [
            "observe",
            "configure",
            "sessions",
            "accounts",
            "channels",
            "federation",
            "backup",
            "audit",
            "process",
        ];
        for (permission, name) in AdminPermission::ALL.into_iter().zip(expected) {
            assert_eq!(permission.as_str(), name);
            assert_eq!(permission.to_string(), name);
            assert_eq!(AdminPermission::parse(name)?, permission);
        }
        for rejected in ["*", "", "Observe", "observe ", "admin"] {
            assert_eq!(
                AdminPermission::parse(rejected),
                Err(ValidationError::InvalidCharacter)
            );
        }
        Ok(())
    }

    #[test]
    fn sets_are_bounded_deduplicated_and_ordered() -> Result<(), ValidationError> {
        let mut set = AdminPermissionSet::EMPTY;
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert!(set.insert(AdminPermission::Process));
        assert!(!set.insert(AdminPermission::Process));
        assert!(set.insert(AdminPermission::Observe));
        assert!(set.contains(AdminPermission::Observe));
        assert!(!set.contains(AdminPermission::Audit));
        assert_eq!(set.len(), 2);
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            vec![AdminPermission::Observe, AdminPermission::Process]
        );

        let full =
            AdminPermissionSet::from_names(AdminPermission::ALL.map(AdminPermission::as_str))?;
        assert_eq!(full.len(), 9);
        assert_eq!(
            full.iter().collect::<Vec<_>>(),
            AdminPermission::ALL.to_vec()
        );
        assert_eq!(
            AdminPermissionSet::from_names(["observe", "observe"]),
            Err(ValidationError::NonCanonical)
        );
        assert_eq!(
            AdminPermissionSet::from_names(["observe", "*"]),
            Err(ValidationError::InvalidCharacter)
        );
        assert_eq!(
            AdminPermissionSet::from_names([]),
            Err(ValidationError::Empty)
        );
        assert_eq!(AdminPermissionSet::default(), AdminPermissionSet::EMPTY);
        Ok(())
    }
}
