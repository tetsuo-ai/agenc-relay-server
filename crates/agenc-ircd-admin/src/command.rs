//! The closed Section 22.5 administrative command registry.

use agenc_ircd_types::{
    AccountId, AdminPermission, BoundedUtf8, ChannelInstanceId, ControlPolicy, ServerId, UserId,
    ValidationError,
};

use crate::canonical::{CanonicalCommand, parse_canonical_u64};
use crate::{AdminError, StatsSelector};

/// A reason is 1..512 prepared UTF-8 bytes (spec 4462-4463).
pub const MIN_ADMIN_REASON_BYTES: usize = 1;
/// A reason is 1..512 prepared UTF-8 bytes (spec 4462-4463).
pub const MAX_ADMIN_REASON_BYTES: usize = 512;
/// PING/PONG payload reflection is bounded to 64 bytes (spec 800-801).
pub const MAX_PING_TOKEN_BYTES: usize = 64;
/// Suspension seconds are canonical decimal 1..31,536,000 (spec 4459-4460).
pub const MAX_SUSPENSION_SECONDS: u64 = 31_536_000;
/// Suspensions longer than 30 days need the two-step confirmation
/// (spec 4575-4576).
pub const UNCONFIRMED_SUSPENSION_MAX_SECONDS: u64 = 2_592_000;

/// A validated operator reason.
pub type Reason = BoundedUtf8<MIN_ADMIN_REASON_BYTES, MAX_ADMIN_REASON_BYTES>;
/// A bounded liveness token.
pub type PingToken = BoundedUtf8<1, MAX_PING_TOKEN_BYTES>;

/// Canonical decimal suspension length in seconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuspensionSeconds(u64);

impl SuspensionSeconds {
    /// Parses a canonical decimal in `1..=31_536_000`.
    pub fn parse(text: &str) -> Result<Self, AdminError> {
        let value = parse_canonical_u64(text.as_bytes()).map_err(|_| AdminError::Argument)?;
        if value == 0 || value > MAX_SUSPENSION_SECONDS {
            return Err(AdminError::Argument);
        }
        Ok(Self(value))
    }

    /// Returns the seconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Whether the suspension exceeds thirty days (spec 4575-4576).
    #[must_use]
    pub const fn needs_confirmation(self) -> bool {
        self.0 > UNCONFIRMED_SUSPENSION_MAX_SECONDS
    }
}

/// An inclusive audit sequence range with `from <= to` (spec 4460).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditRange {
    from: u64,
    to: u64,
}

impl AuditRange {
    /// Builds a range, rejecting `from > to`.
    pub const fn new(from: u64, to: u64) -> Result<Self, AdminError> {
        if from > to {
            return Err(AdminError::Argument);
        }
        Ok(Self { from, to })
    }

    /// Parses two canonical decimals.
    pub fn parse(from: &str, to: &str) -> Result<Self, AdminError> {
        let from = parse_canonical_u64(from.as_bytes()).map_err(|_| AdminError::Argument)?;
        let to = parse_canonical_u64(to.as_bytes()).map_err(|_| AdminError::Argument)?;
        Self::new(from, to)
    }

    /// Returns the inclusive lower bound.
    #[must_use]
    pub const fn from(self) -> u64 {
        self.from
    }

    /// Returns the inclusive upper bound.
    #[must_use]
    pub const fn to(self) -> u64 {
        self.to
    }

    /// Whether `sequence` lies inside the range.
    #[must_use]
    pub const fn contains(self, sequence: u64) -> bool {
        sequence >= self.from && sequence <= self.to
    }
}

/// One parsed command from the closed registry (spec 4437-4456).
///
/// Reasons and tokens are operator input, so the type deliberately has no
/// `Debug` (Architecture 25.2 forbids input-bearing aggregates in logs).
#[derive(Eq, PartialEq)]
pub enum AdminCommand {
    /// Signed liveness probe carrying a bounded token.
    Ping(PingToken),
    /// Signed liveness answer carrying a bounded token.
    Pong(PingToken),
    /// Signed session close.
    Quit,
    /// Read-only server text.
    Motd,
    /// Read-only software version.
    Version,
    /// Read-only coarse server time.
    Time,
    /// Read-only server information.
    Info,
    /// Read-only link summary.
    Links,
    /// `STATS <selector>` (observe).
    Stats(StatsSelector),
    /// `REHASH :reason` (configure).
    Rehash(Reason),
    /// `KILL <UserId> :reason` (sessions).
    Kill {
        /// The exact live session to terminate.
        user: UserId,
        /// Operator reason.
        reason: Reason,
    },
    /// `ACCOUNT SUSPEND <AccountId> <seconds> :reason` (accounts).
    AccountSuspend {
        /// The account to suspend.
        account: AccountId,
        /// Suspension length.
        seconds: SuspensionSeconds,
        /// Operator reason.
        reason: Reason,
    },
    /// `ACCOUNT RESTORE <AccountId> :reason` (accounts).
    AccountRestore {
        /// The account to restore.
        account: AccountId,
        /// Operator reason.
        reason: Reason,
    },
    /// `CHANNEL QUARANTINE <ChannelInstanceId> :reason` (channels).
    ChannelQuarantine {
        /// The channel instance to quarantine.
        channel: ChannelInstanceId,
        /// Operator reason.
        reason: Reason,
    },
    /// `CHANNEL HISTORY PURGE <ChannelInstanceId> :reason` (channels, confirmed).
    ChannelHistoryPurge {
        /// The exact channel instance whose retained plaintext is deleted.
        channel: ChannelInstanceId,
        /// Operator reason.
        reason: Reason,
    },
    /// `CONNECT <ServerId> :reason` (federation).
    Connect {
        /// The configured peer.
        server: ServerId,
        /// Operator reason.
        reason: Reason,
    },
    /// `SQUIT <ServerId> :reason` (federation).
    Squit {
        /// The configured peer.
        server: ServerId,
        /// Operator reason.
        reason: Reason,
    },
    /// `PEER QUARANTINE <ServerId> :reason` (federation, confirmed).
    PeerQuarantine {
        /// The configured peer.
        server: ServerId,
        /// Operator reason.
        reason: Reason,
    },
    /// `BACKUP CREATE :reason` (backup).
    BackupCreate(Reason),
    /// `AUDIT EXPORT <from> <to>` (audit).
    AuditExport(AuditRange),
    /// `RESTART :reason` (process, confirmed).
    Restart(Reason),
    /// `DIE :reason` (process, confirmed).
    Die(Reason),
}

impl AdminCommand {
    /// Parses one canonical line into the current command registry.
    pub fn parse(command: CanonicalCommand<'_>) -> Result<Self, AdminError> {
        let parameters = command.parameters();
        match (command.verb(), parameters.as_slice()) {
            ("PING", [token]) => Ok(Self::Ping(ping_token(token)?)),
            ("PONG", [token]) => Ok(Self::Pong(ping_token(token)?)),
            ("QUIT", []) => Ok(Self::Quit),
            ("MOTD", []) => Ok(Self::Motd),
            ("VERSION", []) => Ok(Self::Version),
            ("TIME", []) => Ok(Self::Time),
            ("INFO", []) => Ok(Self::Info),
            ("LINKS", []) => Ok(Self::Links),
            ("STATS", [selector]) => StatsSelector::parse(selector).map(Self::Stats),
            ("REHASH", [reason]) => reason_text(reason).map(Self::Rehash),
            ("KILL", [user, reason]) => Ok(Self::Kill {
                user: UserId::parse(user).map_err(map_validation)?,
                reason: reason_text(reason)?,
            }),
            ("ACCOUNT", rest) => Self::parse_account(rest),
            ("CHANNEL", ["QUARANTINE", channel, reason]) => Ok(Self::ChannelQuarantine {
                channel: ChannelInstanceId::parse(channel).map_err(map_validation)?,
                reason: reason_text(reason)?,
            }),
            ("CHANNEL", ["HISTORY", "PURGE", channel, reason]) => Ok(Self::ChannelHistoryPurge {
                channel: ChannelInstanceId::parse(channel).map_err(map_validation)?,
                reason: reason_text(reason)?,
            }),
            ("CONNECT", [server, reason]) => Ok(Self::Connect {
                server: ServerId::parse(server).map_err(map_validation)?,
                reason: reason_text(reason)?,
            }),
            ("SQUIT", [server, reason]) => Ok(Self::Squit {
                server: ServerId::parse(server).map_err(map_validation)?,
                reason: reason_text(reason)?,
            }),
            ("PEER", ["QUARANTINE", server, reason]) => Ok(Self::PeerQuarantine {
                server: ServerId::parse(server).map_err(map_validation)?,
                reason: reason_text(reason)?,
            }),
            ("BACKUP", ["CREATE", reason]) => reason_text(reason).map(Self::BackupCreate),
            ("AUDIT", ["EXPORT", from, to]) => AuditRange::parse(from, to).map(Self::AuditExport),
            ("RESTART", [reason]) => reason_text(reason).map(Self::Restart),
            ("DIE", [reason]) => reason_text(reason).map(Self::Die),
            _ => Err(AdminError::Command),
        }
    }

    fn parse_account(parameters: &[&str]) -> Result<Self, AdminError> {
        match parameters {
            ["SUSPEND", account, seconds, reason] => Ok(Self::AccountSuspend {
                account: AccountId::parse(account).map_err(map_validation)?,
                seconds: SuspensionSeconds::parse(seconds)?,
                reason: reason_text(reason)?,
            }),
            ["RESTORE", account, reason] => Ok(Self::AccountRestore {
                account: AccountId::parse(account).map_err(map_validation)?,
                reason: reason_text(reason)?,
            }),
            _ => Err(AdminError::Command),
        }
    }

    /// Returns the command verb used in FAIL and NOTE replies.
    #[must_use]
    pub const fn verb(&self) -> &'static str {
        match self {
            Self::Ping(_) => "PING",
            Self::Pong(_) => "PONG",
            Self::Quit => "QUIT",
            Self::Motd => "MOTD",
            Self::Version => "VERSION",
            Self::Time => "TIME",
            Self::Info => "INFO",
            Self::Links => "LINKS",
            Self::Stats(_) => "STATS",
            Self::Rehash(_) => "REHASH",
            Self::Kill { .. } => "KILL",
            Self::AccountSuspend { .. } | Self::AccountRestore { .. } => "ACCOUNT",
            Self::ChannelQuarantine { .. } | Self::ChannelHistoryPurge { .. } => "CHANNEL",
            Self::Connect { .. } => "CONNECT",
            Self::Squit { .. } => "SQUIT",
            Self::PeerQuarantine { .. } => "PEER",
            Self::BackupCreate(_) => "BACKUP",
            Self::AuditExport(_) => "AUDIT",
            Self::Restart(_) => "RESTART",
            Self::Die(_) => "DIE",
        }
    }

    /// Returns the permission the 22.5 table requires, or none for the
    /// signed liveness and read-only informational commands.
    #[must_use]
    pub const fn required_permission(&self) -> Option<AdminPermission> {
        match self {
            Self::Ping(_)
            | Self::Pong(_)
            | Self::Quit
            | Self::Motd
            | Self::Version
            | Self::Time
            | Self::Info
            | Self::Links => None,
            Self::Stats(_) => Some(AdminPermission::Observe),
            Self::Rehash(_) => Some(AdminPermission::Configure),
            Self::Kill { .. } => Some(AdminPermission::Sessions),
            Self::AccountSuspend { .. } | Self::AccountRestore { .. } => {
                Some(AdminPermission::Accounts)
            }
            Self::ChannelQuarantine { .. } | Self::ChannelHistoryPurge { .. } => {
                Some(AdminPermission::Channels)
            }
            Self::Connect { .. } | Self::Squit { .. } | Self::PeerQuarantine { .. } => {
                Some(AdminPermission::Federation)
            }
            Self::BackupCreate(_) => Some(AdminPermission::Backup),
            Self::AuditExport(_) => Some(AdminPermission::Audit),
            Self::Restart(_) | Self::Die(_) => Some(AdminPermission::Process),
        }
    }

    /// Whether the two-step confirmation rule applies (spec 4575-4576).
    #[must_use]
    pub const fn needs_confirmation(&self) -> bool {
        match self {
            Self::Die(_)
            | Self::Restart(_)
            | Self::PeerQuarantine { .. }
            | Self::ChannelHistoryPurge { .. } => true,
            Self::AccountSuspend { seconds, .. } => seconds.needs_confirmation(),
            _ => false,
        }
    }

    /// Whether a success is recorded as an `observed` audit event rather
    /// than a mutation, intent, or outcome (spec 4560-4562).
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(
            self,
            Self::Motd
                | Self::Version
                | Self::Time
                | Self::Info
                | Self::Links
                | Self::Stats(_)
                | Self::AuditExport(_)
        )
    }

    /// Whether the command is liveness traffic exempt from audit
    /// (spec 2320-2321).
    #[must_use]
    pub const fn is_liveness(&self) -> bool {
        matches!(self, Self::Ping(_) | Self::Pong(_) | Self::Quit)
    }
}

fn reason_text(text: &str) -> Result<Reason, AdminError> {
    Reason::try_from_str(text, ControlPolicy::RejectAll).map_err(map_validation)
}

fn ping_token(text: &str) -> Result<PingToken, AdminError> {
    PingToken::try_from_str(text, ControlPolicy::RejectAll).map_err(map_validation)
}

const fn map_validation(_error: ValidationError) -> AdminError {
    AdminError::Argument
}

#[cfg(test)]
mod tests {
    use agenc_ircd_types::AdminPermission;

    use super::{AdminCommand, AuditRange, SuspensionSeconds};
    use crate::{AdminError, CanonicalCommand, StatsSelector};

    fn parse(text: &str) -> Result<AdminCommand, AdminError> {
        AdminCommand::parse(CanonicalCommand::check(text.as_bytes())?)
    }

    #[test]
    fn history_purge_requires_exact_channel_permission_and_confirmation() -> Result<(), AdminError>
    {
        let command = parse("CHANNEL HISTORY PURGE AQEBAQEBAQEBAQEBAQEBAQ :retention request")?;
        assert!(matches!(command, AdminCommand::ChannelHistoryPurge { .. }));
        assert_eq!(
            command.required_permission(),
            Some(AdminPermission::Channels)
        );
        assert!(command.needs_confirmation());
        assert!(!command.is_read_only());
        assert_eq!(command.verb(), "CHANNEL");
        for invalid in [
            "CHANNEL HISTORY PURGE #channel :reason",
            "CHANNEL HISTORY PURGE AQEBAQEBAQEBAQEBAQEBAQ",
            "CHANNEL HISTORY PURGE AQEBAQEBAQEBAQEBAQEBAQ :",
            "CHANNEL HISTORY PURGE AQEBAQEBAQEBAQEBAQEBAQ extra :reason",
            "CHANNEL HISTORY DELETE AQEBAQEBAQEBAQEBAQEBAQ :reason",
        ] {
            assert!(parse(invalid).is_err(), "{invalid}");
        }
        Ok(())
    }

    const USER: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    const ACCOUNT: &str = "a_AAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn every_registered_command_parses_with_its_permission_and_rules() -> Result<(), AdminError> {
        let table: [(String, Option<AdminPermission>, bool, bool); 21] = [
            ("PING abc".into(), None, false, false),
            ("PONG abc".into(), None, false, false),
            ("QUIT".into(), None, false, false),
            ("MOTD".into(), None, false, true),
            ("VERSION".into(), None, false, true),
            ("TIME".into(), None, false, true),
            ("INFO".into(), None, false, true),
            ("LINKS".into(), None, false, true),
            (
                "STATS RUNTIME".into(),
                Some(AdminPermission::Observe),
                false,
                true,
            ),
            (
                "REHASH :reload now".into(),
                Some(AdminPermission::Configure),
                false,
                false,
            ),
            (
                format!("KILL {USER} :abuse report"),
                Some(AdminPermission::Sessions),
                false,
                false,
            ),
            (
                format!("ACCOUNT SUSPEND {ACCOUNT} 2592000 :spam wave"),
                Some(AdminPermission::Accounts),
                false,
                false,
            ),
            (
                format!("ACCOUNT SUSPEND {ACCOUNT} 2592001 :spam wave"),
                Some(AdminPermission::Accounts),
                true,
                false,
            ),
            (
                format!("ACCOUNT RESTORE {ACCOUNT} :ok now"),
                Some(AdminPermission::Accounts),
                false,
                false,
            ),
            (
                format!("CHANNEL QUARANTINE {USER} :x y"),
                Some(AdminPermission::Channels),
                false,
                false,
            ),
            (
                format!("CONNECT {USER} :x y"),
                Some(AdminPermission::Federation),
                false,
                false,
            ),
            (
                format!("SQUIT {USER} :x y"),
                Some(AdminPermission::Federation),
                false,
                false,
            ),
            (
                format!("PEER QUARANTINE {USER} :x y"),
                Some(AdminPermission::Federation),
                true,
                false,
            ),
            (
                "BACKUP CREATE :nightly run".into(),
                Some(AdminPermission::Backup),
                false,
                false,
            ),
            (
                "AUDIT EXPORT 0 10".into(),
                Some(AdminPermission::Audit),
                false,
                true,
            ),
            (
                "DIE :bye now".into(),
                Some(AdminPermission::Process),
                true,
                false,
            ),
        ];
        for (text, permission, confirmation, read_only) in table {
            let command = parse(&text)?;
            assert_eq!(command.required_permission(), permission, "{text}");
            assert_eq!(command.needs_confirmation(), confirmation, "{text}");
            assert_eq!(command.is_read_only(), read_only, "{text}");
            assert!(text.starts_with(command.verb()), "{text}");
        }
        let restart = parse("RESTART :soon ok")?;
        assert!(restart.needs_confirmation());
        assert_eq!(
            restart.required_permission(),
            Some(AdminPermission::Process)
        );
        assert!(parse("QUIT")?.is_liveness());
        assert!(!parse("MOTD")?.is_liveness());
        assert!(parse("STATS E2EE")? == AdminCommand::Stats(StatsSelector::E2ee));
        Ok(())
    }

    #[test]
    fn malformed_and_unregistered_commands_are_rejected() {
        for (text, expected) in [
            ("OPER x y", AdminError::Command),
            ("NICK x", AdminError::Command),
            ("QUIT x", AdminError::Command),
            ("STATS", AdminError::Command),
            ("STATS runtime", AdminError::Argument),
            ("KILL x :r s", AdminError::Argument),
            ("REHASH", AdminError::Command),
            ("ACCOUNT SUSPEND x 1 :r s", AdminError::Argument),
            ("ACCOUNT FREEZE x :r s", AdminError::Command),
            ("CHANNEL BAN x :r s", AdminError::Command),
            ("PEER CONNECT x :r s", AdminError::Command),
            ("BACKUP VERIFY :r s", AdminError::Command),
            ("AUDIT EXPORT 5 4", AdminError::Argument),
            ("AUDIT EXPORT 01 4", AdminError::Argument),
            ("AUDIT EXPORT 0", AdminError::Command),
            ("PING", AdminError::Command),
            ("REHASH :single", AdminError::Canonical),
            ("KILL x single", AdminError::Argument),
        ] {
            assert_eq!(parse(text).err(), Some(expected), "{text}");
        }
        let long_reason = format!("DIE :{}r", "r ".repeat(256));
        assert_eq!(parse(&long_reason).err(), Some(AdminError::Argument));
        let max_reason = format!("DIE :{}rr", "r ".repeat(255));
        assert!(parse(&max_reason).is_ok());
        assert_eq!(parse("DIE :").err(), Some(AdminError::Argument));
        let long_ping = format!("PING {}", "p".repeat(65));
        assert_eq!(parse(&long_ping).err(), Some(AdminError::Argument));
    }

    #[test]
    fn suspension_and_range_boundaries_are_exact() -> Result<(), AdminError> {
        assert_eq!(SuspensionSeconds::parse("1")?.get(), 1);
        assert_eq!(SuspensionSeconds::parse("31536000")?.get(), 31_536_000);
        assert_eq!(SuspensionSeconds::parse("0"), Err(AdminError::Argument));
        assert_eq!(
            SuspensionSeconds::parse("31536001"),
            Err(AdminError::Argument)
        );
        assert_eq!(SuspensionSeconds::parse("+1"), Err(AdminError::Argument));
        assert!(!SuspensionSeconds::parse("2592000")?.needs_confirmation());
        assert!(SuspensionSeconds::parse("2592001")?.needs_confirmation());
        let range = AuditRange::parse("3", "3")?;
        assert_eq!((range.from(), range.to()), (3, 3));
        assert!(range.contains(3));
        assert!(!range.contains(2));
        assert!(!range.contains(4));
        assert_eq!(AuditRange::new(4, 3), Err(AdminError::Argument));
        assert!(AuditRange::parse("0", "18446744073709551615").is_ok());
        Ok(())
    }

    #[path = "argument_refusals.rs"]
    mod argument_refusals;
}
