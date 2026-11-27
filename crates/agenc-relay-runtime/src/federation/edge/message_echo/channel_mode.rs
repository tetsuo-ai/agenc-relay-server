//! Match the canonical delta of an original channel mode command.
use crate::budget::MemoryPermit;
use crate::federation::codec::operations::ModeChangeArg;
use crate::state_core::StateCoreContext;
use agenc_relay_crypto::{Digest32, Sha256Stream};
use agenc_relay_domain::federation::projection::{apply_prefix_code, prefix_delta};
use agenc_relay_domain::federation::{
    EdgeReplica, MembershipView, ModeDirection, ProjectedModeChange,
};
use agenc_relay_domain::{DomainError, Role};
use agenc_relay_types::{ChannelInstanceId, TypedMask, UserId};

#[derive(PartialEq, Eq)]
enum PublicArgument {
    Mask(Digest32),
    Member(UserId, Option<Role>),
}

#[derive(PartialEq, Eq)]
struct ModeTarget {
    code: u16,
    direction: ModeDirection,
    argument: PublicArgument,
}

/// Only public selectors, limit, canonical mask digests and resolved member identities survive
/// admission. The correlated completion must independently name the generation of this delta.
pub(in crate::federation::edge) struct ChannelModeRequester {
    channel: ChannelInstanceId,
    revision: u64,
    additions: u32,
    removals: u32,
    member_limit: Option<u32>,
    targets: Box<[ModeTarget]>,
    _backing: MemoryPermit,
}

impl ChannelModeRequester {
    pub(in crate::federation::edge) fn new(
        context: &StateCoreContext,
        replica: &EdgeReplica,
        channel: ChannelInstanceId,
        revision: u64,
        changes: &[ModeChangeArg],
    ) -> Result<Self, DomainError> {
        let count = changes
            .iter()
            .filter(|change| matches!(change.mode_code, 1..=3 | 12..=16))
            .count();
        // The packed slice is the only retained allocation. Each argument is fixed-size and inline.
        let bytes = count
            .checked_mul(size_of::<ModeTarget>())
            .ok_or(DomainError::ServerBusy)?;
        let backing = context
            .reserve_output_backing(bytes)
            .map_err(|_| DomainError::ServerBusy)?;
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(count)
            .map_err(|_| DomainError::ServerBusy)?;
        let mut original = Self {
            channel,
            revision,
            additions: 0,
            removals: 0,
            member_limit: None,
            targets: Box::default(),
            _backing: backing,
        };
        for change in changes {
            if let Some(argument) = original.record(replica, change)? {
                targets.push(ModeTarget {
                    code: change.mode_code,
                    direction: change.direction,
                    argument,
                });
            }
        }
        original.targets = targets.into_boxed_slice();
        Ok(original)
    }

    fn record(
        &mut self,
        replica: &EdgeReplica,
        change: &ModeChangeArg,
    ) -> Result<Option<PublicArgument>, DomainError> {
        let selector = bit(change.mode_code);
        match change.direction {
            ModeDirection::Add => self.additions |= selector,
            ModeDirection::Remove => self.removals |= selector,
        }
        match (change.mode_code, change.direction) {
            (1..=3, _) => {
                let text = std::str::from_utf8(&change.argument)
                    .map_err(|_| DomainError::InvalidArgument)?;
                let mask = TypedMask::parse(text).map_err(|_| DomainError::InvalidArgument)?;
                Ok(Some(PublicArgument::Mask(mask_digest(
                    &crate::mutation_render::typed_mask_text(&mask),
                ))))
            }
            (12..=16, _) => {
                let bytes = change
                    .argument
                    .as_slice()
                    .try_into()
                    .map_err(|_| DomainError::InvalidArgument)?;
                let user = UserId::from_bytes(bytes);
                Ok(Some(PublicArgument::Member(
                    user,
                    replica.membership(self.channel, user).map(|row| row.role),
                )))
            }
            (5, direction) => {
                self.member_limit = Some(match direction {
                    ModeDirection::Remove => 0,
                    ModeDirection::Add => std::str::from_utf8(&change.argument)
                        .ok()
                        .and_then(|value| value.parse().ok())
                        .ok_or(DomainError::InvalidArgument)?,
                });
                Ok(None)
            }
            // Setting one visibility can implicitly clear the other.
            (9, ModeDirection::Add) => {
                self.removals |= bit(10);
                Ok(None)
            }
            (10, ModeDirection::Add) => {
                self.removals |= bit(9);
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    pub(super) fn matches(
        &self,
        channel: ChannelInstanceId,
        revision: u64,
        changes: &[ProjectedModeChange],
    ) -> bool {
        channel == self.channel
            && revision > self.revision
            && !changes.is_empty()
            && changes.iter().all(|change| self.admitted(change))
    }

    fn admitted(&self, change: &ProjectedModeChange) -> bool {
        let direction = change.direction();
        let code = change.mode_code();
        let selected = match direction {
            ModeDirection::Add => self.additions,
            ModeDirection::Remove => self.removals,
        };
        let argument = match change {
            ProjectedModeChange::Prefix { view, .. } => {
                return self.admitted_prefix(view, direction, code);
            }
            _ if selected & bit(code) == 0 => return false,
            ProjectedModeChange::Limit { limit, .. } => return self.member_limit == Some(*limit),
            ProjectedModeChange::Key { present, .. } => {
                return *present == (direction == ModeDirection::Add);
            }
            ProjectedModeChange::Simple { .. } => return true,
            ProjectedModeChange::List { entry, .. } => {
                if entry.channel_id != self.channel {
                    return false;
                }
                PublicArgument::Mask(mask_digest(&entry.mask))
            }
        };
        self.targets.contains(&ModeTarget {
            code,
            direction,
            argument,
        })
    }

    fn admitted_prefix(&self, view: &MembershipView, direction: ModeDirection, code: u16) -> bool {
        let member = &view.membership;
        if member.channel_id != self.channel || member.user_id != view.source.user_id {
            return false;
        }
        let steps = self
            .targets
            .iter()
            .filter_map(|target| match target.argument {
                PublicArgument::Member(user, before) if user == member.user_id => {
                    Some((before, target.direction, target.code))
                }
                _ => None,
            });
        let Some((known_before, _, _)) = steps.clone().next() else {
            return false;
        };
        // The replica owns only local memberships. A remote target still has one physical
        // identity; the observed delta must be possible for the full original ordered vector.
        [
            Role::Member,
            Role::Voice,
            Role::HalfOperator,
            Role::Operator,
            Role::Administrator,
            Role::Owner,
        ]
        .into_iter()
        .filter(|before| known_before.is_none_or(|known| known == *before))
        .any(|before| {
            let after = steps.clone().try_fold(before, |role, (_, op, selector)| {
                apply_prefix_code(role, op, selector)
            });
            after == Ok(member.role) && prefix_delta(before, member.role) == Some((direction, code))
        })
    }
}

fn mask_digest(canonical: &str) -> Digest32 {
    let mut digest = Sha256Stream::new();
    digest.update(canonical.as_bytes());
    digest.finish()
}

fn bit(code: u16) -> u32 {
    1_u32.checked_shl(u32::from(code)).unwrap_or(0)
}
