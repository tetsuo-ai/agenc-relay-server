//! Match the canonical delta of an original channel mode command.
use crate::federation::codec::operations::ModeChangeArg;
use agenc_relay_domain::federation::{ModeDirection, ProjectedModeChange};
use agenc_relay_types::{ChannelInstanceId, TypedMask};

/// Only the public selectors, limit, list masks and resolved member identities survive admission.
/// The correlated completion must independently name the generation containing this delta.
pub(in crate::federation::edge) struct ChannelModeRequester {
    channel: ChannelInstanceId,
    revision: u64,
    additions: u32,
    removals: u32,
    member_limit: Option<u32>,
    public_targets: Box<[ModeChangeArg]>,
}

impl ChannelModeRequester {
    pub(in crate::federation::edge) fn new(
        channel: ChannelInstanceId,
        revision: u64,
        mut changes: Vec<ModeChangeArg>,
    ) -> Self {
        let mut original = Self {
            channel,
            revision,
            additions: 0,
            removals: 0,
            member_limit: None,
            public_targets: Box::default(),
        };
        changes.retain_mut(|change| {
            let selector = bit(change.mode_code);
            match change.direction {
                ModeDirection::Add => original.additions |= selector,
                ModeDirection::Remove => original.removals |= selector,
            }
            match (change.mode_code, change.direction) {
                (1..=3, _) => return canonicalize_mask(change),
                (12..=16, _) => return true,
                (5, ModeDirection::Add) => {
                    original.member_limit = std::str::from_utf8(&change.argument)
                        .ok()
                        .and_then(|s| s.parse().ok());
                }
                (5, ModeDirection::Remove) => original.member_limit = Some(0),
                // Unlisted and secret are exclusive. Setting either can clear the other.
                (9, ModeDirection::Add) => original.removals |= bit(10),
                (10, ModeDirection::Add) => original.removals |= bit(9),
                _ => {}
            }
            // Dropping a join-key argument clears its zeroizing buffer.
            false
        });
        original.public_targets = changes.into_boxed_slice();
        original
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
        if selected & bit(code) == 0 {
            return false;
        }
        let target = match change {
            ProjectedModeChange::Limit { limit, .. } => return self.member_limit == Some(*limit),
            ProjectedModeChange::Key { present, .. } => {
                return *present == (direction == ModeDirection::Add);
            }
            ProjectedModeChange::Simple { .. } => return true,
            ProjectedModeChange::List { entry, .. } => {
                if entry.channel_id != self.channel {
                    return false;
                }
                entry.mask.as_bytes()
            }
            ProjectedModeChange::Prefix { view, .. } => {
                if view.membership.channel_id != self.channel
                    || view.membership.user_id != view.source.user_id
                {
                    return false;
                }
                view.source.user_id.as_bytes()
            }
        };
        self.public_targets.iter().any(|original| {
            original.direction == direction
                && original.mode_code == code
                && original.argument.as_slice() == target
        })
    }
}

/// Store the public list argument in the form emitted by the domain projector.
fn canonicalize_mask(change: &mut ModeChangeArg) -> bool {
    let Some(mask) = std::str::from_utf8(&change.argument)
        .ok()
        .and_then(|text| TypedMask::parse(text).ok())
    else {
        return false;
    };
    *change.argument = crate::mutation_render::typed_mask_text(&mask).into_bytes();
    true
}

fn bit(code: u16) -> u32 {
    1_u32.checked_shl(u32::from(code)).unwrap_or(0)
}
