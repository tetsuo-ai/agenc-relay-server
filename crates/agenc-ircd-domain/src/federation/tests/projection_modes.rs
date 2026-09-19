//! Channel mode changes project as the exact registered mode deltas.
#![forbid(unsafe_code)]

use super::*;
use crate::federation::record::{ModeDirection, ProjectedModeChange};
use crate::{ChannelKeyVerifier, MaskList, ModeChange, ModeOperation, Role, VisibilityMode};
use agenc_ircd_types::TypedMask;

/// `alice` on edge A owns `#ops`; `bob` on edge B is a plain member.
struct Ops {
    harness: Harness,
    alice: UserId,
    bob: UserId,
    channel: ChannelInstanceId,
}

fn ops() -> Result<Ops, DomainError> {
    ops_with(false)
}

/// The fixture, with `alice` authenticated to an account before she joins
/// when `registered`.
fn ops_with(registered: bool) -> Result<Ops, DomainError> {
    let mut harness = Harness::new()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    if registered {
        harness.register(alice, 41)?;
    }
    let name = ChannelNameValue::parse("#ops")?;
    for user in [alice, bob] {
        let join = || CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)]);
        harness.run(user, join, &MutationContext::default())?;
    }
    let channel = harness
        .state
        .resolve_channel(&name)
        .ok_or(DomainError::NotFound)?;
    Ok(Ops {
        harness,
        alice,
        bob,
        channel,
    })
}

impl Ops {
    /// Applies `changes` as `alice` and returns the delta edge B observed.
    fn apply(
        &mut self,
        changes: impl Fn() -> Result<Vec<ModeChange>, DomainError>,
    ) -> Result<Vec<ProjectedModeChange>, DomainError> {
        let name = ChannelNameValue::parse("#ops")?;
        let build = || CanonicalCommand::mode(name.clone(), changes()?);
        let context = MutationContext {
            actor: Some(self.alice),
            ..MutationContext::default()
        };
        let projection = self.harness.run(self.alice, build, &context)?;
        let observed = |edge| {
            events_for(&projection, edge)
                .into_iter()
                .find_map(|event| match event {
                    ProjectedEvent::ChannelModesChanged {
                        channel_id,
                        changes,
                        ..
                    } if *channel_id == self.channel => Some(changes.clone()),
                    _ => None,
                })
                .unwrap_or_default()
        };
        assert!(
            observed(EDGE_A) == observed(EDGE_B),
            "every member edge observes the same delta"
        );
        Ok(observed(EDGE_B))
    }

    fn bob_nickname(&self) -> Result<NicknameValue, DomainError> {
        Ok(self
            .harness
            .state
            .session(self.bob)
            .ok_or(DomainError::NotFound)?
            .nickname()
            .clone())
    }
}

fn simple(direction: ModeDirection, mode_code: u16) -> ProjectedModeChange {
    ProjectedModeChange::Simple {
        direction,
        mode_code,
    }
}

#[test]
fn simple_flags_project_their_registered_codes_in_both_directions() -> Result<(), DomainError> {
    let mut ops = ops()?;
    let set = ops.apply(|| {
        Ok(vec![
            ModeChange::InviteOnly(true),
            ModeChange::Moderated(true),
        ])
    })?;
    assert!(
        set == vec![
            simple(ModeDirection::Add, MODE_CODE_INVITE_ONLY),
            simple(ModeDirection::Add, MODE_CODE_MODERATED)
        ]
    );
    let cleared = ops.apply(|| Ok(vec![ModeChange::InviteOnly(false)]))?;
    assert!(cleared == vec![simple(ModeDirection::Remove, MODE_CODE_INVITE_ONLY)]);
    Ok(())
}

#[test]
fn visibility_changes_project_the_private_and_secret_codes() -> Result<(), DomainError> {
    let ops = ops()?;
    let listed = ops
        .harness
        .state
        .durable_channel(ops.channel)
        .ok_or(DomainError::NotFound)?;
    let mut secret = listed.clone();
    secret.visibility = Visibility::Secret;
    let mut unlisted = listed.clone();
    unlisted.visibility = Visibility::Unlisted;
    let mut changes = Vec::new();
    scalar_mode_changes(&listed, &secret, &mut changes);
    assert!(changes == vec![simple(ModeDirection::Add, MODE_CODE_SECRET)]);
    let mut changes = Vec::new();
    scalar_mode_changes(&secret, &unlisted, &mut changes);
    assert!(
        changes
            == vec![
                simple(ModeDirection::Add, MODE_CODE_PRIVATE),
                simple(ModeDirection::Remove, MODE_CODE_SECRET)
            ]
    );
    Ok(())
}

#[test]
fn a_visibility_mode_on_an_unregistered_channel_is_refused_before_projection()
-> Result<(), DomainError> {
    let mut ops = ops()?;
    let refused = ops.apply(|| {
        Ok(vec![ModeChange::Visibility {
            operation: ModeOperation::Add,
            mode: VisibilityMode::Secret,
        }])
    });
    assert_eq!(refused.err(), Some(DomainError::RegistrationRequired));
    Ok(())
}

#[test]
fn a_member_limit_projects_its_value_and_zero_when_cleared() -> Result<(), DomainError> {
    let mut ops = ops()?;
    let set = ops.apply(|| Ok(vec![ModeChange::MemberLimit(Some(5))]))?;
    assert!(
        set == vec![ProjectedModeChange::Limit {
            direction: ModeDirection::Add,
            limit: 5
        }]
    );
    let cleared = ops.apply(|| Ok(vec![ModeChange::MemberLimit(None)]))?;
    assert!(
        cleared
            == vec![ProjectedModeChange::Limit {
                direction: ModeDirection::Remove,
                limit: 0
            }]
    );
    Ok(())
}

#[test]
fn a_role_grant_and_its_revocation_project_the_same_prefix_code() -> Result<(), DomainError> {
    let mut ops = ops()?;
    let target = ops.bob_nickname()?;
    let role = |operation| ModeChange::Role {
        operation,
        role: Role::Voice,
        target: target.clone(),
    };
    for (operation, direction) in [
        (ModeOperation::Add, ModeDirection::Add),
        (ModeOperation::Remove, ModeDirection::Remove),
    ] {
        let changes = ops.apply(|| Ok(vec![role(operation)]))?;
        let [
            ProjectedModeChange::Prefix {
                direction: observed,
                mode_code,
                view,
            },
        ] = changes.as_slice()
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert!(*observed == direction);
        assert_eq!(Some(*mode_code), prefix_code(Role::Voice));
        assert_eq!(view.source.user_id, ops.bob);
    }
    Ok(())
}

#[test]
fn a_mask_entry_projects_with_its_setter_when_added_and_removed() -> Result<(), DomainError> {
    let mut ops = ops()?;
    let added = ops.apply(|| {
        Ok(vec![ModeChange::AddMask {
            list: MaskList::Ban,
            mask: TypedMask::parse("$n:blocked")?,
        }])
    })?;
    let [
        ProjectedModeChange::List {
            direction: ModeDirection::Add,
            entry,
        },
    ] = added.as_slice()
    else {
        return Err(DomainError::InvariantViolation);
    };
    assert_eq!(entry.mode_code, MODE_CODE_BAN);
    assert_eq!(entry.channel_id, ops.channel);
    assert_eq!(entry.setter.user_id, ops.alice);
    let entry_id = entry.entry_id;
    let removed = ops.apply(|| {
        Ok(vec![ModeChange::RemoveMask {
            list: MaskList::Ban,
            entry_id,
        }])
    })?;
    let [
        ProjectedModeChange::List {
            direction: ModeDirection::Remove,
            entry,
        },
    ] = removed.as_slice()
    else {
        return Err(DomainError::InvariantViolation);
    };
    assert_eq!(entry.entry_id, entry_id);
    Ok(())
}

#[test]
fn exception_lists_project_their_own_mode_codes() -> Result<(), DomainError> {
    let mut ops = ops()?;
    for (list, code) in [
        (MaskList::Exception, MODE_CODE_EXCEPTION),
        (MaskList::InviteException, MODE_CODE_INVITE_EXCEPTION),
    ] {
        let added = ops.apply(|| {
            Ok(vec![ModeChange::AddMask {
                list,
                mask: TypedMask::parse("$n:friend")?,
            }])
        })?;
        let [ProjectedModeChange::List { entry, .. }] = added.as_slice() else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(entry.mode_code, code);
    }
    Ok(())
}

#[test]
fn a_mask_set_by_an_account_projects_a_live_session_of_that_account() -> Result<(), DomainError> {
    let mut ops = ops_with(true)?;
    let added = ops.apply(|| {
        Ok(vec![ModeChange::AddMask {
            list: MaskList::Ban,
            mask: TypedMask::parse("$n:blocked")?,
        }])
    })?;
    let [ProjectedModeChange::List { entry, .. }] = added.as_slice() else {
        return Err(DomainError::InvariantViolation);
    };
    assert_eq!(entry.setter.user_id, ops.alice);
    Ok(())
}

#[test]
fn scalar_changes_report_a_key_by_presence_only() -> Result<(), DomainError> {
    let ops = ops()?;
    let pre = ops
        .harness
        .state
        .durable_channel(ops.channel)
        .ok_or(DomainError::NotFound)?;
    let mut post = pre.clone();
    post.key_verifier = Some(ChannelKeyVerifier::new([1; 16], [2; 32]));
    let mut changes = Vec::new();
    scalar_mode_changes(&pre, &post, &mut changes);
    assert!(
        changes
            == vec![ProjectedModeChange::Key {
                direction: ModeDirection::Add,
                present: true
            }]
    );
    let mut changes = Vec::new();
    scalar_mode_changes(&post, &pre, &mut changes);
    assert!(
        changes
            == vec![ProjectedModeChange::Key {
                direction: ModeDirection::Remove,
                present: false
            }]
    );
    let mut changes = Vec::new();
    scalar_mode_changes(&pre, &pre, &mut changes);
    assert!(changes.is_empty());
    Ok(())
}
