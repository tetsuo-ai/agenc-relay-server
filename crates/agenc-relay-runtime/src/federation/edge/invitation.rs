//! Match the sender's original INVITE with an authorized missing-nickname
//! refusal or the correlated invitation event for its physical channel.
use super::*;
use agenc_relay_client_wire::{CapabilityState, WireMessage, numeric_reply};
use agenc_relay_domain::NicknameValue;
use agenc_relay_types::ChannelInstanceId;

#[cfg(test)]
#[path = "tests/invitation.rs"]
mod tests;

pub(crate) struct InviteRequester {
    channel: ChannelInstanceId,
    origin: ReplyRequester,
}

impl InviteRequester {
    pub(super) fn new(
        channel: ChannelInstanceId,
        nick: &str,
        caps: &CapabilityState,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            channel,
            origin: ReplyRequester::new(nick, caps)?,
        })
    }

    pub(in crate::federation::edge) fn matches(
        &self,
        channel: ChannelInstanceId,
        request: &ParsedMessage,
        target: &NicknameValue,
    ) -> bool {
        self.channel == channel
            && request
                .middle()
                .first()
                .is_some_and(|original| original.eq_ignore_ascii_case(target.presentation()))
    }

    fn refusal(
        &self,
        prefix: &str,
        request: &ParsedMessage,
        arm: &ResultArm,
        frame: &WireMessage,
    ) -> Result<WireMessage, Violation> {
        let target = request.middle().first().ok_or(Violation::Consistency)?;
        let recipient = self.origin.nickname()?;
        if !matches!(arm, ResultArm::Failed {code, context} if code == "STALE_STATE" && (context.is_empty() || context.eq_ignore_ascii_case(target)))
        {
            return Err(Violation::Consistency);
        }
        if frame.command() != "401"
            || frame.trailing() != Some("No such nick")
            || !matches!(frame.middle(), [nick, refused] if recipient.eq_ignore_ascii_case(nick) && target.eq_ignore_ascii_case(refused))
        {
            return Err(Violation::Consistency);
        }
        numeric_reply(prefix, 401, recipient, &[target], Some("No such nick"))
            .map_err(|_| Violation::Codec)
    }
}

pub(super) fn project(
    prefix: &str,
    pending: &PendingKind,
    arm: &ResultArm,
    frames: &mut [WireMessage],
) -> Result<(), Violation> {
    let PendingKind::Command {
        message,
        echo_channels: Some(EchoChannels::Invite(requester)),
    } = pending
    else {
        return Ok(());
    };
    match frames {
        // A committed result supplies the 341 through its event. Older failed
        // results and failures before nickname lookup have no per-target evidence.
        [] if matches!(arm, ResultArm::Committed { .. } | ResultArm::Failed { .. }) => Ok(()),
        [frame] => {
            *frame = requester.refusal(prefix, message, arm, frame)?;
            Ok(())
        }
        _ => Err(Violation::Consistency),
    }
}
