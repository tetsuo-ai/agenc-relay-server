//! The carrier matrix (companion Section 11.4): which command carries which
//! object kind, under which complete-object limit, fragment ceiling, and
//! reassembly deadline.

use crate::limits::{
    LIVE_REASSEMBLY_ABSOLUTE_SECONDS, LIVE_REASSEMBLY_IDLE_SECONDS,
    MAILBOX_REASSEMBLY_ABSOLUTE_SECONDS, MAILBOX_REASSEMBLY_IDLE_SECONDS,
    MAX_FEDERATION_CONTROL_OBJECT, MAX_LIVE_FRAGMENT_COUNT, MAX_MAILBOX_FRAGMENT_COUNT,
    MAX_WELCOME_MAILBOX_OBJECT,
};
use crate::object::IrcWireObjectKind;

/// Every command or path that carries a complete object.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum CarrierCommand {
    /// Bound-channel `TAGMSG`.
    Tagmsg,
    /// `EDIRECT`.
    Edirect,
    /// `EGROUP SUBMIT CANDIDATE`.
    SubmitCandidate,
    /// `EGROUP SUBMIT AUTHORIZATION`.
    SubmitAuthorization,
    /// `EGROUP SUBMIT ACK`.
    SubmitAck,
    /// `EGROUP SUBMIT FINALIZATION`.
    SubmitFinalization,
    /// `EGROUP SUBMIT ABORT`.
    SubmitAbort,
    /// `EGROUP SUBMIT REINIT ATTEMPT`.
    SubmitReinitAttempt,
    /// `EGROUP SUBMIT REINIT ACK`.
    SubmitReinitAck,
    /// `EGROUP SUBMIT REINIT ACTIVATE`.
    SubmitReinitActivate,
    /// `EGROUP SUBMIT REINIT ABORT`.
    SubmitReinitAbort,
    /// `EGROUP SUBMIT POLICY`.
    SubmitPolicy,
    /// `EGROUP SUBMIT MEMBERSHIP`.
    SubmitMembership,
    /// `EGROUP BIND`.
    Bind,
    /// `EGROUP CLOSE`.
    Close,
    /// `EKEY PUBLISH IDENTITY`.
    PublishIdentity,
    /// `EKEY PUBLISH ROSTER`.
    PublishRoster,
    /// `EKEY PUBLISH CAPABILITIES`.
    PublishCapabilities,
    /// `EKEY PUBLISH PACKAGE`.
    PublishPackage,
    /// `EKEY DELIVER BINDING`.
    DeliverBinding,
    /// `EKEY DELIVER WELCOME`.
    DeliverWelcome,
    /// `EKEY ATTACH FINISH`.
    AttachFinish,
    /// A server-originated response object of the named kind.
    Response(IrcWireObjectKind),
    /// A federation payload of the named kind.
    Federation(IrcWireObjectKind),
}

/// Which deadline class an assembly uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadlineClass {
    /// Live channel, direct, Commit, and application traffic.
    Live,
    /// Mailbox and control traffic.
    Mailbox,
}

impl DeadlineClass {
    /// Absolute and idle deadlines in seconds.
    #[must_use]
    pub const fn seconds(self) -> (u64, u64) {
        match self {
            Self::Live => (
                LIVE_REASSEMBLY_ABSOLUTE_SECONDS,
                LIVE_REASSEMBLY_IDLE_SECONDS,
            ),
            Self::Mailbox => (
                MAILBOX_REASSEMBLY_ABSOLUTE_SECONDS,
                MAILBOX_REASSEMBLY_IDLE_SECONDS,
            ),
        }
    }
}

/// The complete-object rules of one carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectLimit {
    /// Complete encoded object bytes, envelope included.
    pub max_bytes: usize,
    /// Fragment ceiling.
    pub max_fragments: u32,
    /// Deadline class.
    pub deadline: DeadlineClass,
}

impl CarrierCommand {
    /// The kinds this carrier accepts, in matrix order.
    #[must_use]
    pub fn accepted_kinds(self) -> &'static [IrcWireObjectKind] {
        use IrcWireObjectKind::*;
        match self {
            Self::Tagmsg | Self::Edirect => &[ApplicationMls],
            Self::SubmitCandidate => &[CommitMls],
            Self::SubmitAuthorization => &[CommitApproval],
            Self::SubmitAck => &[CommitAck],
            Self::SubmitFinalization => &[FinalizationRequest],
            Self::SubmitAbort => &[AbortRequest],
            Self::SubmitReinitAttempt => &[ReinitAttempt],
            Self::SubmitReinitAck => &[ReinitAck],
            Self::SubmitReinitActivate => &[ReinitActivationRequest],
            Self::SubmitReinitAbort => &[ReinitAbortRequest],
            Self::SubmitPolicy => &[Policy],
            Self::SubmitMembership => &[IrcWireObjectKind::LeafMembershipProof],
            Self::Bind | Self::DeliverBinding => &[ConversationBinding],
            Self::Close => &[CloseAuthorization],
            Self::PublishIdentity => &[RootIdentity],
            Self::PublishRoster => &[DeviceRoster],
            Self::PublishCapabilities => &[DeviceCapabilities],
            Self::PublishPackage => &[KeyPackageMls],
            Self::DeliverWelcome => &[WelcomeMls, StagedReinit],
            Self::AttachFinish => &[DeviceAttach],
            Self::Response(kind) | Self::Federation(kind) => kind_slice(kind),
        }
    }

    /// Whether `kind` may travel on this carrier.
    #[must_use]
    pub fn accepts(self, kind: IrcWireObjectKind) -> bool {
        self.accepted_kinds().contains(&kind)
    }

    /// Whether this carrier is live (channel, direct, Commit) rather than
    /// a control or mailbox path.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Tagmsg | Self::Edirect | Self::SubmitCandidate)
    }

    /// The complete-object limit: the largest accepted kind's maximum,
    /// the fragment ceiling of the deadline class, and that class.
    #[must_use]
    pub fn limit(self) -> ObjectLimit {
        let max_bytes = self
            .accepted_kinds()
            .iter()
            .map(|kind| kind.maximum_object_bytes())
            .max()
            .unwrap_or(MAX_FEDERATION_CONTROL_OBJECT)
            .min(MAX_WELCOME_MAILBOX_OBJECT);
        let deadline = if self.is_live() {
            DeadlineClass::Live
        } else {
            DeadlineClass::Mailbox
        };
        let max_fragments = if self.is_live() {
            MAX_LIVE_FRAGMENT_COUNT
        } else {
            MAX_MAILBOX_FRAGMENT_COUNT
        };
        ObjectLimit {
            max_bytes,
            max_fragments,
            deadline,
        }
    }
}

fn kind_slice(kind: IrcWireObjectKind) -> &'static [IrcWireObjectKind] {
    IrcWireObjectKind::ALL
        .iter()
        .position(|candidate| *candidate == kind)
        .and_then(|index| IrcWireObjectKind::ALL.get(index..=index))
        .unwrap_or(&[])
}

#[cfg(test)]
#[path = "../tests/carrier.rs"]
mod tests;
